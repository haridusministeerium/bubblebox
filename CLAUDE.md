# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`bb` is a single-file Python executable (no extension, no package, no build step) that merges YAML/JSON sandbox profiles into one config and `exec`s `bwrap` (bubblewrap) with the resulting arguments. Derived from @sloonz's gist. Runtime deps: `pyyaml`, `psutil`, plus `bwrap`, and optionally `xdg-dbus-proxy`.

Tests (Python ≥ 3.12; CI is `.github/workflows/tests.yml` on GitHub Actions):

```sh
pip install -r requirements-dev.txt
python -m pytest                                              # whole suite
python -m pytest tests/test_merge.py::test_env_stacks_across_profiles   # single test
```

`bb` has no `.py` extension and isn't importable as a module, so it is tested only as a black box (entry point is `main()`). `tests/conftest.py` gives each test an isolated HOME/XDG tree (the `bb` fixture → `BBEnv`) and puts fake `bwrap`/`xdg-dbus-proxy`/target scripts first on PATH (`tests/fakes/recorder.py`). The fakes record their argv, the contents of piped FDs, and the ignored-signal mask as JSON (targets also record cwd, env, session, caps/no_new_privs/seccomp state), and tests assert on that record (`res.bwrap.has(...)`, `.setenv`, `.data_for(...)`). `tests/test_real_bwrap.py` runs against real bwrap. It skips when bwrap is unusable; CI sets `BB_REQUIRE_REAL_BWRAP=1` to make that a failure. Known bugs are pinned as `xfail(strict=True)`: when you fix one, remove its marker. `tests/fixtures/config.yaml` is a trimmed copy of a real user config.

For manual checks, run with debug logging. This prints the merged config and the full `bwrap` command before exec:

```sh
./bb -l debug -i <profile-id>[,<id2>] [executable] [args...]
./bb -l debug -j '{"unshareAll": true}' -s 'mounts./tmp=tmpfs' -s ':myvar=x' -s '$PATH=/bin' true
```

Profiles are looked up as `<id>`, `<id>.yml`, `<id>.yaml` in the cwd, then in `$XDG_CONFIG_HOME/bubblebox/`. `config.yaml` there is the global multi-doc file whose profiles apply automatically when the executable's name is in their `matches` list. If nothing matches, the `default` profile is loaded (`--default-sandbox`, `-D` to forbid).

## Architecture (top-to-bottom flow in `bb`)

1. **Argument parsing** (`parse_args`, `parse_set_arg`): `-i/-j/-f/-s` are collected **in order** into a sources list via `tagged_append`. Order matters because later configs override earlier ones. `-s` uses a mini path syntax: `:` prefix means `vars.`, `$` means `env.`, `@` marks a list element, and JSON values are parsed.
2. **Config collection** (`collect_configs`): explicit sources, then `-a` autoload by executable name, then global `matches`, then the default fallback.
3. **Merge** (`merge_sandboxes` → `merge`): resolves `include` recursively (by `id` or `path`, with optional `try`). Each key is merged according to `MERGE_POLICIES`, looked up by dotted path with `*` wildcards (e.g. `dbus.user.rules.*`). **Any key missing from `MERGE_POLICIES` raises "Unknown key while merging". When adding a new config key, register it there.** Policies are:
   - `literal`: last one wins.
   - `list`: concatenate.
   - `items`: dict entries become a list of `(k, v)` tuples. Used by `mounts`/`chmod`, which `get_sandbox` turns back into dicts.
   - `dict`: recurse.
   - `literal-expandable`: `env.*` / `vars.*` values are `str.format_map`-ed against the accumulated `SafeDict`. This lets profiles stack, e.g. `PATH: "/x:{PATH}"`. `SafeDict` leaves unknown `{keys}` unexpanded for later resolution.
   - `discard`: dropped.
   - Keys are processed in reverse-sorted order so `vars` comes before `env`.
4. **Resolve** (`get_sandbox`): env values have special meanings: `true` inherits from the host, `false` adds `--unsetenv`, `null` does nothing, a dict uses `value`/`raw`/`inherits`+`defaultValue`. `vars` and `env` are expanded iteratively against `default_vars` (built in `main()`) plus `{env[...]}` until a fixpoint, and a cycle raises "circular def". Mount and chmod keys are expanded here, and must not be expanded again later (paths may contain literal braces).
5. **Emit bwrap args** (`get_bwrap_args`): camelCase config keys are converted to bwrap's kebab-case by `bwrap_name`. The `BWRAP_FLAGS` / `BWRAP_OPTIONS` / `BWRAP_LIST_OPTIONS` sets define which top-level keys map directly to bwrap.
   - Mounts accept string shorthands (`ro-bind`, `bind-try:/src`, `bind-create`, `overlay-tmp|ro|auto[-create][:/src]`, `symlink:...`, `tmpfs`, `proc`, ...) or dict forms (`bind`, `tmpfs`, `dir`, `file`, `data`, `fd`, `overlay`). `normalize_mount` rewrites shorthands into their dict form, so each mount type has one code path. `-create` is a bb-only convention that runs `makedirs` on the source (or, for `overlay-auto`, on the upper/work dirs).
   - `overlay` `mode: auto` places `_ol_upper`/`._ol_work` under the `olay_root` var, keyed by the lower dir (`overlay_dir_key`: `$HOME/x` → `home-<our uid>/x`, `/home/<user>/x` → `home-<user>/x`, else `root/x`).
   - Config strings are formatted with `expand()` (format + `expanduser`); only `file`/`data` content uses plain `.format()`.
   - Inline data (seccomp programs, `file`/`data` content, the final arg list) is passed to bwrap through pipe FDs created by a forked writer (`pipefd`).
   - `extraArgs` goes before mounts and `extraArgsPost` after them.
6. **D-Bus** (`setup_dbus_proxy`): when a `dbus` block exists, forks `xdg-dbus-proxy`. If `dbus.sandbox` is set, the proxy itself runs inside a bwrap built from that sub-profile. The proxy's sockets are bound over the real bus paths in the main sandbox, and the two are synchronised via `--sync-fd`.
7. **Singleton**: `singleton: true` (which requires `id`) writes the bwrapinfo path to `$XDG_RUNTIME_DIR/bubblebox/<id>.instance.info`. A later launch finds the running instance and joins its namespaces itself (`enter_existing_ns`) instead of starting a new sandbox. The recorded namespace inodes are compared against `/proc/<child-pid>/ns/*` first, so a reused pid is treated as a dead instance. Joining uses one `setns(pidfd, flags)` call. When bwrap nests the sandbox's user ns below the one that owns its mount/pid namespaces (e.g. when the profile mounts `/dev`), joining one at a time fails: after joining the lower user ns, `setns` on the mount ns returns EPERM. Recent nsenter joins all at once the same way. The forked child then does what bwrap does for its own child: drops all capabilities (bounding set included), sets no_new_privs, loads the profile's seccomp program, and honours `newSession`/`dieWithParent`/`chdir`. It runs with the target's environment. `capAdd`, `addSeccompFd` and fd-based `seccomp` are rejected there rather than skipped. Skipping them would leave the entered command less confined than the instance's own processes, and none can be reproduced: the seccomp fds were consumed by the launch that started the instance, and `capAdd` would mean reimplementing bwrap's ambient-capability handling.
8. **Exec**: always go through the module's `exec()` wrapper, never call `os.execlp` directly. The wrapper restores SIGPIPE/SIGXFSZ to their defaults, which CPython otherwise leaves ignored and which sandboxed shells would inherit. `--info-fd` is added last on purpose: it opens a file, and no `fork()` may happen after that.

`disableSandbox: true` skips everything and execs the target directly.

## Conventions / gotchas

- Per-run values (`default_vars`, `instance_id`, the merged `sb`, the command) live in `main()` and are passed to functions explicitly; only host-derived constants (`HOME`, `XDG_*`, `SB_CONFIG`) and `SANDBOXES_CACHE` are module globals.
- The `id` value `config` is reserved for the global config filename.
- `instance_id` must contain a `.` (`org.bubblebox-<pid>`) for portals to work.
- Commit messages use conventional-commit style (per the user's preference); history uses short imperative lowercase subjects.
- `*.orig` files in the working tree are local leftovers, not tracked.
- README's TODO section lists known open design questions: a config validator (probably TypedDict + pydantic `TypeAdapter`, with startup latency as a concern), camelCase vs kebab-case keys, and seccomp.
