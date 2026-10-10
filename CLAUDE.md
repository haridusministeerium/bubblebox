# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`bb` is a single-file Python executable (no extension, no package, no build step) that merges YAML/JSON sandbox profiles into one config and `exec`s `bwrap` (bubblewrap) with the resulting arguments. Derived from @sloonz's gist. Runtime deps: `pyyaml`, `psutil`, plus `bwrap`, and optionally `xdg-dbus-proxy` / `nsenter`.

Tests (Python ≥ 3.12; CI is `.github/workflows/tests.yml` on GitHub Actions):

```sh
pip install -r requirements-dev.txt
python -m pytest                                              # whole suite
python -m pytest tests/test_merge.py::test_env_stacks_across_profiles   # single test
```

`bb` runs at module level, so it is tested only as a black box. `tests/conftest.py` gives each test an isolated HOME/XDG tree (the `bb` fixture → `BBEnv`) and puts fake `bwrap`/`xdg-dbus-proxy`/`nsenter` scripts first on PATH (`tests/fakes/recorder.py`). The fakes record their argv, the contents of piped FDs, and the ignored-signal mask as JSON, and tests assert on that record (`res.bwrap.has(...)`, `.setenv`, `.data_for(...)`). `tests/test_real_bwrap.py` runs against real bwrap. It skips when bwrap is unusable; CI sets `BB_REQUIRE_REAL_BWRAP=1` to make that a failure. Known bugs are pinned as `xfail(strict=True)`: when you fix one, remove its marker. `tests/fixtures/config.yaml` is a trimmed copy of a real user config.

For manual checks, run with debug logging. This prints the merged config and the full `bwrap` command before exec:

```sh
./bb -l debug -i <profile-id>[,<id2>] [executable] [args...]
./bb -l debug -j '{"unshareAll": true}' -s 'mounts./tmp=tmpfs' -s ':myvar=x' -s '$PATH=/bin' true
```

Profiles are looked up as `<id>`, `<id>.yml`, `<id>.yaml` in the cwd, then in `$XDG_CONFIG_HOME/bubblebox/`. `config.yaml` there is the global multi-doc file whose profiles apply automatically when the executable's name is in their `matches` list. If nothing matches, the `default` profile is loaded (`--default-sandbox`, `-D` to forbid).

## Architecture (top-to-bottom flow in `bb`)

1. **Argument parsing** (module level, after `# ENTRY`): `-i/-j/-f/-s` are collected **in order** into `CONFIGS_SOURCES` via `tagged_append`. Order matters because later configs override earlier ones. `-s` uses a mini path syntax: `:` prefix means `vars.`, `$` means `env.`, `@` marks a list element, and JSON values are parsed.
2. **Config collection**: explicit sources, then `-a` autoload by executable name, then global `matches`, then the default fallback.
3. **Merge** (`merge_sandboxes` → `merge`): resolves `include` recursively (by `id` or `path`, with optional `try`). Each key is merged according to `MERGE_POLICIES`, looked up by dotted path with `*` wildcards (e.g. `dbus.user.rules.*`). **Any key missing from `MERGE_POLICIES` raises "Unknown key while merging". When adding a new config key, register it there.** Policies are:
   - `literal`: last one wins.
   - `list`: concatenate.
   - `items`: dict entries become a list of `(k, v)` tuples. Used by `mounts`/`chmod`, which `get_sandbox` turns back into dicts.
   - `dict`: recurse.
   - `literal-expandable`: `env.*` / `vars.*` values are `str.format_map`-ed against the accumulated `SafeDict`. This lets profiles stack, e.g. `PATH: "/x:{PATH}"`. `SafeDict` leaves unknown `{keys}` unexpanded for later resolution.
   - `discard`: dropped.
   - Keys are processed in reverse-sorted order so `vars` comes before `env`.
4. **Resolve** (`get_sandbox`): env values have special meanings: `true` inherits from the host, `false` adds `--unsetenv`, `null` does nothing, a dict uses `value`/`raw`/`inherits`+`defaultValue`. `vars` and `env` are expanded iteratively against `DEFAULT_VARS` plus `{env[...]}` until a fixpoint, and a cycle raises "circular def". Mount and chmod keys are expanded here.
5. **Emit bwrap args** (`get_bwrap_args`): camelCase config keys are converted to bwrap's kebab-case by `bwrap_name`. The `BWRAP_FLAGS` / `BWRAP_OPTIONS` / `BWRAP_LIST_OPTIONS` sets define which top-level keys map directly to bwrap.
   - Mounts accept string shorthands (`ro-bind`, `bind-try:/src`, `bind-create`, `symlink:...`, `tmpfs`, `proc`, ...) or dict forms (`bind`, `tmpfs`, `dir`, `file`, `data`, `fd`, `overlay`). `-create` is a bb-only convention that runs `makedirs` on the source.
   - Inline data (seccomp programs, `file`/`data` content, the final arg list) is passed to bwrap through pipe FDs created by a forked writer (`pipefd`).
   - `extraArgs` goes before mounts and `extraArgsPost` after them.
6. **D-Bus** (`setup_dbus_proxy`): when a `dbus` block exists, forks `xdg-dbus-proxy`. If `dbus.sandbox` is set, the proxy itself runs inside a bwrap built from that sub-profile. The proxy's sockets are bound over the real bus paths in the main sandbox, and the two are synchronised via `--sync-fd`.
7. **Singleton**: `singleton: true` (which requires `id`) writes the bwrapinfo path to `$XDG_RUNTIME_DIR/bubblebox/<id>.instance.info`. A later launch finds the running instance and `nsenter`s its namespaces instead of starting a new sandbox.
8. **Exec**: always go through the module's `exec()` wrapper, never call `os.execlp` directly. The wrapper restores SIGPIPE/SIGXFSZ to their defaults, which CPython otherwise leaves ignored and which sandboxed shells would inherit. `--info-fd` is added last on purpose: it opens a file, and no `fork()` may happen after that.

`disableSandbox: true` skips everything and execs the target directly.

## Conventions / gotchas

- `DEFAULT_VARS` is defined late, after config collection, because it depends on `EXECUTABLE_NAME`, but the functions above reference it as a global. The same applies to `SB`, `ARGS`, `INSTANCE_ID`, `BWRAP_INFOF` and `SINGLETON_LOCATION`. Keep that ordering in mind when moving code.
- The `id` value `config` is reserved for the global config filename.
- `INSTANCE_ID` must contain a `.` (`org.bubblebox-<pid>`) for portals to work.
- Commit messages use conventional-commit style (per the user's preference); history uses short imperative lowercase subjects.
- `*.orig` files in the working tree are local leftovers, not tracked.
- README's TODO section lists known open design questions: a config validator (probably TypedDict + pydantic `TypeAdapter`, with startup latency as a concern), camelCase vs kebab-case keys, and seccomp.
