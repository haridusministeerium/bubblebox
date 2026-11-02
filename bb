#!/usr/bin/python
#
# original ver from https://gist.github.com/sloonz/ef282a1f53366e1ed6f5cb848de015ba#file-sandbox2-py (as of Feb '26)

import argparse
import base64
import ctypes
import hashlib
import json
import logging
import os
from pathlib import Path
from collections.abc import Iterable
from collections import UserDict
from typing import Any, NoReturn
import platform
import pprint
import re
import shlex
import sys
import yaml
import psutil
import signal


BIND_RE = re.compile(
    r"(?P<opt>(?:ro-|dev-)?bind(?:-try)?)"  # bind / ro-bind-try / dev-bind ...
    r"(?P<create>(?<!-try)-create)?"        # optional -create, but not after -try
    r"(?::(?P<src>\S.*))?$"                 # optional ":source_path"
)

OVERLAY_RE = re.compile(
    r"overlay-(?P<mode>tmp|ro|auto)"        # overlay-tmp / overlay-ro / overlay-auto
    r"(?P<create>(?<=auto)-create)?"        # optional -create, only after -auto
    r"(?::(?P<src>\S.*))?$"                 # optional ":source_path"
)

# allows for stacking env vars, e.g. multiple profiles having
# PATH: "/some/dir:{PATH}" while _still_ allowing for later-expanded vars; i.e.
# can extend/stack as opposed to overwriting previous values
class SafeDict(UserDict):
    # makes sure missing format key does not throw KeyError, but leaves the format unexpanded;
    # this also means get() should be invoked on instances of this dict only w/ format_map()
    def __missing__(self, key):
        return Unresolved(key)

    def __setitem__(self, key, value):
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):  # note we don't store bools either (bool is subclass of int!)
            super().__setitem__(key, os.path.expanduser(str(value)))


# Stand-in for a missing format key that renders back to its original
# placeholder. A plain "{key}" string wouldn't do: format_map() goes on to
# apply any index/attribute access to it, e.g. "{env[HOME]}" would index the
# string "{env}" and blow up, instead of being left for get_sandbox() to expand.
class Unresolved:
    def __init__(self, expr: str):
        self.expr = expr

    def __getitem__(self, key) -> "Unresolved":
        return Unresolved(f"{self.expr}[{key}]")

    def __getattr__(self, name: str) -> "Unresolved":
        if name.startswith("__"):
            raise AttributeError(name)
        return Unresolved(f"{self.expr}.{name}")

    def __format__(self, spec: str) -> str:
        return "{" + self.expr + (f":{spec}" if spec else "") + "}"


LOGGER: logging.Logger = logging.getLogger()

HOME: str = os.environ["HOME"]
UID: str = str(os.getuid())
XDG_CONFIG: Path = Path(os.environ.get("XDG_CONFIG_HOME", f"{HOME}/.config"))
XDG_RUNTIME: str = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{UID}")

SB_CONFIG: Path = XDG_CONFIG / "bubblebox"

SANDBOXES_CACHE: dict[str, dict] = {}

# bwrap info-fd namespace key -> (/proc/<pid>/ns/ entry, setns() flag)
NAMESPACES: dict[str, tuple[str, int]] = {
    "mnt-namespace": ("mnt", os.CLONE_NEWNS),
    "pid-namespace": ("pid", os.CLONE_NEWPID),
    "net-namespace": ("net", os.CLONE_NEWNET),
    "ipc-namespace": ("ipc", os.CLONE_NEWIPC),
    "uts-namespace": ("uts", os.CLONE_NEWUTS),
    "cgroup-namespace": ("cgroup", os.CLONE_NEWCGROUP),
}

# from linux/prctl.h & linux/seccomp.h & linux/capability.h
PR_SET_PDEATHSIG: int = 1
PR_SET_SECCOMP: int = 22
PR_CAPBSET_DROP: int = 24
PR_SET_NO_NEW_PRIVS: int = 38
SECCOMP_MODE_FILTER: int = 2
LINUX_CAPABILITY_VERSION_3: int = 0x20080522
LIBC = ctypes.CDLL(None, use_errno=True)


BWRAP_FLAGS: set[str] = {"levelPrefix", "unshareAll", "shareNet", "unshareUser",
                         "unshareUserTry", "unshareIpc", "unsharePid", "unshareNet",
                         "unshareUts", "unshareCgroup", "unshareCgroupTry",
                         "disableUserns", "assertUsernsDisabled", "clearenv",
                         "newSession", "dieWithParent", "asPid1"}
BWRAP_OPTIONS: set[str] = {"argv0", "userns", "userns2", "pidns", "uid", "gid",
                           "hostname", "chdir", "execLabel", "fileLabel",
                           "seccomp", "syncFd", "blockFd", "usernsBlockFd",
                           "infoFd", "jsonStatusFd"}
# bwrap options that may be defined multiple times:
BWRAP_LIST_OPTIONS: set[str] = {"addSeccompFd", "capAdd", "capDrop", "lockFile", "remountRo"}

# TODO: instead of our merge logic, consider using pydash's merge_with() (http://static.aryehleib.com/pydash/api.html#pydash.objects.merge_with)
#       and write the policies into the callback customizer arg.
#       NOTE: it WILL introduce dependency on pydash
MERGE_POLICIES: dict[str, set[str]] = {
  # note rules.{broadcast,call}.* get merged by "items" policy, as we assume
  # there can be e.g. multiple `--broadcast=org.freedesktop.portal.*=@...` rules
  #
  # TODO: shouldn't mounts & chmod items be merged by 'literal' policy? we
  #       can't bind multiple sources to the same target (target being the key),
  #       so it doesn't make much sense to merge by "items". also both get
  #       transformed into dict at the end of get_sandbox() without further processing
  "items": {"mounts", "chmod", "dbus.rules.*", "dbus.user.rules.*", "dbus.system.rules.*"},
  # TODO: wouldn't "override" or "overwrite" be a better name than "literal"?
  "literal": BWRAP_FLAGS
        .union(BWRAP_OPTIONS)
        .union({"id", "disableSandbox", "singleton", "dbus.sloppyNames",
                "dbus.user.sloppyNames", "dbus.system.sloppyNames",
                "dbus.sandbox.*", "dbus.policies.*", "dbus.user.policies.*",
                "dbus.system.policies.*"}),
  "list": BWRAP_LIST_OPTIONS
        .union({"extraArgs", "extraArgsPost", "matches"}),
  "literal-expandable": {"env.*", "vars.*"},
  "dict": {"vars", "env", "dbus", "dbus.sandbox", "dbus.policies",
           "dbus.user.policies", "dbus.system.policies", "dbus.user", "dbus.system",
           "dbus.rules", "dbus.user.rules", "dbus.system.rules"},
  "discard": {"include"},
}


# CPython ignores SIGPIPE and SIGXFSZ at startup, and ignored signals are
# inherited across exec().
# cpython does this so writing to an abandoned pipe wouldn't be killed by
# SIGPIPE (the default), but instead fail with EPIPE, which py turns into
# BrokenPipeError; similar for SIGXFSZ.
#
# Restore defaults so sandboxed processes behave
# as they would when launched from a normal shell.
#
# Without restoring the signal handling here, starting an interactive shell
# (e.g. bash) in a sandbox via this script might show errors like
# "bash: export: write error: Broken pipe"
#
# Note to find ignored signals, run `grep SigIgn /proc/$$/status` on host & in
# sandbox; if the values are same, then all should be OK.
def restore_default_signals() -> None:
    for sig in (signal.SIGPIPE, signal.SIGXFSZ):
        signal.signal(sig, signal.SIG_DFL)


def exec(file: str, *args, env: dict[str, str]|None=None) -> NoReturn:
    restore_default_signals()
    if env is None:
        os.execlp(file, *args)
    os.execvpe(file, args, env)


# picks the seccomp program for our arch from a {data: base64, arch: string} or list thereof
def get_seccomp_program(value: dict|list) -> bytes:
    data: list[bytes] = [base64.b64decode(prog["data"]) for prog in ([value] if isinstance(value, dict) else value)
                         if prog["arch"] == platform.machine()]
    if len(data) == 0:
        raise Exception(f"seccomp program not found for our architecture: {platform.machine()}")
    elif len(data) != 1:
        raise Exception(f"{len(data)} seccomp programs found for our architecture {platform.machine()}, expected 1")
    return data[0]


# TODO: should we also do os.path.expandvars() ?
def expand(var: str, fmt: dict) -> str:
    return os.path.expanduser(var.format(**fmt))


# maps an overlay's lower dir to its relative location under [olay_root]:
# $HOME/x -> ~/x; /home/x -> home/x; /x -> root/x
def overlay_dir_key(path: str) -> str:
    path = os.path.normpath(path)
    if path == HOME or path.startswith(HOME + "/"):
        return "~" + path.removeprefix(HOME)
    if path == "/home" or path.startswith("/home/"):
        return path.lstrip("/")
    return "root" + path.rstrip("/")


def tagged_append(tag: str, dest: list[tuple[str,str]]):
    class TaggedAppend(argparse.Action):
        def __call__(self, parser, ns, values, option_string: str|None=None) -> None:
            dest.append((tag, values))
    return TaggedAppend


def load_sandboxes_file(path: Path|str, default_id: str|None=None) -> list[dict]:
    LOGGER.debug("loading %s", path)
    with open(path) as fd:
        sandboxes: list[dict] = list(yaml.safe_load_all(fd))
        for i, sb in enumerate(sandboxes):
            if id := sb.get("id", default_id if i == 0 else None):
                SANDBOXES_CACHE[id] = sb
        return sandboxes


def try_load_sandbox(id: str) -> dict|None:
    if id == "config":  # global app config filename, illegal name for individual configs
        raise Exception(f"profile/config id cannot be [{id}]")
    elif id in SANDBOXES_CACHE:
        return SANDBOXES_CACHE[id]

    candidate_paths: tuple[Path, ...] = (
        Path(id),
        Path(f"{id}.yml"),
        Path(f"{id}.yaml"),
        SB_CONFIG / f"{id}.yml",
        SB_CONFIG / f"{id}.yaml",
    )
    for p in candidate_paths:
        if p.is_file():
            return load_sandboxes_file(p, id)[0]


def load_sandbox(id: str) -> dict:
    if (sb := try_load_sandbox(id)) is not None:
        return sb
    raise Exception(f"[{id}] sandbox not found")


def get_merge_policy(path: list[str], k: str) -> tuple[str, list[str]]:
    kl = ".".join(path + [k])
    kg = ".".join(path + ["*"])
    for p, s in MERGE_POLICIES.items():
        if kl in s:
            return p, path + [k]
        elif kg in s:
            return p, path + ["*"]
    raise Exception(f"Unknown key while merging: {".".join(path + [k])}")


def merge(a: dict[str, Any], b: dict[str, Any], format_env: SafeDict, path: list[str]=[]) -> dict[str, Any]:
    res = {}
    # note we sort so we get e.g. 'vars' before 'env'; otherwise result is not deterministic
    # as our envs & vars are stackable/extendable from sb-to-sb:
    for k in sorted(set(a.keys()).union(b.keys()), reverse=True):
        policy, key_path = get_merge_policy(path, k)
        match policy:
            case "list":
                res[k] = a.get(k, []) + b.get(k, [])
            case "items":
                left = a.get(k, [])
                right = b.get(k, [])
                res[k] = (list(left.items()) if isinstance(left, dict) else left) + \
                         (list(right.items()) if isinstance(right, dict) else right)
            case "dict":
                # an empty yaml key (e.g. `user:` under dbus) loads as None; treat it as empty mapping
                left, right = (({} if side.get(k) is None else side[k]) for side in (a, b))
                for side in (left, right):
                    if not isinstance(side, dict):
                        raise Exception(f"config key [{".".join(path + [k])}] must be a mapping, got: {side!r}")
                res[k] = merge(left, right, format_env, key_path)
            case "literal":
                res[k] = b.get(k, a.get(k))
            case "literal-expandable":
                # print(f"env key: [{k}]; a={a.get(k)}; b={b.get(k)}")
                if k in a:
                    # if isinstance(a[k], str):
                        # res[k] = format_env[k] = a[k].format_map(format_env)
                    # else:
                        # res[k] = format_env[k] = a[k]
                    res[k] = format_env[k] = a[k]
                if k in b:
                    if isinstance(b[k], str):
                        res[k] = format_env[k] = b[k].format_map(format_env)
                    else:
                        res[k] = format_env[k] = b[k]

            case "discard":
                pass
            case _:
                raise NotImplementedError
    return res


def merge_sandboxes(sandboxes: Iterable[dict], format_env: SafeDict) -> dict:
    def load_include(inc_in: str|dict) -> dict:
        inc: dict = {"id": inc_in} if isinstance(inc_in, str) else inc_in
        if id := inc.get("id"):
            if inc.get("try"):
                if sb := try_load_sandbox(id):
                    return sb
                return {}
            return load_sandbox(id)
        elif path := inc.get("path"):
            if inc.get("try") and not os.path.isfile(path):
                return {}
            return load_sandboxes_file(path)[0]

        raise Exception(f"include entry needs an [id] or [path] key: {inc_in!r}")

    res = {}
    for sb in sandboxes:
        inc = merge_sandboxes((load_include(child_sb) for child_sb in sb.get("include", ())), format_env)
        res = merge(res, merge(inc, sb, format_env), format_env)
    return res


# note passed sb is the final/merged/resolved sandbox config
#
# returns enriched sandbox with env/vars/mounts/chmod data
def get_sandbox(sb: dict, default_vars: dict[str, str]) -> dict:
    # Parse vars & env
    raw_env: dict = {}
    env: dict = {}
    env_unset: set = set()  # env vars to explicitly unset via --unsetenv

    for k, v in sb.get("env", {}).items():
        if v is True:  # inherit
            if k in os.environ:
                env[k] = os.environ[k]
        elif v is False:  # clear
            env_unset.add(k)
        elif v is None:  # nothing
            pass
        elif isinstance(v, str):
            raw_env[k] = v
        elif isinstance(v, dict):
            # TODO: consider renaming "inherits" to "ordefault"/"withdefault".
            #       or perhaps require/support _only_ "defaultValue" key if v = dict? this requires deprecation of "value" as suggested below.
            if "inherits" in v:
                if k in os.environ:
                    env[k] = os.environ[k]
                #elif "defaultValue" in v:
                else:
                    raw_env[k] = v["defaultValue"]  # note here we expect/require "defaultValue" key to be present
            elif "value" in v:
                # TODO: should it not go in raw_env dict if v.get("raw") is truthy?
                #       if not, then perhaps "raw" key in v would be better named something like "asis"?
                #       note the effective difference is that only values in raw_env get expanded later on.
                #       better yet, why not deprecate the "value" key option in env dict altogether?
                if v.get("raw"):
                    env[k] = v["value"]
                else:
                    raw_env[k] = v["value"]
            else:
                raise Exception(f"Invalid value for environment variable {k}: {repr(v)}")
        elif isinstance(v, (int, float)):  # e.g. yaml `FOO: 5`; SafeDict only coerces merge-time format values
            raw_env[k] = str(v)
        else:
            raise Exception(f"Invalid value for environment variable {k}: {repr(v)}")

    # note format_vars is used to expand our raw_vars & raw_env via python's
    # string.format() method, passing **format_vars as possible values to
    # be expanded into the raw values
    raw_vars: dict = {**sb.get("vars", {})}
    vars: dict = {**default_vars}
    format_vars: dict = {**vars, "env": {**os.environ, **env}}
    while True:
        changed: bool = False
        for parsed, raw in ((vars, raw_vars), (env, raw_env)):
            for k in list(raw.keys()):
                try:
                    parsed[k] = expand(raw[k], format_vars)
                    del raw[k]
                    changed = True
                except KeyError:
                    pass
        # redefine format_vars, as both vars & env were potentially modified:
        format_vars = {**vars, "env": {**os.environ, **env}}
        if not (raw_env or raw_vars):
            break  # all raw values were processed/expanded
        elif not changed:
            raise Exception(f"circular def!! env: {raw_env.keys()}  var: {raw_vars.keys()}")

    # Parse mounts & chmod; note sb[mounts|chmod] are tuple[key,v] because of 'items' merge policy:
    mounts: dict[str, Any] = {expand(k, format_vars).rstrip("/"): v for k, v in sb.get("mounts", ()) if v}
    chmod: dict[str, Any] = {expand(k, format_vars).rstrip("/"): v for k, v in sb.get("chmod", ()) if v}

    return {**sb, "vars": vars, "env": env, "envUnset": env_unset,
            "mounts": mounts, "chmod": chmod, "format_vars": format_vars}  # note we store the resulting format_vars
                                                                           # just-in-case for potential later use


# returns string representation of read end of the pipe FD
def pipefd(data: bytes) -> str:
    pr, pw  = os.pipe2(0)
    if os.fork() == 0:
        os.close(pr)
        os.write(pw, data)
        os._exit(0)  # don't unwind into the parent's code in this forked child
    else:
        os.close(pw)
        return str(pr)


def pipefd_args(args: list[str]) -> str:
    return pipefd("\0".join(args).encode("utf-8"))


# turns string mount shorthands into their equivalent dict form
def normalize_mount(mount: Any) -> Any:
    if not isinstance(mount, str):
        return mount
    if mount in ("tmpfs", "dir"):
        return {mount: {}}
    if mount.startswith("symlink:"):
        return {"symlink": mount.removeprefix("symlink:")}
    # '-try' and '-create' suffixes; '-create' is our own convention: it creates the SRC dir if missing
    if m := BIND_RE.match(mount):
        opt: str = m["opt"]
        return {"bind": {"ro": opt.startswith("ro-"), "dev": opt.startswith("dev-"),
                         "try": opt.endswith("-try"), "create": bool(m["create"]),
                         **({"path": m["src"]} if m["src"] is not None else {})}}
    if m := OVERLAY_RE.match(mount):
        return {"overlay": {"mode": m["mode"], "create": bool(m["create"]),
                            **({"lower": [m["src"]]} if m["src"] is not None else {})}}
    return mount


# { overlay: { lower?: string[]; upper?: string; work?: string; mode?: "rw" | "tmp" | "ro" | "auto"; create?: boolean }}
# lower defaults to DEST; 'auto' mode places upper & work dirs under the [olay_root] var, keyed by
# the (single) lower dir, and 'create' creates them
def get_overlay_args(overlay: dict, dest_path: str, format_vars: dict) -> list[str]:
    lowers: list[str] = [expand(l, format_vars) for l in overlay["lower"]] if "lower" in overlay else [dest_path]
    args: list[str] = []
    for lower in lowers:  # host paths from which files are read if they aren't present in a higher layer
        args += ("--overlay-src", lower)
    mode: str = overlay.get("mode", "rw" if ("upper" in overlay and "work" in overlay) else "tmp")
    if mode != "rw" and ("upper" in overlay or "work" in overlay):
        raise Exception(f"{mode} overlay does not accept [upper] nor [work] configs/dirs")
    if mode == "rw":
        upper, work = expand(overlay["upper"], format_vars), expand(overlay["work"], format_vars)
    elif mode == "auto":
        if "olay_root" not in format_vars:
            raise Exception(f"[olay_root] var needs to be defined for auto overlay mount at [{dest_path}]")
        if len(lowers) != 1:
            raise Exception(f"auto overlay at [{dest_path}] needs exactly one lower dir, got {len(lowers)}")
        olay_dir = os.path.join(expand(format_vars["olay_root"], format_vars), overlay_dir_key(lowers[0]))
        upper, work = os.path.join(olay_dir, "_ol_upper"), os.path.join(olay_dir, "._ol_work")
        if overlay.get("create") is True:
            os.makedirs(upper, exist_ok=True)
            os.makedirs(work, exist_ok=True)
    else:
        return args + [f"--{mode}-overlay", dest_path]
    return args + ["--overlay", upper, work, dest_path]  # i.e. --overlay RWSRC WORKDIR DEST


# resolve bwrap flags from given sandbox config
def get_bwrap_args(sb: dict) -> list[str]:
    # convert the camel-cased options to kebab-case used by bwrap
    def bwrap_name(name: str) -> str:
        # special cases; we don't want to get 'argv-0', 'userns-2':
        if name in ("argv0", "userns2"):
            return name
        return re.sub(r"(?<=[a-z])([A-Z0-9+])", lambda m: "-" + m.group(1).lower(), name)

    # TODO: the input 'value' type can never be list, only dict or int, no?
    #       edit: think it can be list with 'seccomp' after all
    def format_seccomp_value(value: dict|list|int) -> str:
        if isinstance(value, (dict, list)):
            return pipefd(get_seccomp_program(value))
        return str(value)  # fd

    # TODO: what are the possible 'value' types? is it dict|list|int|str?
    def format_option_value(opt_name: str, value) -> str:
        if opt_name in ("seccomp", "addSeccompFd"):
            return format_seccomp_value(value)
        elif opt_name in ("userns", "userns2", "pidns", "syncFd", "blockFd",
                          "usernsBlockFd", "infoFd", "jsonStatusFd"):
            return str(value)
        return expand(str(value), format_vars)

    def format_datasource_value(value) -> str:  # {fd: number} | {content: string, raw?: boolean, base64?: boolean}
        if (fd := value.get("fd")) is not None:
            return str(fd)
        elif (content := value.get("content")) is not None:
            if not value.get("raw"):
                content = content.format(**format_vars)  # not expand(): a leading ~ in file content isn't a path

            if value.get("base64") is True:
                content = base64.b64decode(content)
            else:
                content = content.encode("utf-8")
            return pipefd(content)
        raise NotImplementedError

    def get_perms(data: dict) -> tuple[str, ...]:
        if (perms := data.get("perms")) is None:
            return ()
        if isinstance(perms, str) and perms.startswith("0o"):
            perms = f"0{int(perms, 0):o}"
        return "--perms", str(perms)

    format_vars: dict = {**sb["vars"], "env": {**os.environ, **sb["env"]}}
    args: list[str] = [f"--{bwrap_name(f)}" for f in BWRAP_FLAGS if sb.get(f) is True]
    for o in BWRAP_OPTIONS:
        if (v := sb.get(o)) not in (False, None):
            args += (f"--{bwrap_name(o)}", format_option_value(o, v))
    for o in BWRAP_LIST_OPTIONS:
        for v in sb.get(o, ()):
            if v not in (False, None):
                args += (f"--{bwrap_name(o)}", format_option_value(o, v))
    args += (expand(arg, format_vars) for arg in sb.get("extraArgs", ()))
    for e in sb["envUnset"]:
        args += ("--unsetenv", e)
    for k, v in sb["env"].items():
        args += ("--setenv", k, v)

    # note dest_path is on the sandbox side & already expanded by get_sandbox(), so it
    # mustn't be expanded again; note it's sorting lexicographically by key, not length
    for dest_path, mount in sorted(sb["mounts"].items()):
        if mount in ("proc", "dev", "mqueue"):
            args += (f"--{mount}", dest_path)
            continue
        match normalize_mount(mount):
            case {"tmpfs": dict(tmpfs)}:  # { tmpfs: { perms?: number; size?: number }}
                args += get_perms(tmpfs)
                if (size := tmpfs.get("size")) is not None:
                    args += ("--size", str(size))
                args += ("--tmpfs", dest_path)
            case {"dir": dict(dir)}:  # { dir: { perms?: number }}
                args += get_perms(dir)
                args += ("--dir", dest_path)
            case {"symlink": str(symlink)}:  # { symlink: string }
                args += ("--symlink", expand(symlink, format_vars), dest_path)
            case {"bind": dict(bind)}:  # { bind: { path?: string; ro?: boolean; dev?: boolean; try?: boolean, create?: boolean }}
                prefix = "dev-" if bind.get("dev") else "ro-" if bind.get("ro") else ""
                suffix = "-try" if bind.get("try") else ""
                src_path = expand(bind["path"], format_vars) if "path" in bind else dest_path
                if bind.get("create") is True:
                    os.makedirs(src_path, exist_ok=True)
                args += (f"--{prefix}bind{suffix}", src_path, dest_path)
            case {"fd": dict(fd)}:  # { fd: { fd: number; ro?: boolean }}
                args += ("--ro-bind-fd" if fd.get("ro") else "--bind-fd", str(fd["fd"]), dest_path)
            case {"file": dict(file)}:  # { file: DataSource & { perms?: number }}
                args += get_perms(file)
                args += ("--file", format_datasource_value(file), dest_path)
            case {"data": dict(data)}:  # { data: DataSource & { ro?: boolean; perms?: number }}
                args += get_perms(data)
                args += ("--ro-bind-data" if data.get("ro") else "--bind-data",
                         format_datasource_value(data), dest_path)
            case {"overlay": dict(overlay)}:
                args += get_overlay_args(overlay, dest_path, format_vars)
            case _:
                raise Exception(f"invalid mount (of type {type(mount)}) value: {repr(mount)}")
    # TODO: is sorting for chmod needed? note it's sorting lexicographically by the first element's (ie. key); not length
    for path, mode in sorted(sb["chmod"].items()):
        args += ("--chmod", str(mode), path)
    args += (expand(arg, format_vars) for arg in sb.get("extraArgsPost", ()))
    return args


# resolve options to be passed to `xdg-dbus-proxy`.
# 'bus_name' arg is system|user
def get_dbus_proxy_args(dbus: dict, bus_name: str) -> list[str]:
    b: dict = dbus[bus_name] or {}  # because empty user|system key in yaml would translate to None value
    args: list[str] = []
    if b.get("sloppyNames", dbus.get("sloppyNames", False)) is True:
        args.append("--sloppy-names")

    policies: dict[str, str] = {**dbus.get("policies", {}), **b.get("policies", {})}
    args += (f"--{policy}={name}" for name, policy in policies.items())

    for rule_type in ("broadcast", "call"):
        ruleset: list[tuple[str, str]] = (dbus.get("rules", {}).get(rule_type, []) +
                                          b.get("rules", {}).get(rule_type, []))
        args += (f"--{rule_type}={name}={rule}" for name, rule in ruleset)
    return args


# if required so by the sb's config, start a xdg-dbus-proxy subprocess and
# return additional bwrap parameters to pass to the main sandbox command
def setup_dbus_proxy(sb: dict, instance_id: str, default_vars: dict[str, str]) -> list[str]|tuple[()]:
    if not (dbus := sb.get("dbus")):
        if "dbus" in sb:  # sanity
            raise Exception("empty [dbus] key/block not allowed")
        return ()  # no dbus proxies configured, bail

    proxy_dir: str = f"{XDG_RUNTIME}/xdg-dbus-proxy/{instance_id}"

    unix_path_prefix: str = "unix:path="
    dbus_sess_bus_env_var: str = "DBUS_SESSION_BUS_ADDRESS"
    dbus_session_address: str = os.environ.get(dbus_sess_bus_env_var, f"{unix_path_prefix}{XDG_RUNTIME}/bus")
    buses: tuple[tuple[str,str,str|None], ...] = (
        ("system", f"{unix_path_prefix}/run/dbus/system_bus_socket", None),
        ("user", dbus_session_address, dbus_sess_bus_env_var),
    )

    proxy_bwrap_args: list[str] = ["--bind", proxy_dir, proxy_dir]
    cmd_bwrap_args: list[str] = []
    dbus_proxy_args: list[str] = []
    for bus, address, addr_env in buses:
        if bus not in dbus:
            continue
        dbus_proxy_args += (address, f"{proxy_dir}/{bus}", "--filter")
        bus_args: list[str] = get_dbus_proxy_args(dbus, bus)
        dbus_proxy_args += bus_args

        addr_path: str = address.removeprefix(unix_path_prefix)
        if not os.path.exists(addr_path):  # sanity
            raise Exception(f"{bus} dbus socket [{addr_path}] does not exist")

        proxy_bwrap_args += ("--bind", addr_path, addr_path)
        cmd_bwrap_args += ("--bind", f"{proxy_dir}/{bus}", addr_path)
        if addr_env:
            cmd_bwrap_args += ("--setenv", addr_env, address)

    if not dbus_proxy_args:  # sanity
        prefix = f"[{sb["id"]}] " if "id" in sb else ""
        raise Exception(f"{prefix}sandbox has [dbus] block configured, but none of {[b[0] for b in buses]} bus(es) under it")

    os.makedirs(proxy_dir, exist_ok=True)
    pr, pw = os.pipe2(0)
    dbus_proxy_args = ["xdg-dbus-proxy", f"--fd={pw}"] + dbus_proxy_args
    LOGGER.debug("proxy args for dbus proxy: %s\n", shlex.join(dbus_proxy_args))

    # if 'dbus.sandbox' defined, then it means xdg-dbus-proxy itself is to be ran in bwrap as well:
    # TODO: as of May '26, portals do not work if x-d-p runs unsandboxed:
    if proxy_sb := dbus.get("sandbox"):
        proxy_sb: dict = get_sandbox(merge_sandboxes((proxy_sb,), SafeDict(**os.environ, **default_vars)), default_vars)  # note we call merge_sandboxes() to get the [include] resolution/expansion
        debug_object("dbus proxy sandbox", proxy_sb)
        proxy_bwrap_args = get_bwrap_args(proxy_sb) + proxy_bwrap_args
        dbus_proxy_args = ["bwrap", "--args", pipefd_args(proxy_bwrap_args), "--"] + dbus_proxy_args
        LOGGER.debug("bwrap args for xdg-dbus-proxy: %s\n", shlex.join(proxy_bwrap_args))

    if os.fork() == 0:
        os.close(pr)
        try:
            exec(dbus_proxy_args[0], *dbus_proxy_args)
        except OSError as e:
            print(f"failed to start [{dbus_proxy_args[0]}]: {e}", file=sys.stderr)
            os._exit(127)  # don't unwind into the parent's code in this forked child
    else:
        os.close(pw)
        if os.read(pr, 1) != b"x":  # proxy writes a byte to --fd once it's listening
            raise Exception("xdg-dbus-proxy exited before signalling it's ready")
        return ["--sync-fd", str(pr)] + cmd_bwrap_args


# for some explanation, see e.g.
# - https://github.com/ValveSoftware/steam-for-linux/issues/10645#issuecomment-2013609605
# - https://gist.github.com/sloonz/4b7f5f575a96b6fe338534dbc2480a5d#gistcomment-5515250
def get_bwrapinfo_args(path: str) -> tuple[str, str]:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd: int = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.set_inheritable(fd, True)  # raw fd, so bwrap inherits it & nothing closes it on gc
    return "--info-fd", str(fd)


def debug_object(label: str, obj: object) -> None:
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug(f"{label}:\n{pprint.pformat(obj)}")


def process_active(pid: int) -> psutil.Process|None:
    try:
        process = psutil.Process(pid)
        if process.status() not in (psutil.STATUS_DEAD, psutil.STATUS_ZOMBIE):
            return process
    except psutil.Error:  # includes NoSuchProcess error
        pass
    return None


# guards against pid reuse: the process now at [pid] must still live in the namespaces bwrap reported
def in_recorded_namespaces(pid: int, bwrap_info: dict) -> bool:
    try:
        return all(os.stat(f"/proc/{pid}/ns/{NAMESPACES[k][0]}").st_ino == bwrap_info[k]
                   for k in bwrap_info.keys() & NAMESPACES.keys())
    except OSError:
        return False


def get_running_instance_bwrapinfo(singleton_location: str, sb_id: str) -> dict|None:
    try:
        with open(singleton_location, "r") as f:
            bwrap_infof, _, config_hash = f.read().partition("\n")
        with open(bwrap_infof, "r") as f:
            content = f.read()
    except IOError:
        return None

    # the instance file is written before bwrap starts, so the info file stays
    # empty if bwrap failed at startup; treat it as no running instance, or
    # every later launch of this profile would fail
    try:
        info: dict = json.loads(content)
    except json.JSONDecodeError:
        LOGGER.warning("ignoring unparsable bwrap info file [%s] of a previous [%s] instance",
                       bwrap_infof, sb_id)
        return None

    # sanity checks:
    child_pid_key = "child-pid"
    expected_bwrap_keys: set[str] = {*NAMESPACES, child_pid_key}
    bwrap_info_keys: set[str] = set(info.keys())
    min_keys = 2  # at least child-pid and one namespace expected
    if not bwrap_info_keys.issubset(expected_bwrap_keys):
        raise Exception(f"bwrap_info contains unexpected keys: {bwrap_info_keys - expected_bwrap_keys}")
    elif len(bwrap_info_keys) < min_keys:
        raise Exception(f"bwrap_info contains only {len(bwrap_info_keys)} key(s), expected at least {min_keys}")
    elif child_pid_key not in info:
        raise Exception(f"bwrap_info [{bwrap_infof}] lacks [{child_pid_key}] key")

    if bwrap_proc := process_active(info[child_pid_key]):
        if not in_recorded_namespaces(bwrap_proc.pid, info):
            LOGGER.warning("ignoring stale [%s] instance: pid %s no longer runs in its recorded namespaces",
                           sb_id, bwrap_proc.pid)
            return None
        info["bwrap_proc"] = bwrap_proc
        info["config_hash"] = config_hash
        return info


def prctl(option: int, *args: int) -> None:
    if LIBC.prctl(ctypes.c_int(option), *(ctypes.c_ulong(a) for a in (*args, 0, 0, 0, 0)[:4])) != 0:
        err: int = ctypes.get_errno()
        raise OSError(err, f"prctl({option}): {os.strerror(err)}")


class SockFprog(ctypes.Structure):  # struct sock_fprog
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def load_seccomp(program: bytes) -> None:
    if len(program) % 8:  # array of 8-byte struct sock_filter
        raise Exception(f"seccomp program size {len(program)} is not a multiple of 8")
    buf = ctypes.create_string_buffer(program, len(program))
    fprog = SockFprog(len(program) // 8, ctypes.addressof(buf))
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(fprog))


# like bwrap does for its child: empty the bounding set, so even a uid 0 can't regain
# capabilities on exec, then clear effective/permitted/inheritable (& thus ambient) sets
def drop_capabilities(cap_last: int) -> None:
    try:
        for cap in range(cap_last + 1):
            prctl(PR_CAPBSET_DROP, cap)
    except PermissionError:  # lacking CAP_SETPCAP, i.e. we hold no caps to begin with
        if os.geteuid() == 0:
            raise
    header = (ctypes.c_uint32 * 2)(LINUX_CAPABILITY_VERSION_3, 0)
    data = (ctypes.c_uint32 * 6)()  # 2x struct __user_cap_data_struct, all zeroes
    if LIBC.capset(header, data) != 0:
        err: int = ctypes.get_errno()
        raise OSError(err, f"capset: {os.strerror(err)}")


# Runs [cmd] inside a running singleton's namespaces, applying what bwrap would apply to
# its own child: no capabilities, no_new_privs, the seccomp program, newSession & dieWithParent.
#
# Done in-process rather than via `nsenter`, as nsenter can't apply seccomp, and its
# --keep-caps would leave [cmd] with the full capability set that joining a user ns grants
# (bwrap's own child runs with none).
#
# Some options can't be reproduced here, so they're rejected rather than silently skipped,
# which would run [cmd] less confined than the instance's own processes:
# - fd-based [seccomp] & [addSeccompFd]: these name fds the user handed to the launch that
#   started the instance; bwrap read & consumed them then, so there's no program to load now;
# - [capAdd]: keeping select caps across exec for a non-root uid needs ambient caps & a
#   cap-name-to-number table, i.e. reimplementing bwrap's cap handling; dropping
#   everything instead would break whatever needed those caps.
def enter_existing_ns(bwrap_info: dict, sb: dict, cmd: list[str]) -> NoReturn:
    if sb.get("capAdd") or sb.get("addSeccompFd") or isinstance(sb.get("seccomp"), int):
        raise Exception("entering a running singleton supports neither [capAdd], [addSeccompFd] nor fd-based [seccomp]")
    seccomp: bytes|None = get_seccomp_program(sb["seccomp"]) if sb.get("seccomp") else None

    target: psutil.Process|None = next(iter(bwrap_info["bwrap_proc"].children()), None)  # first child running _in_ the sandbox
    if target is None:
        raise Exception("running singleton instance has no sandboxed process to enter")
    pidfd: int = os.pidfd_open(target.pid)  # pins the process, so the checks below can't race a pid reuse
    with open(f"/proc/{target.pid}/environ", "rb") as f:
        env: dict[str, str] = dict(os.fsdecode(e).split("=", 1) for e in f.read().split(b"\0") if b"=" in e)
    flags: int = 0
    for key, (name, flag) in (("user-namespace", ("user", os.CLONE_NEWUSER)), *NAMESPACES.items()):
        if key != "user-namespace" and key not in bwrap_info:
            continue
        ino: int = os.stat(f"/proc/{target.pid}/ns/{name}").st_ino
        if key in bwrap_info and ino != bwrap_info[key]:
            raise Exception(f"pid {target.pid} is not in the singleton's recorded {name} namespace")
        if ino != os.stat(f"/proc/self/ns/{name}").st_ino:  # (re)joining one's own user ns is EINVAL
            flags |= flag
    signal.pidfd_send_signal(pidfd, 0)  # raises if it exited, i.e. the /proc reads above may be of another process
    cap_last: int = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
    host_cwd: str = os.getcwd()

    # Join all namespaces in one setns(pidfd, flags) call, not one by one: bwrap may nest
    # the sandboxed process' user ns one level below the user ns that owns the sandbox's
    # mount & pid namespaces (seen e.g. when the profile mounts /dev). Joining that lower user
    # ns grants caps only within it, not in its parent that owns the mount ns, so a
    # subsequent setns(mnt) fails with EPERM. The pidfd variant validates the whole set
    # at once, the same way recent nsenter does it.
    if flags:
        os.setns(pidfd, flags)
    os.close(pidfd)

    if wd := sb.get("chdir"):
        os.chdir(expand(wd, sb["format_vars"]))
    else:  # same fallbacks as bwrap: the original cwd, then $HOME, then /
        for d in (host_cwd, env.get("HOME"), "/"):
            try:
                os.chdir(d)
                break
            except (OSError, TypeError):
                pass

    LOGGER.debug("entering pid %s namespaces (flags %#x) to run: %s", target.pid, flags, shlex.join(cmd))
    if (child := os.fork()) == 0:  # joining a pid ns only applies to children
        try:
            if sb.get("newSession") is True:
                os.setsid()
            if sb.get("dieWithParent") is True:
                prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
            drop_capabilities(cap_last)
            prctl(PR_SET_NO_NEW_PRIVS, 1)
            if seccomp is not None:
                load_seccomp(seccomp)  # last, as the filter may forbid the syscalls above
            exec(cmd[0], *cmd, env=env)
        except BaseException as e:
            print(f"failed to run [{cmd[0]}] in the singleton sandbox: {e}", file=sys.stderr)
            os._exit(127)

    for sig in (signal.SIGINT, signal.SIGQUIT):  # leave terminal signals to the child, like a shell does
        signal.signal(sig, signal.SIG_IGN)
    code: int = os.waitstatus_to_exitcode(os.waitpid(child, 0)[1])
    if code < 0:  # killed by a signal: die the same way
        signal.signal(-code, signal.SIG_DFL)
        os.kill(os.getpid(), -code)
        code = 128 - code
    sys.exit(code)


def parse_args() -> tuple[argparse.Namespace, list[tuple[str, str]]]:
    sources: list[tuple[str, str]] = []  # (passed-option, value) tuples in cli order, e.g. ('id', 'value-for-id'), ('json', '{"some-key":"some-val"}')
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--log-level", choices=[lvl.lower() for lvl in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")])
    parser.add_argument("-i", "--id", action=tagged_append("id", sources))  # can be a comma-separated list
    parser.add_argument("-j", "--json", action=tagged_append("json", sources))
    parser.add_argument("-f", "--file", action=tagged_append("file", sources))  # needs to be yaml file!
    parser.add_argument("-s", "--set", action=tagged_append("set", sources))
    parser.add_argument("-a", "--autoload", action="store_true")
    parser.add_argument("-M", "--no-match", action="store_true")
    parser.add_argument("-D", "--no-default", action="store_true")
    parser.add_argument("--default-sandbox", action="store", default="default")
    parser.add_argument("executable", nargs="?")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    return parser.parse_args(), sources


# turns a `-s path.to.key=value` arg into a config dict
def parse_set_arg(source_data: str) -> dict:
    k, v = source_data.split("=", 1)
    k = re.sub(r"^\$", "env.", re.sub(r"^:", "vars.", k))
    v = json.loads(v) if v and (v[0] in '"[{' or v in ("true", "false", "null")) else v
    if k in ("include", "@include") and isinstance(v, str):
        k, v = "include", [i for i in (i.strip() for i in v.split(",")) if i]
    obj = {}
    cur = obj
    for is_array, p, end in re.findall(r'(?:^|\.)(@?)("[^"=]+"|[^".=]+)(=$)?', f"{k}="):
        p = p[1:-1] if p.startswith('"') else p
        c = v if end else {}
        if is_array:
            cur[p] = [c]
            cur = cur[p][0]
        else:
            cur[p] = c
            cur = cur[p]
    return obj


# returns all active sandbox configs to be merged, and the subset of them selected via -i
def collect_configs(args: argparse.Namespace, sources: list[tuple[str, str]],
                    executable_name: str) -> tuple[list[dict], list[dict]]:
    global_sandboxes: list[dict] = []
    for global_path in (SB_CONFIG / "config.yaml", SB_CONFIG / "config.yml"):
        if global_path.is_file():
            global_sandboxes += load_sandboxes_file(global_path)

    configs: list[dict] = []
    cli_id_configs: list[dict] = []
    for source_type, source_data in sources:
        match source_type:
            case "id":
                for id in (i.strip() for i in source_data.split(",")):
                    if id:
                        configs.append(sb := load_sandbox(id))
                        cli_id_configs.append(sb)
            case "json":
                configs.append(json.loads(source_data))
            case "file":
                configs += load_sandboxes_file(source_data)
            case "set":
                configs.append(parse_set_arg(source_data))
            case _:
                raise NotImplementedError

    if args.autoload:
        if (sb := try_load_sandbox(executable_name)) and sb not in configs:
            configs.append(sb)

    # TODO: do we want to utilize the 'matches' logic when given ID(s) is/are given via -i flag?
    if not args.no_match:
        for gs in global_sandboxes:
            if executable_name in gs.get("matches", ()) and gs not in configs:
                configs.append(gs)

    if not configs:
        if args.no_default:
            raise Exception(f"no matching sandbox config(s) found, and defaulting to [{args.default_sandbox}] sandbox is disallowed")
        configs.append(load_sandbox(args.default_sandbox))
    return configs, cli_id_configs


def main() -> NoReturn:
    args, sources = parse_args()
    if args.log_level:
        logging.basicConfig(stream=sys.stdout, level=getattr(logging, args.log_level.upper()), force=True)

    executable_name: str = os.path.basename(args.executable or os.environ.get("SHELL", "sh"))
    cmd: list[str] = [args.executable or executable_name, *args.args]
    configs, cli_id_configs = collect_configs(args, sources, executable_name)
    debug_object("configs", configs)

    app_base: str = "org.bubblebox"  # note app name needs to contain '.' in it for portals to work!
    instance_id: str = f"{app_base}-{os.getpid()}"
    default_vars: dict[str, str] = {
        "instance_id": instance_id,
        "home": HOME,  # if using prefix home, then prefer using ~ instead
        "uid": UID,
        "xdg_runtime": XDG_RUNTIME,
        "xdg_config": str(XDG_CONFIG),
        "xdg_data": os.environ.get("XDG_DATA_HOME", f"{HOME}/.local/share"),
        "xdg_state": os.environ.get("XDG_STATE_HOME", f"{HOME}/.local/state"),
        "xdg_cache": os.environ.get("XDG_CACHE_HOME", f"{HOME}/.cache"),
        "cwd": os.getcwd(),
        "exe_arg": args.executable,  # str | None
        "exe_name": executable_name,  # used to be the old name/fqname value prior to adding mandatory dot for portal (but we don't want fqname e.g. in our private-home dirname)
        # NOTE: either allow defining default 'name' var here and make sure to use it directly in private-home profile's [mount], OR
        #       remove default 'name' here, which would allow you to reference it in private-home's [private-home' var, e.g. [private-home: "{xdg_data}/bubblebox/homes/{name}"]
        #       if you keep the default and reference it in another var, then you won't be able to overwrite the name, and private home dir will
        #       always be named this default
        "name": executable_name,
        "fqname": f"{app_base}.{executable_name}",  # fully qualified
    }

    sb: dict = get_sandbox(merge_sandboxes(configs, SafeDict(**os.environ, **default_vars)), default_vars)
    # [id] keys the singleton instance, so a profile picked via -i owns it even when a later
    # source (e.g. `-s @include=base`, a global `matches` profile) also sets an [id].
    # Only an [id] set by the profile itself counts, not one inherited through its includes:
    for cli_sb in reversed(cli_id_configs):
        if id := cli_sb.get("id"):
            sb["id"] = id
            break
    debug_object("sandbox", sb)

    # TODO: consider removing this option; although this allows us to use matches: key
    #       in config to selectively disable sandboxing for select commands...
    if sb.get("disableSandbox") is True:
        exec(cmd[0], *cmd)

    singleton: bool = sb.get("singleton") is True
    bwrap_infof: str = f"{XDG_RUNTIME}/.flatpak/{instance_id}/bwrapinfo.json"
    singleton_location: str = f"{XDG_RUNTIME}/bubblebox/{sb.get("id")}.instance.info"  # file containing bwrap_infof path for this profile's running instance
    # entering existing namespace(s) can't apply config, so refuse to enter an instance started from a different one.
    # Hashed before vars/env expansion, which differs per run (instance_id, cwd, host env).
    config_hash: str = hashlib.sha256(json.dumps(merge_sandboxes(configs, SafeDict()), sort_keys=True,
                                                 default=str).encode()).hexdigest() if singleton else ""
    if singleton and (bwrap_info := get_running_instance_bwrapinfo(singleton_location, sb.get("id"))):
        LOGGER.debug(f"existing bwrap instance (from {singleton_location}): {bwrap_info}")
        if bwrap_info["config_hash"] != config_hash:
            raise Exception(f"running [{sb["id"]}] singleton instance was started with a different config; "
                            "exit it first, or drop the config changes (extra -i/-j/-f/-s/-a, edited profiles)")
        enter_existing_ns(bwrap_info, sb, cmd)

    bwrap_args: list[str] = get_bwrap_args(sb)
    bwrap_args += setup_dbus_proxy(sb, instance_id, default_vars)
    bwrap_args += get_bwrapinfo_args(bwrap_infof)  # leave this last, as it opens a file; we don't want any
                                                   # fork()s after this, as the open fd would get duplicated
    if singleton:
        if not sb.get("id"):
            raise Exception("singleton=True set, but no [id] attr configured")
        os.makedirs(os.path.dirname(singleton_location), exist_ok=True)
        with open(singleton_location, "w") as f:
            f.write(f"{bwrap_infof}\n{config_hash}")

    LOGGER.debug("bwrap command: %s\n", shlex.join(["bwrap", *bwrap_args, "--", *cmd]))
    exec("bwrap", "bwrap", "--args", pipefd_args(bwrap_args), "--", *cmd)


if __name__ == "__main__":
    main()

# TODO: document that 'vars' cannot contain 'env' key, as it'll get overwritten
# TODO: consider renaming 'path' key in mount config to 'src'
