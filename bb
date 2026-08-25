#!/usr/bin/python
#
# original ver from https://gist.github.com/sloonz/ef282a1f53366e1ed6f5cb848de015ba#file-sandbox2-py (as of Feb '26)

import argparse
import base64
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
import fcntl
import psutil


# allows for stacking env vars, e.g. multiple profiles having
# PATH: "/some/dir:{PATH}" while _still_ allowing for later-expanded vars; i.e.
# can extend as opposed to overwriting previous values
class SafeDict(UserDict):
    # makes sure missing format key does not throw KeyError, but leaves the format unexpanded;
    # this also means get() should be invoked on instances of this dict only w/ format_map()
    def __missing__(self, key):
        return "{" + key + "}"

    def __setitem__(self, key, value):
        if (isinstance(value, (str, int, float))
                and value not in (True, False)):  # note we don't store bools either (bool is subclass of int!)
            super().__setitem__(key, os.path.expanduser(str(value)))


LOGGER: logging.Logger = logging.getLogger()

HOME: str = os.environ["HOME"]
XDG_CONFIG: Path = Path(os.environ.get("XDG_CONFIG_HOME", f"{HOME}/.config"))
XDG_RUNTIME: str = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")

SB_CONFIG: Path = XDG_CONFIG / "bubblebox"

SANDBOXES_CACHE: dict[str, dict] = {}
GLOBAL_SANDBOXES: list[dict] = []

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
        .union({"disableSandbox", "dbus.sloppyNames",
                "dbus.user.sloppyNames", "dbus.system.sloppyNames",
                "dbus.sandbox.*", "dbus.policies.*", "dbus.user.policies.*",
                "dbus.system.policies.*"}),
  "list": BWRAP_LIST_OPTIONS
        .union({"extraArgs", "matches"}),
  "literal-expandable": {"env.*", "vars.*"},
  "dict": {"vars", "env", "dbus", "dbus.sandbox", "dbus.policies",
           "dbus.user.policies", "dbus.system.policies", "dbus.user", "dbus.system",
           "dbus.rules", "dbus.user.rules", "dbus.system.rules"},
  "discard": {"name", "include"},
}


# TODO: should we also do os.path.expandvars() ?
def expand(var: str, fmt: dict) -> str:
    return os.path.expanduser(var.format(**fmt))


def tagged_append(tag: str, dest: list[tuple[str,str]]):
    class TaggedAppend(argparse.Action):
        def __call__(self, parser, ns, values, option_string: str|None=None) -> None:
            dest.append((tag, values))
    return TaggedAppend


def load_sandboxes_file(path: Path|str, default_name: str|None=None) -> list[dict]:
    LOGGER.debug("loading %s", path)
    with open(path) as fd:
        sandboxes: list[dict] = list(yaml.safe_load_all(fd))
        for i, sb in enumerate(sandboxes):
            if name := sb.get("name", default_name if i == 0 else None):
                SANDBOXES_CACHE[name] = sb
        return sandboxes


def try_load_sandbox(name: str) -> dict|None:
    if name == "config":  # global app config
        raise Exception(f"profile/config name cannot be [{name}]")
    elif name in SANDBOXES_CACHE:
        return SANDBOXES_CACHE[name]

    candidate_paths: tuple[Path, ...] = (
        Path(name),
        Path(f"{name}.yml"),
        Path(f"{name}.yaml"),
        SB_CONFIG / f"{name}.yml",
        SB_CONFIG / f"{name}.yaml",
    )
    for p in candidate_paths:
        if p.is_file():
            return load_sandboxes_file(p, name)[0]


def load_sandbox(name: str) -> dict:
    if (sb := try_load_sandbox(name)) is not None:
        return sb
    raise Exception(f"[{name}] sandbox not found")


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
                res[k] = merge(a.get(k, {}), b.get(k, {}), format_env, key_path)
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
        inc: dict = {"name": inc_in} if isinstance(inc_in, str) else inc_in
        if name := inc.get("name"):
            if inc.get("try"):
                if sb := try_load_sandbox(name):
                    return sb
                return {}
            return load_sandbox(name)
        elif path := inc.get("path"):
            if inc.get("try") and not os.path.isfile(path):
                return {}
            return load_sandboxes_file(path)[0]

        # TODO: should we not raise a proper error here?
        assert False

    res = {}
    for sb in sandboxes:
        inc = merge_sandboxes((load_include(child_sb) for child_sb in sb.get("include", ())), format_env)
        res = merge(res, merge(inc, sb, format_env), format_env)
    return res


# note passed sb is the final/merged/resolved sandbox config
#
# returns enriched sandbox with env/vars/mounts/chmod data
def get_sandbox(sb: dict) -> dict:
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
        # TODO: int,float shouldn't occur anymore due to SafeDict, right?:
        elif isinstance(v, (int, float)):
            raw_env[k] = str(v)
        else:
            raise Exception(f"Invalid value for environment variable {k}: {repr(v)}")

    # note format_vars is used to expand our raw_vars & raw_env via python's
    # string.format() method, passing **format_vars as possible values to
    # be expanded into the raw values
    raw_vars: dict = {**sb.get("vars", {})}
    vars: dict = {**DEFAULT_VARS}
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
            print(f"cirular!! env: {raw_env.keys()}  var: {raw_vars.keys()}")
            # TODO: should we not raise a proper error here?
            assert False  # circular definition

    # Parse mounts & chmod; note sb[mounts|chmod] are tuple[key,v] because of 'items' merge policy:
    mounts: dict[str, Any] = {expand(k, format_vars).rstrip("/"): v for k, v in sb.get("mounts", ()) if v}
    chmod: dict[str, Any] = {expand(k, format_vars).rstrip("/"): v for k, v in sb.get("chmod", ()) if v}

    return {**sb, "vars": vars, "env": env, "envUnset": env_unset,
            "mounts": mounts, "chmod": chmod}


# returns string representation of read end of the pipe FD
def pipefd(data: bytes) -> str:
    pr, pw  = os.pipe2(0)
    if os.fork() == 0:
        os.close(pr)
        os.write(pw, data)
        sys.exit(0)  # immediately exit the child process
    else:
        os.close(pw)
        return str(pr)


def pipefd_args(args: list[str]) -> str:
    return pipefd("\0".join(args).encode("utf-8"))


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
        if isinstance(value, dict):  # {data: string, arch: string}
            value = [value]

        if isinstance(value, list):  # {data: string, arch: string}[]
            data: list[bytes] = [base64.b64decode(prog["data"]) for prog in value if prog["arch"] == platform.machine()]
            if len(data) == 0:
                raise Exception(f"seccomp program not found for our architecture: {platform.machine()}")
            elif len(data) != 1:
                raise Exception(f"{len(data)} seccomp programs found for our architecture {platform.machine()}, expected 1")
            return pipefd(data[0])
        else:  # fd
            return str(value)

    # TODO: what are the possible 'value' types? is it dict|list|int|str?
    def format_option_value(opt_name: str, value) -> str:
        if opt_name in ("seccomp", "addSeccomp"):
            return format_seccomp_value(value)
        elif opt_name in ("userns", "userns2", "pidns", "syncFd", "blockFd",
                          "userNsBlockFd", "infoFd", "jsonStatusFd"):
            return str(value)
        return str(value).format(**format_vars)  # TODO: instead of .format(), invoke our expand()?

    def format_datasource_value(value) -> str:  # {fd: number} | {content: string, raw?: boolean, base64?: boolean}
        if (fd := value.get("fd")) is not None:
            return str(fd)
        elif (content := value.get("content")) is not None:
            if not value.get("raw"):
                content = content.format(**format_vars)  # TODO: instead of .format(), invoke our expand()?

            if value.get("base64"):
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
    args += (arg.format(**format_vars) for arg in sb.get("extraArgs", ()))  # TODO: instead of .format(), invoke our expand()?
    for e in sb["envUnset"]:
        args += ("--unsetenv", e)
    for k, v in sb["env"].items():
        args += ("--setenv", k, v)

    # note dest_path is on the sandbox side; note it's sorting lexicographically by the first element's (ie. key); not length
    for dest_path, mount in sorted(sb["mounts"].items()):
        if mount in ("proc", "dev", "tmpfs", "mqueue", "dir"):
            # TODO: is there a need to do dest_path.format(**format_vars) anymore, given
            #       key formatting was already done in the end of get_sandbox()?
            args += (f"--{mount}", dest_path.format(**format_vars))  # TODO: instead of .format(), invoke our expand()?
        # 'bind' convenience for when SRC & DEST are the same; note:
        # - it covers also '-try' or '-create' suffixes;
        # - the '-create' suffix is our own convention and will be stripped from final flag;
        #   it creates the SRC dir if it doesn't exist
        elif isinstance(mount, str) and re.match(r"(ro-|dev-)?bind(-try|-create)?(:\S|$)", mount):
            src_path = dest_path
            if ":" in mount:
                mount, src_path = mount.split(":", 1)
                src_path = expand(src_path, format_vars)
            if mount.endswith("-create"):
                mount = mount.removesuffix("-create")
                os.makedirs(src_path, exist_ok=True)
            args += (f"--{mount}", src_path, dest_path)
        elif isinstance(mount, str) and mount.startswith("symlink:"):
            args += ("--symlink", expand(mount.removeprefix("symlink:"), format_vars), dest_path)
        elif isinstance(mount, dict):
            if (tmpfs := mount.get("tmpfs")) is not None:  # { tmpfs: { perms?: number; size?: number }}
                args += get_perms(tmpfs)
                if (size := tmpfs.get("size")) is not None:
                    args += ("--size", str(size))
                args += ("--tmpfs", dest_path)
            elif (dir := mount.get("dir")) is not None:  # { dir: { perms?: number }}
                args += get_perms(dir)
                args += ("--dir", dest_path)
            elif (symlink := mount.get("symlink")) is not None:  # { symlink: string }
                args += ("--symlink", symlink.format(**format_vars), dest_path)  # TODO: instead of .format(), invoke our expand()?
            elif (bind := mount.get("bind")) is not None:  # { bind: { path: string; ro?: boolean; dev?: boolean; try?: boolean, create?: boolean }}
                prefix = "dev-" if bind.get("dev") else "ro-" if bind.get("ro") else ""
                suffix = "-try" if bind.get("try") else ""
                src_path = expand(bind.get("path", dest_path), format_vars)
                if bind.get("create") is True:
                    os.makedirs(src_path, exist_ok=True)
                args += (f"--{prefix}bind{suffix}", src_path, dest_path)
            elif (fd := mount.get("fd")) is not None:  # { fd: { fd: number; ro?: boolean }}
                args += ("--ro-bind-fd" if fd.get("ro") else "--bind-fd", str(fd["fd"]))
            elif (file := mount.get("file")) is not None:  # { file: DataSource & { perms?: number }}
                args += get_perms(file)
                args += ("--file", format_datasource_value(file), dest_path)
            elif (data := mount.get("data")) is not None:  # { data: DataSource & { ro?: boolean; perms?: number }}
                args += get_perms(data)
                args += ("--ro-bind-data" if data.get("ro") else "--bind-data",
                         format_datasource_value(data), dest_path)
            elif (overlay := mount.get("overlay")) is not None:  # { overlay: { lower: string[]; upper?: string; work?: string; mode?: "rw" | "tmp" | "ro" }}
                for lower in overlay["lower"]:
                    args += ("--overlay-src", lower.format(**format_vars))  # TODO: instead of .format(), invoke our expand()?
                mode = overlay.get("mode", "rw" if "upper" in overlay and "work" in overlay else "tmp")
                if mode == "rw":
                    args += ("--overlay", overlay["upper"], overlay["work"], dest_path)  # i.e. --overlay RWSRC WORKDIR DEST
                else:
                    args += (f"--{mode}-overlay", dest_path)
            else:
                raise Exception(f"invalid mount value: {repr(mount)}")
        else:
            raise Exception(f"invalid mount (of type {type(mount)}) value: {repr(mount)}")
    # TODO: is there need to do path.format(**format_vars) anymore, given
    #       key formatting was already done in the end of get_sandbox()?
    # TODO: is sorting for chmod needed? note it's sorting lexicographically by the first element's (ie. key); not length
    for path, mode in sorted(sb["chmod"].items()):
        args += ("--chmod", str(mode), path.format(**format_vars))
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
        ruleset: list[tuple[str, str]] = dbus.get("rules", {}).get(rule_type, []) + \
                                         b.get("rules", {}).get(rule_type, [])
        args += (f"--{rule_type}={name}={rule}" for name, rule in ruleset)
    return args


# if required so by the sb's config, start a xdg-dbus-proxy subprocess and
# return additional bwrap parameters to pass to the main sandbox command
def setup_dbus_proxy(sb: dict) -> list[str]|tuple[()]:
    if not (dbus := sb.get("dbus")):
        if "dbus" in sb:  # sanity
            raise Exception("empty [dbus] key/block not allowed")
        return ()  # no dbus proxies configured, bail

    proxy_dir: str = f"{XDG_RUNTIME}/xdg-dbus-proxy/{INSTANCE_ID}"

    unix_path_prefix: str = "unix:path="
    dbus_sess_bus_env_var: str = "DBUS_SESSION_BUS_ADDRESS"
    dbus_session_address: str = os.environ.get(dbus_sess_bus_env_var, f"{unix_path_prefix}/run/user/{os.getuid()}/bus")
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
        prefix = f"[{sb['name']}] " if "name" in sb else ""
        raise Exception(f"{prefix}sandbox has [dbus] block configured, but none of {[b[0] for b in buses]} buses under it")

    os.makedirs(proxy_dir, exist_ok=True)
    pr, pw = os.pipe2(0)
    dbus_proxy_args = ["xdg-dbus-proxy", f"--fd={pw}"] + dbus_proxy_args
    LOGGER.debug("proxy args for dbus proxy: %s\n", shlex.join(dbus_proxy_args))

    # if 'dbus.sandbox' defined, then it means xdg-dbus-proxy itself is to be ran in bwrap as well:
    # TODO: as of May '26, portals do not work if x-d-p runs unsandboxed:
    if proxy_sb := dbus.get("sandbox"):
        proxy_sb: dict = get_sandbox(merge_sandboxes((proxy_sb,), SafeDict(**os.environ, **DEFAULT_VARS)))  # note we call merge_sandboxes() to get the [include] resolution/expansion
        debug_object("dbus proxy sandbox", proxy_sb)
        proxy_bwrap_args = get_bwrap_args(proxy_sb) + proxy_bwrap_args
        dbus_proxy_args = ["bwrap", "--args", pipefd_args(proxy_bwrap_args), "--"] + dbus_proxy_args
        LOGGER.debug("bwrap args for xdg-dbus-proxy: %s\n", shlex.join(proxy_bwrap_args))

    if os.fork() == 0:
        os.close(pr)
        os.execlp(dbus_proxy_args[0], *dbus_proxy_args)
    else:
        os.close(pw)
        assert os.read(pr, 1) == b"x"
        return ["--sync-fd", str(pr)] + cmd_bwrap_args


# for some explanation, see e.g.
# - https://github.com/ValveSoftware/steam-for-linux/issues/10645#issuecomment-2013609605
# - https://gist.github.com/sloonz/4b7f5f575a96b6fe338534dbc2480a5d#gistcomment-5515250
def get_bwrapinfo_args() -> tuple[str, str]:
    global INFO_FD  # so it's not gc-d prematurely
    os.makedirs(os.path.dirname(BWRAP_INFOF), exist_ok=True)
    INFO_FD = open(BWRAP_INFOF, "w")
    fcntl.fcntl(INFO_FD, fcntl.F_SETFD, 0)
    return "--info-fd", str(INFO_FD.fileno())


def debug_object(label: str, obj: object) -> None:
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug(f"{label}:\n{pprint.pformat(obj)}")


def process_active(pid: int) -> bool:
    try:
        return (psutil.pid_exists(pid) and psutil.Process(pid).status()
                not in (psutil.STATUS_DEAD, psutil.STATUS_ZOMBIE))
    except psutil.Error:  # includes NoSuchProcess error
        return False


def get_running_instance_bwrapinfo() -> dict|None:
    try:
        with open(SINGLETON_LOCATION, "r") as f:
            bwrap_infof = f.read()
        with open(bwrap_infof, "r") as f:
            info = json.loads(f.read())
        if process_active(info["child-pid"]):
            return info
    except IOError:
        pass


# TODO: lacking seccomp filters; consider re-adding, or migrating to gvisor?
#       alternatively consider https://gist.github.com/sloonz/4b7f5f575a96b6fe338534dbc2480a5d?permalink_comment_id=5926910#file-sandbox-py-L135-L142
def enter_existing_ns(bwrap_info: dict) -> NoReturn:
    pid: int = bwrap_info["child-pid"]  # this is the PID of bwrap process
    child: psutil.Process = next(x for x in psutil.Process(pid).children())  # first child running _in_ the namespace
    nsent_args: list[str] = ["nsenter", "--preserve-credentials", "--user",
                             "--keep-caps", "--env", "--target", str(child.pid)]
    if "mnt-namespace" in bwrap_info:
        nsent_args += "--mount"
    if "pid-namespace" in bwrap_info:
        nsent_args += "--pid"
    if "net-namespace" in bwrap_info:
        nsent_args += "--net"
    if "ipc-namespace" in bwrap_info:
        nsent_args += "--ipc"
    if "uts-namespace" in bwrap_info:
        nsent_args += "--uts"
    if "cgroup-namespace" in bwrap_info:
        nsent_args += "--cgroup"

    if wd := SB.get("chdir"):
        nsent_args += f"--wdns={wd}"

    nsent_args += ("--", EFFECTIVE_EXEC, *ARGS.args)
    LOGGER.debug("nsenter command: %s\n", shlex.join(nsent_args))
    os.execlp(nsent_args[0], *nsent_args)


# ENTRY
#################################
CONFIGS_SOURCES: list[tuple[str,str]] = []  # contains (passed-option, value) tuples, e.g. ('name', 'value-for-name'), ('json', '{"some-key":"some-val"}')
parser = argparse.ArgumentParser()
parser.add_argument("-l", "--log-level", choices=[lvl.lower() for lvl in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")])
parser.add_argument("-n", "--name", action=tagged_append("name", CONFIGS_SOURCES))  # can be a comma-separated list
parser.add_argument("-j", "--json", action=tagged_append("json", CONFIGS_SOURCES))
parser.add_argument("-f", "--file", action=tagged_append("file", CONFIGS_SOURCES))  # needs to be yaml file!
parser.add_argument("-s", "--set", action=tagged_append("set", CONFIGS_SOURCES))
parser.add_argument("-a", "--autoload", action="store_true")
parser.add_argument("-M", "--no-match", action="store_true")
parser.add_argument("-D", "--no-default", action="store_true")
parser.add_argument("--default-sandbox", action="store", default="default")
parser.add_argument("executable", nargs="?")
parser.add_argument("args", nargs=argparse.REMAINDER)
ARGS: argparse.Namespace = parser.parse_args()

if ARGS.log_level:
    logging.basicConfig(stream=sys.stdout, level=getattr(logging, ARGS.log_level.upper()), force=True)

for global_path in (SB_CONFIG / "config.yaml", SB_CONFIG / "config.yml"):
    if global_path.is_file():
        GLOBAL_SANDBOXES += load_sandboxes_file(global_path)

CONFIGS: list[dict] = []  # active sandbox configs to use, will be merged into a single sandbox config
for source_type, source_data in CONFIGS_SOURCES:
    match source_type:
        case "name":
            for name in [n.strip() for n in source_data.split(",")]:
                if name:
                    CONFIGS.append(load_sandbox(name))
        case "json":
            CONFIGS.append(json.loads(source_data))
        case "file":
            CONFIGS += load_sandboxes_file(source_data)
        case "set":
            k, v = source_data.split("=", 1)
            k = re.sub(r"^\$", "env.", re.sub(r"^:", "vars.", k))
            v = json.loads(v) if v and (v[0] in '"[{' or v in ("true", "false", "null")) else v
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
            CONFIGS.append(obj)
        case _:
            raise NotImplementedError

EXECUTABLE_NAME: str = os.path.basename(ARGS.executable or os.environ.get("SHELL", "sh"))
EFFECTIVE_EXEC: str = ARGS.executable or EXECUTABLE_NAME

if ARGS.autoload:
    if (sb := try_load_sandbox(EXECUTABLE_NAME)) and sb not in CONFIGS:
        CONFIGS.append(sb)

if not ARGS.no_match:
    for gs in GLOBAL_SANDBOXES:
        if EXECUTABLE_NAME in gs.get("matches", ()) and gs not in CONFIGS:
            CONFIGS.append(gs)

if not CONFIGS:
    if ARGS.no_default:
        raise Exception(f"no matching sandbox config(s) found, and defaulting to [{ARGS.default_sandbox}] sandbox is disallowed")
    CONFIGS.append(load_sandbox(ARGS.default_sandbox))

debug_object("configs", CONFIGS)

APP_BASE: str = "org.bubblebox"  # note app name needs to contain '.' in it for portals to work!
INSTANCE_ID: str = f"{APP_BASE}-{os.getpid()}"
DEFAULT_VARS: dict[str, str] = {
    "instance_id": INSTANCE_ID,
    "home": HOME,  # if using prefix home, then prefer using ~
    "xdg_runtime": XDG_RUNTIME,
    "xdg_config": str(XDG_CONFIG),
    "xdg_data": os.environ.get("XDG_DATA_HOME", f"{HOME}/.local/share"),
    "xdg_state": os.environ.get("XDG_STATE_HOME", f"{HOME}/.local/state"),
    "xdg_cache": os.environ.get("XDG_CACHE_HOME", f"{HOME}/.cache"),
    "cwd": os.getcwd(),
    "exe_arg": ARGS.executable,  # str | None
    "exe_name": EXECUTABLE_NAME,  # used to be the old name/fqname value prior to adding mandatory dot for portal (but we don't want fqname e.g. in our private-home dirname)
    "name": EXECUTABLE_NAME,  # alias for "exe_name"
    "fqname": f"{APP_BASE}.{EXECUTABLE_NAME}",  # fully qualified
}

SB: dict = get_sandbox(merge_sandboxes(CONFIGS, SafeDict(**os.environ, **DEFAULT_VARS)))
debug_object("sandbox", SB)

# TODO: consider removing this option; although this allows us to use matches: key
#       in config to selectively disable sandboxing for select commands...
if SB.get("disableSandbox") is True:
    os.execlp(ARGS.executable, ARGS.executable, *ARGS.args)

BWRAP_INFOF = f"{XDG_RUNTIME}/.flatpak/{INSTANCE_ID}/bwrapinfo.json"
SINGLETON_LOCATION = f"{XDG_RUNTIME}/bubblebox/{SB.get("name")}.instance.info"
if SB.get("singleton") is True and (bwrap_info := get_running_instance_bwrapinfo()):
    enter_existing_ns(bwrap_info)

BWRAP_ARGS: list[str] = get_bwrap_args(SB)
BWRAP_ARGS += setup_dbus_proxy(SB)
BWRAP_ARGS += get_bwrapinfo_args()  # leave this last, as it will open() a file, thus we dont want any previous
                                    # fork()s after this, as open files & other resources would get duplicated
if SB.get("singleton") is True:
    os.makedirs(os.path.dirname(SINGLETON_LOCATION), exist_ok=True)
    with open(SINGLETON_LOCATION, "w") as f:
        f.write(BWRAP_INFOF)

LOGGER.debug("bwrap command: %s\n", shlex.join(["bwrap"] + BWRAP_ARGS +
                                               ["--", EFFECTIVE_EXEC] + ARGS.args))
os.execlp("bwrap", "bwrap", "--args", pipefd_args(BWRAP_ARGS), "--", EFFECTIVE_EXEC, *ARGS.args)

# TODO: document that 'vars' cannot contain 'env' key, as it'll get overwritten
# TODO: consider renaming 'path' key in mount config to 'src'

