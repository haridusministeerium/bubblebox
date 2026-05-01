#!/usr/bin/python
#
# original ver from https://gist.github.com/sloonz/ef282a1f53366e1ed6f5cb848de015ba#file-sandbox2-py (as of Feb '26)

import argparse
import base64
import json
import logging
import os
from pathlib import Path
from collections.abc import Iterable, Sequence
from typing import Any
import platform
import pprint
import re
import shlex
import sys
import yaml

LOGGER: logging.Logger = logging.getLogger()

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

MERGE_POLICIES: dict[str, set[str]] = {
  "items": {"mounts", "chmod"},
  # TODO: wouldn't "override" or "overwrite" be a better name than "literal"?
  "literal": BWRAP_FLAGS.union(BWRAP_OPTIONS).union({"disableSandbox", "vars.*", "env.*", "dbus.sloppyNames.*",
                                                     "dbus.sandbox.*", "dbus.user.*", "dbus.system.*"}),
  "list": BWRAP_LIST_OPTIONS.union({"extraArgs"}).union({"matches", "dbus.rules.*.*.*"}),
  "dict": {"vars", "env", "dbus", "dbus.sloppyNames", "dbus.sandbox",
           "dbus.user", "dbus.system", "dbus.rules.*", "dbus.rules.*.*"},
  "discard": {"name", "include"},
}


def tagged_append(tag: str, dest: list[tuple[str,str]]):
    class TaggedAppend(argparse.Action):
        def __call__(self, parser, ns, values, option_string: str|None=None):
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
    if name in SANDBOXES_CACHE:
        return SANDBOXES_CACHE[name]
    candidate_paths = [
        Path(name),
        Path(f"{name}.yml"),
        Path(f"{name}.yaml"),
        Path.home() / ".config" / "sandbox" / f"{name}.yml",
        Path.home() / ".config" / "sandbox" / f"{name}.yaml",
    ]
    for p in candidate_paths:
        if p.exists():
            return load_sandboxes_file(p, name)[0]


def load_sandbox(name: str) -> dict:
    if (sb := try_load_sandbox(name)) is None:
        raise Exception(f"sandbox not found: {name}")
    return sb


def get_merge_policy(path: list[str], k: str) -> tuple[str, list[str]]:
    kl = ".".join(path + [k])
    kg = ".".join(path + ["*"])
    for p, s in MERGE_POLICIES.items():
        if kl in s:
            return p, path + [k]
        elif kg in s:
            return p, path + ["*"]
    raise Exception(f"Unknown key while merging: {".".join(path + [k])}")


def merge(a: dict, b: dict, path: list[str]=[]) -> dict:
    res = {}
    for k in set(a.keys()).union(b.keys()):
        policy, key_path = get_merge_policy(path, k)
        match policy:
            case "list":
                res[k] = a.get(k, []) + b.get(k, [])
            case "items":
                left = a.get(k, {})
                right = b.get(k, {})
                # TODO: is this merge correct? e.g. mounts' dict would get merged
                #       into list of (k, v) tuples. think 'items' policy needs to
                #       be removed, and (mounts, chmod) should be merged by 'literal'
                res[k] = (list(left.items()) if isinstance(left, dict) else left) + \
                    (list(right.items()) if isinstance(right, dict) else right)
            case "dict":
                res[k] = merge(a.get(k, {}), b.get(k, {}), key_path)
            case "literal":
                res[k] = b.get(k, a.get(k))
            case "discard":
                pass
            case _:
                raise NotImplementedError
    return res


def merge_sandboxes(sandboxes: Iterable[dict]) -> dict:
    def load_include(inc_in: str|dict) -> dict:
        inc: dict = {"name": inc_in} if isinstance(inc_in, str) else inc_in
        if name := inc.get("name"):
            if inc.get("try"):
                if sb := try_load_sandbox(name):
                    return sb
                return {}
            return load_sandbox(name)
        elif path := inc.get("path"):
            if inc.get("try") and not os.path.exists(path):
                return {}
            return load_sandboxes_file(path)[0]

        # TODO: should we not raise a proper error here?
        assert False

    res = {}
    for sb in sandboxes:
        inc = merge_sandboxes(load_include(child_sb) for child_sb in sb.get("include", ()))
        res = merge(res, merge(inc, sb))
    return res


# note passed sb is the final/merged/resolved sandbox config
#
# returns enriched sandbox with env/vars/mounts/chmod data
def get_sandbox(sb: dict) -> dict:
    # Parse vars & env
    raw_env = {}
    env = {}
    env_unset = set()  # env vars to explicitly unset via --unsetenv

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
            if "inherits" in v:
                if k in os.environ or "defaultValue" not in v:
                    env[k] = os.environ[k]
                else:
                    raw_env[k] = v["defaultValue"]
            elif "value" in v:
                # TODO: should it not go in raw_env dict if v.get("raw") is truthy?
                #       if not, then perhaps "raw" key in v would be better named something like "asis"?
                if v.get("raw"):
                    env[k] = v["value"]
                else:
                    raw_env[k] = v["value"]
            else:
                raise Exception(f"Invalid value for environment variable {k}: {repr(v)}")
        else:
            raise Exception(f"Invalid value for environment variable {k}: {repr(v)}")

    # note format_vars is used to expand our raw_vars & raw_env via python's
    # string.format() method, passing **format_vars as possible values to
    # be expanded into the raw values
    raw_vars = {**sb.get("vars", {})}
    vars = {**DEFAULT_VARS}
    format_vars = {**vars, "env": {**os.environ, **env}}
    while True:
        changed = False
        for parsed, raw in ((vars, raw_vars), (env, raw_env)):
            for k in list(raw.keys()):
                try:
                    parsed[k] = raw[k].format(**format_vars)
                    del raw[k]
                    changed = True
                except KeyError:
                    pass
        # redefine format_vars, as both vars & env were potentially modified:
        format_vars = {**vars, "env": {**os.environ, **env}}
        if not (raw_env or raw_vars):
            break  # all raw values were processed/expanded
        if not changed:
            # TODO: should we not raise a proper error here?
            assert False  # circular definition

    # Parse mounts & chmod
    mounts: dict[str, Any] = {os.path.expanduser(k.format(**format_vars).rstrip("/")): v for k, v in sb.get("mounts", {}) if v}
    chmod: dict[str, Any] = {os.path.expanduser(k.format(**format_vars).rstrip("/")): v for k, v in sb.get("chmod", {}) if v}

    return {**sb, "vars": vars, "env": env, "envUnset": env_unset, "mounts": mounts, "chmod": chmod}


# returns read end of the pipe
def pipefd(data: bytes) -> int:
    pr, pw  = os.pipe2(0)
    if os.fork() == 0:
        os.close(pr)
        os.write(pw, data)
        sys.exit(0)  # immediately exit the child process
    else:
        os.close(pw)
        return pr


# resolve bwrap flags from given sandbox config
def get_bwrap_args(sb: dict) -> list[str]:
    # convert the camel-cased options to kebab-case used by bwrap
    def bwrap_name(name: str) -> str:
        # special case, we don't want to get 'argv-0', 'userns-2':
        if name in ("argv0", "userns2"):
            return name
        return re.sub(r"(?<=[a-z])([A-Z0-9+])", lambda m: "-" + m.group(1).lower(), name)

    # TODO: the input 'value' type can never be list, only dict or int, no?
    def format_seccomp_value(value: dict|list|int) -> str:
        if isinstance(value, dict):  # {data: string, arch: string}
            value = [value]

        if isinstance(value, list):  # {data: string, arch: string}[]
            data: list[bytes] = [base64.b64decode(prog["data"]) for prog in value if prog["arch"] == platform.machine()]
            if len(data) == 0:
                raise Exception(f"seccomp program not found for our architecture: {platform.machine()}")
            return str(pipefd(data[0]))
        else:  # fd
            return str(value)

    # TODO: what are the possible 'value' types? is it dict|list|int|str?
    def format_option_value(opt_name: str, value) -> str:
        if opt_name in ("seccomp", "addSeccomp"):
            return format_seccomp_value(value)
        elif opt_name in ("userns", "userns2", "pidns", "syncFd", "blockFd", "userNsBlockFd", "infoFd", "jsonStatusFd"):
            return str(value)
        else:
            return str(value).format(**format_vars)

    def format_datasource_value(value) -> str:  # {fd: number} | {content: string, raw?: boolean, base64?: boolean}
        if (fd := value.get("fd")) is not None:
            return str(fd)
        elif (content := value.get("content")) is not None:
            if not value.get("raw"):
                content = content.format(**format_vars)

            if value.get("base64"):
                content = base64.b64decode(content)
            else:
                content = content.encode("utf-8")
            return str(pipefd(content))
        raise NotImplementedError

    format_vars = {**sb["vars"], "env": {**os.environ, **sb["env"]}}
    args: list[str] = [f"--{bwrap_name(f)}" for f in BWRAP_FLAGS if sb.get(f)]
    for o in BWRAP_OPTIONS:
        if (v := sb.get(o)) not in (False, None):
            args.extend((f"--{bwrap_name(o)}", format_option_value(o, v)))
    for o in BWRAP_LIST_OPTIONS:
        for v in sb.get(o, ()):
            if v not in (False, None):
                args.extend((f"--{bwrap_name(o)}", format_option_value(o, v)))
    args.extend(arg.format(**format_vars) for arg in sb.get("extraArgs", ()))
    for e in sb["envUnset"]:
        args.extend(("--unsetenv", e))
    for k, v in sb["env"].items():
        args.extend(("--setenv", k, v))
    # dest_path being in sandbox
    for dest_path, mount in sorted(sb["mounts"].items()):
        if mount in ("proc", "dev", "tmpfs", "mqueue", "dir"):
            args.extend((f"--{mount}", dest_path.format(**format_vars)))
        elif isinstance(mount, dict):
            if (tmpfs := mount.get("tmpfs")) is not None:  # { tmpfs: { perms?: number; size?: number }}
                if (perms := tmpfs.get("perms")) is not None:
                    args.extend(("--perms", str(perms)))
                if (size := tmpfs.get("size")) is not None:
                    args.extend(("--size", str(size)))
                args.extend(("--tmpfs", dest_path))
            elif (dir := mount.get("dir")) is not None:  # { dir: { perms?: number }}
                if (perms := dir.get("perms")) is not None:
                    args.extend(("--perms", str(perms)))
                args.extend(("--dir", dest_path))
            elif (symlink := mount.get("symlink")) is not None:  # { symlink: string }
                args.extend(("--symlink", symlink.format(**format_vars), dest_path))
            elif (bind := mount.get("bind")) is not None:  # { bind: { path: string; readOnly?: boolean; dev?: boolean; try?: boolean, create?: boolean }}
                prefix = "dev-" if bind.get("dev") else "ro-" if bind.get("ro") else ""
                suffix = "-try" if bind.get("try") else ""
                src_path = os.path.expanduser(bind.get("path", dest_path).format(**format_vars))
                if bind.get("create"):
                    os.makedirs(src_path, exist_ok=True)
                args.extend((f"--{prefix}bind{suffix}", src_path, dest_path))
            elif (fd := mount.get("fd")) is not None:  # { fd: { fd: number; readOnly?: boolean }}
                args.extend(("--ro-bind-fd" if fd.get("readOnly") else "--bind-fd", str(fd["fd"])))
            elif (file := mount.get("file")) is not None:  # { file: DataSource & { perms?: number }}
                if (perms := file.get("perms")) is not None:
                    args.extend(("--perms", str(perms)))
                args.extend(("--file", format_datasource_value(file), dest_path))
            elif (data := mount.get("data")) is not None:  # { data: DataSource & { readOnly?: boolean; perms?: number }}
                if (perms := data.get("perms")) is not None:
                    args.extend(("--perms", str(perms)))
                args.extend(("--ro-bind-data" if data.get("readOnly") else "--bind-data", format_datasource_value(data), dest_path))
            elif (overlay := mount.get("overlay")) is not None:  # { overlay: { lower: string[]; upper?: string; work?: string; mode?: "rw" | "tmp" | "ro" }}
                for lower in overlay["lower"]:
                    args.extend(("--overlay-src", lower.format(**format_vars)))
                mode = overlay.get("mode", "rw" if "upper" in overlay and "work" in overlay else "tmp")
                if mode == "rw":
                    args.extend(("--overlay", overlay["upper"], overlay["work"], dest_path))  # i.e. --overlay RWSRC WORKDIR DEST
                else:
                    args.extend((f"--{mode}-overlay", dest_path))
            else:
                raise Exception(f"invalid mount value: {repr(mount)}")
        else:
            raise Exception(f"invalid mount (of type {type(mount)}) value: {repr(mount)}")
    # TODO: isn't chmod a map? sorted(sb["chmod"]) would return _list_ of sorted keys.
    #       think we need to sort on sb[chmod].items(), i.e. same as is done with mounts above
    for path, mode in sorted(sb["chmod"]):
        args.extend(("--chmod", path.format(**format_vars), str(mode)))
    return args


# resolve options to be passed to `xdg-dbus-proxy`
# 'bus' arg is system|user
def get_dbus_proxy_args(sb: dict, bus: str) -> list[str]:
    args: list[str] = []
    if not (b := sb.get("dbus")):
        return args

    # TODO: how are sloppyNames supposed to be defined? atm it looks like it's a dict
    #       sb.dbus.sloppyNames, but... why a dict? wouldn't it make more sense
    #       to define it as a bool under dbus.<bus>.sloppyNames?
    if b.get("sloppyNames", {}).get(bus):
        args.append("--sloppy-names")
    for name, policy in b.get(bus, {}).items():
        args.append(f"--{policy}={name}")
    for rule_type in ("broadcast", "call"):
        # TODO: this iteration smells: [for name, rules] while iterating over list of keys:
        #       shouldn't it be .items() instead?
        # TODO2: wouldn't it make more sense to move 'rules' key under dbus.<bus>,
        #        not the other way around as it is currently?
        for name, rules in b.get("rules", {}).get(bus, {}).get(rule_type, {}).keys():
            args.extend(f"--broadcast={name}={rule}" for rule in rules)
    return args


# if required so by the sb's config, start a xdg-dbus-proxy subprocess and
# return additional bwrap parameters to pass to the main sandbox command
def setup_dbus_proxy(sb: dict) -> list[str]:
    proxy_dir: str = f"{os.environ["XDG_RUNTIME_DIR"]}/xdg-dbus-proxy/bwrap-{os.getpid()}"
    proxy_bwrap_args: list[str] = ["--bind", proxy_dir, proxy_dir]
    buses: Sequence[tuple[str,str,str|None]] = (
        ("system", "unix:path=/run/dbus/system_bus_socket", None),
        ("user", os.environ["DBUS_SESSION_BUS_ADDRESS"], "DBUS_SESSION_BUS_ADDRESS"),
    )

    cmd_bwrap_args = []
    dbus_proxy_args = []
    for bus, address, addr_env in buses:
        if bus_args := get_dbus_proxy_args(sb, bus):
            dbus_proxy_args.extend((address, f"{proxy_dir}/{bus}", "--filter"))
            dbus_proxy_args.extend(bus_args)

            addr_path = address.removeprefix("unix:path=")
            proxy_bwrap_args.extend(("--bind", addr_path, addr_path))
            cmd_bwrap_args.extend(("--bind", f"{proxy_dir}/{bus}", addr_path))
            if addr_env:
                cmd_bwrap_args.extend(("--setenv", addr_env, address))

    if not dbus_proxy_args:
        return []

    os.makedirs(proxy_dir, exist_ok=True)
    pr, pw = os.pipe2(0)
    dbus_proxy_args = ["xdg-dbus-proxy", f"--fd={pw}"] + dbus_proxy_args
    LOGGER.debug("proxy args for dbus proxy: %r", shlex.join(dbus_proxy_args))

    # if 'dbus.sandbox' defined, then it means xdg-dbus-proxy itself is to be ran in bwrap as well:
    if proxy_sb := sb.get("dbus", {}).get("sandbox"):
        proxy_sb = get_sandbox(merge_sandboxes((proxy_sb,)))  # note we call merge_sandboxes() to get the [include] resolution/expansion
        debug_object("dbus proxy sandbox", proxy_sb)
        # TODO: proxy_bwrap_args is not really used? I'm guessing it's to be used
        #       2 lines down in 'dbus_proxy_args' definition _instead_ of the global BWRAP_ARGS?
        proxy_bwrap_args = get_bwrap_args(proxy_sb) + proxy_bwrap_args
        dbus_proxy_args = ["bwrap", "--args", str(pipefd("\0".join(BWRAP_ARGS).encode("utf-8")))] + dbus_proxy_args
        LOGGER.debug("bwrap args for xdg-dbus-proxy for bus: %s", shlex.join(proxy_bwrap_args))

    if os.fork() == 0:
        os.close(pr)
        os.execlp(dbus_proxy_args[0], *dbus_proxy_args)
    else:
        os.close(pw)
        assert os.read(pr, 1) == b"x"
        return ["--sync-fd", str(pr)] + cmd_bwrap_args


def debug_object(label: str, obj: Any):
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug(f"{label}:\n{pprint.pformat(obj)}")


# ENTRY
#################################
CONFIGS_SOURCES: list[tuple[str,str]] = []  # contains (passed-option, value) tuples, e.g. ('name', 'value-for-name'), ('json', '{some-json: data}')
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
args: argparse.Namespace = parser.parse_args()

if args.log_level:
    logging.basicConfig(stream=sys.stdout, level=getattr(logging, args.log_level.upper()), force=True)

for global_path in (Path.home() / ".config" / "sandbox.yaml", Path.home() / ".config" / "sandbox.yml"):
    if global_path.exists():
        GLOBAL_SANDBOXES = load_sandboxes_file(global_path)

CONFIGS: list[dict] = []  # active sandbox configs to use
for source_type, source_data in CONFIGS_SOURCES:
    match source_type:
        case "name":
            for name in source_data.split(","):
                CONFIGS.append(load_sandbox(name.strip()))
        case "json":
            CONFIGS.append(json.loads(source_data))
        case "file":
            CONFIGS.extend(load_sandboxes_file(source_data))
        case "set":
            k, v = source_data.split("=", 1)
            k = re.sub(r"^\$", "env.", re.sub("^:", "vars.", k))
            v = json.loads(v) if v and (v[0] in '"[{'or v in ("true", "false", "null")) else v
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

EXECUTABLE_NAME: str = os.path.basename(args.executable or os.environ.get("SHELL", "sh"))

if args.autoload:
    sb: dict|None = try_load_sandbox(EXECUTABLE_NAME)
    if sb and sb not in CONFIGS:
        CONFIGS.append(sb)

if not args.no_match:
    for sb in GLOBAL_SANDBOXES:
        if EXECUTABLE_NAME in sb.get("matches", ()) and sb not in CONFIGS:
            CONFIGS.append(sb)

if not CONFIGS and not args.no_default:
    CONFIGS.append(load_sandbox(args.default_sandbox))

debug_object("configs", CONFIGS)

DEFAULT_VARS: dict[str, str|int] = {
    "pid": os.getpid(),
    "cwd": os.getcwd(),
    "executable": args.executable,
    "name": EXECUTABLE_NAME,
}

SB = get_sandbox(merge_sandboxes(CONFIGS))
debug_object("sandbox", SB)

if SB.get("disableSandbox"):
    os.execlp(args.executable, args.executable, *args.args)

DBUS_PROXY_ARGS: list[str] = setup_dbus_proxy(SB)

BWRAP_ARGS: list[str] = get_bwrap_args(SB)
BWRAP_ARGS.extend(DBUS_PROXY_ARGS)

LOGGER.debug("bwrap command: %s", shlex.join(["bwrap"] + BWRAP_ARGS + [args.executable or EXECUTABLE_NAME] + args.args))
os.execlp("bwrap", "bwrap", "--args", str(pipefd("\0".join(BWRAP_ARGS).encode("utf-8"))),
          args.executable or EXECUTABLE_NAME, *args.args)

