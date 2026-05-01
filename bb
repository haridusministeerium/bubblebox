#!/usr/bin/python

import argparse
import base64
import json
import logging
import os
import pathlib
import platform
import pprint
import re
import shlex
import sys

import yaml

sandboxes_cache = {}
global_sandboxes = {}

bwrap_flags = {"levelPrefix", "unshareAll", "shareNet", "unshareUser", "unshareUserTry", "unshareIpc", "unsharePid", "unshareNet", "unshareUts", "unshareCgroup", "unshareCgroupTry", "disableUserns", "assertUsernsDisabled", "clearenv", "newSession", "dieWithParent", "asPid1"}
bwrap_options = {"argv0", "userns", "userns2", "pidns", "uid", "gid", "hostname", "chdir", "execLabel", "fileLabel", "seccomp", "syncFd", "blockFd", "usernsBlockFd", "infoFd", "jsonStatusFd"}
bwrap_list_options = {"addSeccompFd", "capAdd", "capDrop", "lockFile", "remountRo"}

merge_policy = {
  "items": {"mounts", "chmod"},
  "literal": bwrap_flags.union(bwrap_options).union({"disableSandbox", "vars.*", "env.*", "dbus.sloppyNames.*", "dbus.sandbox.*", "dbus.user.*", "dbus.system.*"}),
  "list": bwrap_list_options.union({"extraArgs"}).union({"matches", "dbus.rules.*.*.*"}),
  "dict": {"vars", "env", "dbus", "dbus.sloppyNames", "dbus.sandbox", "dbus.user", "dbus.system", "dbus.rules.*", "dbus.rules.*.*"},
  "discard": {"name", "include"},
}

def tagged_append(tag, dest):
    class TaggedAppend(argparse.Action):
        def __call__(self, parser, ns, values, option_strings=None):
            dest.append((tag, values))
    return TaggedAppend

def load_sandboxes_file(path, default_name=None):
    logging.debug("loading %s", path)
    with open(path) as fd:
        sandboxes = list(yaml.safe_load_all(fd))
        sandboxes = [sandboxes] if isinstance(sandboxes, dict) else sandboxes
        for i, sb in enumerate(sandboxes):
            if name := sb.get("name", default_name if i == 0 else None):
                sandboxes_cache[name] = sb
        return sandboxes

def try_load_sandbox(name):
    if name in sandboxes_cache:
        return sandboxes_cache[name]
    if name in global_sandboxes:
        return global_sandboxes[name]
    candidate_paths = [
        pathlib.Path(name),
        pathlib.Path(f"{name}.yml"),
        pathlib.Path(f"{name}.yaml"),
        pathlib.Path.home() / ".config" / "sandbox" / f"{name}.yml",
        pathlib.Path.home() / ".config" / "sandbox" / f"{name}.yaml",
    ]
    for p in candidate_paths:
        if p.exists():
            return load_sandboxes_file(p, name)[0]

def load_sandbox(name):
    sb = try_load_sandbox(name)
    if sb is None:
        raise Exception(f"sandbox not found: {name}")
    return sb

def get_merge_policy(path, k):
    kl = ".".join(path + [k])
    kg = ".".join(path + ["*"])
    for p, s in merge_policy.items():
        if kl in s:
            return p, path + [k]
        if kg in s:
            return p, path + ["*"]
    raise Exception(f"Unknown key while merging: {".".join(path + [k])}")

def merge(a, b, path=[]):
    res = {}
    for k in set(a.keys()).union(b.keys()):
        policy, key_path = get_merge_policy(path, k)
        if policy == "list":
            res[k] = a.get(k, []) + b.get(k, [])
        elif policy == "items":
            left = a.get(k, {})
            right = b.get(k, {})
            res[k] = (list(left.items()) if isinstance(left, dict) else left) + \
                (list(right.items()) if isinstance(right, dict) else right)
        elif policy == "dict":
            res[k] = merge(a.get(k, {}), b.get(k, {}), key_path)
        elif policy == "literal":
            res[k] = b.get(k, a.get(k, None))
    return res

def merge_sandboxes(sandboxes):
    def load_include(inc):
        inc = {"name": inc} if isinstance(inc, str) else inc
        if name := inc.get("name"):
            if inc.get("try"):
                return try_load_sandbox(name)
            else:
                return load_sandbox(name)
        elif path := inc.get("path"):
            if inc.get("try") and not os.path.exists(path):
                return {}
            else:
                return load_sandboxes_file(path)[0]
        else:
            assert False

    res = {}
    for sb in sandboxes:
        inc = merge_sandboxes(load_include(child_sb) for child_sb in sb.get("include", []))
        res = merge(res, merge(inc, sb))
    return res

def get_sandbox(sb, default_vars):
    # Parse vars & env
    raw_vars = {**sb.get("vars", {})}
    raw_env = {}

    vars = {**default_vars}
    env = {}
    env_unset = set()

    for k, v in sb.get("env", {}).items():
        if v is True: # inherit
            if k in os.environ:
                env[k] = os.environ[k]
        elif v is False: # clear
            env_unset.add(k)
        elif v is None: # nothing
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
                if v.get("raw", False):
                    env[k] = v["value"]
                else:
                    raw_env[k] = v["value"]
            else:
                raise Exception(f"Invalid value for environment variable {k}: {repr(v)}")
        else:
            raise Exception(f"Invalid value for environment variable {k}: {repr(v)}")

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
        format_vars = {**vars, "env": {**os.environ, **env}}
        if not raw_env and not raw_vars:
            break
        if not changed:
            assert False # circular definition

    # Parse mounts & chmod
    mounts = {os.path.expanduser(k.format(**format_vars).rstrip("/")): v for k, v in sb.get("mounts", []) if v}
    chmod = {os.path.expanduser(k.format(**format_vars).rstrip("/")): v for k, v in sb.get("chmod", []) if v}

    return {**sb, "vars": vars, "env": env, "envUnset": env_unset, "mounts": mounts, "chmod": chmod}

def pipefd(data):
    pr, pw  = os.pipe2(0)
    if os.fork() == 0:
        os.close(pr)
        os.write(pw, data)
        sys.exit(0)
    else:
        os.close(pw)
        return pr

def get_bwrap_args(sb):
    def bwrap_name(name):
        if name == "argv0":
            return name
        return re.sub(r"(?<=[a-z])([A-Z0-9+])", lambda m: "-" + m.group(1).lower(), name)

    def format_seccomp_value(value):
        if isinstance(value, dict): # {data: string, arch: string}
            value = [value]
        if isinstance(value, list): # {data: string, arch: string}[]
            data = [base64.b64decode(prog["data"]) for prog in value if prog["arch"] == platform.machine()]
            if len(data) == 0:
                raise Exception(f"seccomp program not found for that architecture: {platform.machine()}")
            return str(pipefd(data[0]))
        else: # fd
            return str(value)

    def format_option_value(name, value):
        if name in ("seccomp", "addSeccomp"):
            return format_seccomp_value(value)
        elif name in ("userns", "userns2", "pidns","syncFd", "blockFd", "userNsBlockFd", "infoFd", "jsonStatusFd"):
            return str(value)
        else:
            return str(value).format(**format_vars)

    def format_datasource_value(value): # {fd: number} | {content: string, raw?: boolean, base64?: boolean}
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
        else:
            raise NotImplementedError

    format_vars = {**sb["vars"], "env": {**os.environ, **sb["env"]}}
    args = [f"--{bwrap_name(f)}" for f in bwrap_flags if sb.get(f)]
    for o in bwrap_options:
        if sb.get(o) not in (False, None):
            args.extend((f"--{bwrap_name(o)}", format_option_value(o, sb[o])))
    for o in bwrap_list_options:
        for v in sb.get(o, []):
            if v not in (False, None):
                args.extend((f"--{bwrap_name(o)}", format_option_value(o, v)))
    args.extend(arg.format(**format_vars) for arg in sb.get("extraArgs", []))
    for e in sb["envUnset"]:
        args.extend(("--unsetenv", e))
    for k, v in sb["env"].items():
        args.extend(("--setenv", k, v))
    for dest_path, mount in sorted(sb["mounts"].items()):
        if mount in ("proc", "dev", "tmpfs", "mqueue", "dir"):
            args.extend((f"--{mount}", dest_path.format(**format_vars)))
        elif isinstance(mount, dict):
            if (tmpfs := mount.get("tmpfs")) is not None: # { tmpfs: { perms?: number; size?: number }}
                if (perms := tmpfs.get("perms")) is not None:
                    args.extend(("--perms", str(perms)))
                if (size := tmpfs.get("size")) is not None:
                    args.extend(("--size", str(size)))
                args.extend(("--tmpfs", dest_path))
            elif (dir := mount.get("dir")) is not None: # { dir: { perms?: number }}
                if (perms := dir.get("perms")) is not None:
                    args.extend(("--perms", str(perms)))
                args.extend(("--dir", dest_path))
            elif (symlink := mount.get("symlink")) is not None: # { symlink: string }
                args.extend(("--symlink", symlink.format(**format_vars), dest_path))
            elif (bind := mount.get("bind")) is not None: # { bind: { path: string; readOnly?: boolean; dev?: boolean; try?: boolean, create?: boolean }}
                prefix = "dev-" if bind.get("dev") else "ro-" if bind.get("ro") else ""
                suffix = "-try" if bind.get("try") else ""
                src_path = os.path.expanduser(bind.get("path", dest_path).format(**format_vars))
                if bind.get("create"):
                    os.makedirs(src_path, exist_ok=True)
                args.extend(("--" + prefix + "bind" + suffix, src_path, dest_path))
            elif (fd := mount.get("fd")) is not None: # { fd: { fd: number; readOnly?: boolean }}
                args.extend(("--ro-bind-fd" if fd.get("readOnly") else "--bind-fd", str(fd["fd"])))
            elif (file := mount.get("file")) is not None: # { file: DataSource & { perms?: number }}
                if (perms := file.get("perms")) is not None:
                    args.extend(("--perms", str(perms)))
                args.extend(("--file", format_datasource_value(file), dest_path))
            elif (data := mount.get("data")) is not None: # { data: DataSource & { readOnly?: boolean; perms?: number }}
                if (perms := data.get("perms")) is not None:
                    args.extend(("--perms", str(perms)))
                args.extend(("--ro-bind-data" if data.get("readOnly") else "--bind-data", format_datasource_value(data), dest_path))
            elif (overlay := mount.get("overlay")) is not None: # { overlay: { lower: string[]; upper?: string; work?: string; mode?: "rw" | "tmp" | "ro" }}
                for lower in overlay["lower"]:
                    args.extend(("--overlay-src", lower.format(**format_vars)))
                mode = overlay.get("mode", "rw" if "upper" in overlay and "work" in overlay else "tmp")
                if mode == "rw":
                    args.extend(("--overlay", overlay["upper"], overlay["work"], dest_path))
                else:
                    args.extend((f"--{mode}-overlay", dest_path))
            else:
                raise Exception(f"invalid mount value: {repr(mount)}")
        else:
            raise Exception(f"invalid mount value: {repr(mount)}")
    for path, mode in sorted(sb["chmod"]):
        args.extend(("--chmod", path.format(**format_vars), str(mode)))
    return args

def get_dbus_proxy_args(sb, bus):
    args = []
    if sb.get("dbus", {}).get("sloppyNames", {}).get(bus, False):
        args.append("--sloppy-names")
    for name, policy in sb.get("dbus", {}).get(bus, {}).items():
        args.append(f"--{policy}={name}")
    for rule_type in ("broadcast", "call"):
        for name, rules in sb.get("dbus", {}).get("rules", {}).get(bus, {}).get(rule_type, {}).keys():
            args.extend(f"--broadcast={name}={rule}" for rule in rules)
    return args

def setup_dbus_proxy(sb, vars, proxy_dir, buses):
    args = []
    proxy_bwrap_args = ["--bind", proxy_dir, proxy_dir]
    cmd_bwrap_args = []

    for bus, address, addr_env in buses:
        if bus_args := get_dbus_proxy_args(sb, bus):
            args.extend((address, f"{proxy_dir}/{bus}", "--filter"))
            args.extend(bus_args)

            addr_path = address.removeprefix("unix:path=")
            proxy_bwrap_args.extend(("--bind", addr_path, addr_path))
            cmd_bwrap_args.extend(("--bind", f"{proxy_dir}/{bus}", addr_path))
            if addr_env:
                cmd_bwrap_args.extend(("--setenv", addr_env, address))

    if not args:
        return []

    pr, pw = os.pipe2(0)
    os.makedirs(proxy_dir, exist_ok=True)
    args = ["xdg-dbus-proxy", f"--fd={pw}"] + args
    logging.debug("proxy args for dbus proxy: %r", shlex.join(args))
    if proxy_sb := sb.get("dbus", {}).get("sandbox"):
        proxy_sb = get_sandbox(merge_sandboxes([proxy_sb]), vars)
        debug_object("dbus proxy sandbox", proxy_sb)
        proxy_bwrap_args = get_bwrap_args(proxy_sb) + proxy_bwrap_args
        args = ["bwrap", "--args", str(pipefd("\0".join(bwrap_args).encode("utf-8")))] + args
        logging.debug("bwrap args for xdg-dbus-proxy for bus: %s", shlex.join(proxy_bwrap_args))

    if os.fork() == 0:
        os.close(pr)
        os.execlp(args[0], *args)
    else:
        os.close(pw)
        assert os.read(pr, 1) == b"x"
        return ["--sync-fd", str(pr)] + cmd_bwrap_args

def debug_object(label, obj):
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.debug("%s:\n%s", label, pprint.pformat(obj))

configs_sources = []
parser = argparse.ArgumentParser()
parser.add_argument("-l", "--log-level", choices=[lvl.lower() for lvl in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")])
parser.add_argument("-n", "--name", action=tagged_append("name", configs_sources))
parser.add_argument("-j", "--json", action=tagged_append("json", configs_sources))
parser.add_argument("-f", "--file", action=tagged_append("file", configs_sources))
parser.add_argument("-s", "--set", action=tagged_append("set", configs_sources))
parser.add_argument("-a", "--autoload", action="store_true")
parser.add_argument("-M", "--no-match", action="store_true")
parser.add_argument("-D", "--no-default", action="store_true")
parser.add_argument("--default-sandbox", action="store", default="default")
parser.add_argument("executable", nargs="?")
parser.add_argument("args", nargs=argparse.REMAINDER)
args = parser.parse_args()

executable_name = os.path.basename(args.executable or os.environ.get("SHELL", "sh"))

if args.log_level:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))

for global_path in (pathlib.Path.home() / ".config" / "sandbox.yaml", pathlib.Path.home() / ".config" / "sandbox.yml"):
    if global_path.exists():
        global_sandboxes = load_sandboxes_file(global_path)

configs = []
for source_type, source_data in configs_sources:
    if source_type == "name":
        for name in source_data.split(","):
            configs.append(load_sandbox(name.strip()))
    elif source_type == "json":
        configs.append(json.loads(source_data))
    elif source_type == "file":
        configs.extend(load_sandboxes_file(source_data))
    elif source_type == "set":
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
        configs.append(obj)
    else:
        raise NotImplementedError

if args.autoload:
    sb = try_load_sandbox(executable_name)
    if sb and sb not in configs:
        configs.append(sb)

if not args.no_match:
    for sb in global_sandboxes:
        if executable_name in sb.get("matches", []) and sb not in configs:
            configs.append(sb)

if not configs and not args.no_default:
    configs = [load_sandbox(args.default_sandbox)]

debug_object("configs", configs)

default_vars = {
    "pid": os.getpid(),
    "cwd": os.getcwd(),
    "executable": args.executable,
    "name": executable_name,
}

sb = get_sandbox(merge_sandboxes(configs), default_vars)
debug_object("sandbox", sb)

if sb.get("disableSandbox"):
    os.execlp(args.executable, args.executable, *args.args)

dbus_proxy_dir = f"{os.environ["XDG_RUNTIME_DIR"]}/xdg-dbus-proxy/bwrap-{os.getpid()}"
dbus_proxy_args = setup_dbus_proxy(sb, default_vars, dbus_proxy_dir, (
    ("system", "unix:path=/run/dbus/system_bus_socket", None),
    ("user", os.environ["DBUS_SESSION_BUS_ADDRESS"], "DBUS_SESSION_BUS_ADDRESS"),
))

bwrap_args = get_bwrap_args(sb)
bwrap_args.extend(dbus_proxy_args)

logging.debug("bwrap command: %s", shlex.join(["bwrap"] + bwrap_args + [args.executable] + args.args))
os.execlp("bwrap", "bwrap", "--args", str(pipefd("\0".join(bwrap_args).encode("utf-8"))), args.executable or executable_name, *args.args)

