"""Stand-in for bwrap / xdg-dbus-proxy / nsenter / sandboxed executables.

Invoked as `recorder.py <name> <args...>` by the wrappers that conftest.py
puts first on PATH. Instead of doing anything, it appends a JSON record of
how it was called to $BB_TEST_RECORDS/<name>.json.
"""
import base64
import json
import os
import sys
from pathlib import Path

# bwrap options whose following arg is an FD that bb filled via pipefd()
DATA_FD_OPTS = {"--seccomp", "--file", "--bind-data", "--ro-bind-data"}


def record(name: str, payload: dict) -> None:
    path = Path(os.environ["BB_TEST_RECORDS"]) / f"{name}.json"
    calls = json.loads(path.read_text()) if path.exists() else []
    calls.append({**payload, "pid": os.getpid(), "sigign": os.environ.get("BB_SIGIGN", "")})
    path.write_text(json.dumps(calls, indent=2))


def read_fd(fd: int) -> bytes | None:
    try:
        chunks = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        os.close(fd)
        return b"".join(chunks)
    except OSError:  # fd not open: a user-supplied fd number rather than one bb piped
        return None


def fake_bwrap(argv: list[str]) -> None:
    assert argv[:1] == ["--args"] and argv[2:3] == ["--"], argv
    args = read_fd(int(argv[1])).decode().split("\0")
    cmd = argv[3:]

    fd_data: dict[str, str | None] = {}
    info_fd_target = None
    for i, arg in enumerate(args[:-1]):
        nxt = args[i + 1]
        if arg in DATA_FD_OPTS and nxt.isdigit():
            data = read_fd(int(nxt))
            fd_data[nxt] = None if data is None else base64.b64encode(data).decode()
        elif arg == "--info-fd":
            info_fd_target = os.readlink(f"/proc/self/fd/{nxt}")

    proxied = bool(cmd) and os.path.basename(cmd[0]) == "xdg-dbus-proxy"
    record("bwrap-proxy" if proxied else "bwrap",
           {"args": args, "cmd": cmd, "fd_data": fd_data, "info_fd_target": info_fd_target})
    if proxied:  # bwrap wrapping xdg-dbus-proxy: keep the chain going so bb gets its sync byte
        os.execvp(cmd[0], cmd)


def fake_dbus_proxy(argv: list[str]) -> None:
    record("xdg-dbus-proxy", {"argv": argv})
    fd = next(int(a.removeprefix("--fd=")) for a in argv if a.startswith("--fd="))
    os.write(fd, b"x")


def main() -> None:
    name, argv = sys.argv[1], sys.argv[2:]
    if name == "bwrap":
        fake_bwrap(argv)
    elif name == "xdg-dbus-proxy":
        fake_dbus_proxy(argv)
    else:
        record(name, {"argv": argv, "cwd": os.getcwd()})


if __name__ == "__main__":
    main()
