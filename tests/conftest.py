"""Test harness for the `bb` script.

`bb` does all its work at module level and ends by exec()ing bwrap, so it is
tested as a black box: each test runs it as a subprocess against an isolated
HOME/XDG tree, with fake bwrap/xdg-dbus-proxy/nsenter executables first on
PATH (see fakes/recorder.py). Tests then assert on the recorded invocations.
"""
from __future__ import annotations

import base64
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

TESTS = Path(__file__).resolve().parent
BB = TESTS.parent / "bb"
RECORDER = TESTS / "fakes" / "recorder.py"
FIXTURES = TESTS / "fixtures"

TARGET = "sbx-target"  # fake executable to "sandbox"
UNSANDBOXED = "sbx-unsandboxed"  # fake executable matched by disableSandbox profiles
FAKE_EXECUTABLES = ("bwrap", "xdg-dbus-proxy", "nsenter", TARGET, UNSANDBOXED)

SIGPIPE_SIGXFSZ = (1 << (signal.SIGPIPE - 1)) | (1 << (signal.SIGXFSZ - 1))

# the shell captures ignored signals before python starts, as python itself ignores SIGPIPE
WRAPPER = """#!/bin/sh
BB_SIGIGN=$(grep '^SigIgn:' /proc/$$/status | cut -f2)
export BB_SIGIGN
exec {python} {recorder} {name} "$@"
"""


class BwrapCall:
    def __init__(self, rec: dict):
        self.args: list[str] = rec["args"]
        self.cmd: list[str] = rec["cmd"]
        self.pid: int = rec["pid"]
        self.sigign: int = int(rec["sigign"], 16)
        self.info_fd_target: str | None = rec["info_fd_target"]
        self._fd_data: dict[str, str | None] = rec["fd_data"]

    def find(self, *seq: str) -> int:
        n = len(seq)
        for i in range(len(self.args) - n + 1):
            if tuple(self.args[i:i + n]) == seq:
                return i
        return -1

    def has(self, *seq: str) -> bool:
        return self.find(*seq) != -1

    def values(self, opt: str) -> list[str]:
        return [self.args[i + 1] for i, a in enumerate(self.args[:-1]) if a == opt]

    @property
    def setenv(self) -> dict[str, str]:
        res, i = {}, 0
        while i < len(self.args):
            if self.args[i] == "--setenv":
                res[self.args[i + 1]] = self.args[i + 2]
                i += 3
            else:
                i += 1
        return res

    @property
    def unsetenv(self) -> set[str]:
        return set(self.values("--unsetenv"))

    def fd_content(self, fd: str) -> bytes | None:
        data = self._fd_data[fd]
        return None if data is None else base64.b64decode(data)

    def data_for(self, opt: str, dest: str) -> bytes | None:
        """Content piped to bwrap for `opt FD dest` (e.g. --file / --ro-bind-data)."""
        for i, a in enumerate(self.args[:-2]):
            if a == opt and self.args[i + 2] == dest:
                return self.fd_content(self.args[i + 1])
        raise AssertionError(f"no [{opt} FD {dest}] in {self.args}")


class Result:
    def __init__(self, proc: subprocess.CompletedProcess, records: Path):
        self.proc = proc
        self.returncode = proc.returncode
        self.stdout: str = proc.stdout
        self.stderr: str = proc.stderr
        self._records = records

    def calls(self, name: str) -> list[dict]:
        path = self._records / f"{name}.json"
        return json.loads(path.read_text()) if path.exists() else []

    def only(self, name: str) -> dict:
        calls = self.calls(name)
        assert len(calls) == 1, f"expected exactly 1 [{name}] invocation, got {len(calls)}"
        return calls[0]

    @property
    def bwrap(self) -> BwrapCall:
        return BwrapCall(self.only("bwrap"))

    @property
    def proxy_bwrap(self) -> BwrapCall:
        return BwrapCall(self.only("bwrap-proxy"))

    @property
    def instance_id(self) -> str:
        return f"org.bubblebox-{self.bwrap.pid}"  # bb exec()s into bwrap, so pids match


class BBEnv:
    def __init__(self, root: Path):
        self.root = root
        self.home = root / "home"
        self.xdg_config = root / "config"
        self.xdg_data = root / "data"
        self.xdg_state = root / "state"
        self.xdg_cache = root / "cache"
        self.xdg_runtime = root / "run"
        self.sb_config = self.xdg_config / "bubblebox"
        self.cwd = root / "cwd"
        self.records = root / "records"
        self.fakebin = root / "fakebin"
        for d in (self.home, self.sb_config, self.xdg_data, self.xdg_state, self.xdg_cache,
                  self.xdg_runtime, self.cwd, self.records, self.fakebin):
            d.mkdir(parents=True, exist_ok=True)
        self.xdg_runtime.chmod(0o700)

        for name in FAKE_EXECUTABLES:
            exe = self.fakebin / name
            exe.write_text(WRAPPER.format(python=shlex.quote(sys.executable),
                                          recorder=shlex.quote(str(RECORDER)),
                                          name=shlex.quote(name)))
            exe.chmod(0o755)

        self.env: dict[str, str] = {
            "PATH": f"{self.fakebin}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.xdg_config),
            "XDG_DATA_HOME": str(self.xdg_data),
            "XDG_STATE_HOME": str(self.xdg_state),
            "XDG_CACHE_HOME": str(self.xdg_cache),
            "XDG_RUNTIME_DIR": str(self.xdg_runtime),
            "SHELL": "/bin/sh",
            "LANG": "C.UTF-8",
            "BB_TEST_RECORDS": str(self.records),
        }

    def profile(self, id: str, *docs: dict, ext: str = "yml", dir: Path | None = None) -> Path:
        path = (dir or self.sb_config) / f"{id}.{ext}"
        path.write_text(yaml.safe_dump_all(docs or [{}], sort_keys=False))
        return path

    def global_config(self, *docs: dict) -> Path:
        return self.profile("config", *docs, ext="yaml")

    def run(self, *args: str, check: bool = True, env: dict[str, str | None] | None = None,
            cwd: Path | None = None, real: bool = False, timeout: float = 30) -> Result:
        shutil.rmtree(self.records)
        self.records.mkdir()
        e = {**self.env, **(env or {})}
        if real:
            e["PATH"] = os.environ.get("PATH", os.defpath)
        e = {k: v for k, v in e.items() if v is not None}
        proc = subprocess.run([sys.executable, str(BB), *args], env=e, cwd=cwd or self.cwd,
                              capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)
        if check:
            assert proc.returncode == 0, (f"bb exited {proc.returncode}\n"
                                          f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        return Result(proc, self.records)

    def fails(self, *args: str, match: str, **kw) -> Result:
        res = self.run(*args, check=False, **kw)
        assert res.returncode != 0, f"bb unexpectedly succeeded\nstdout:\n{res.stdout}"
        assert match in res.stderr, res.stderr
        return res


@pytest.fixture
def bb(tmp_path: Path) -> BBEnv:
    return BBEnv(tmp_path)


def _real_bwrap_problem() -> str | None:
    if not shutil.which("bwrap"):
        return "bwrap not installed"
    probe = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "true"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        return f"bwrap unusable here: {probe.stderr.strip()}"
    return None


@pytest.fixture(scope="session")
def real_bwrap() -> None:
    if problem := _real_bwrap_problem():
        if os.environ.get("BB_REQUIRE_REAL_BWRAP"):
            pytest.fail(problem)
        pytest.skip(problem)
