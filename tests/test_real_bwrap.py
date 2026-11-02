"""Smoke tests against the real bwrap binary (skipped when it can't run here;
set BB_REQUIRE_REAL_BWRAP=1 to turn that skip into a failure, as CI does)."""
import json
import os
import subprocess
import sys
import time

import pytest

from conftest import BB

pytestmark = pytest.mark.usefixtures("real_bwrap")

MINIMAL = {
    "id": "minimal",
    "clearenv": True,
    "dieWithParent": True,
    "unsharePid": True,
    "mounts": {
        "/usr": "ro-bind",
        "/etc": "ro-bind",
        "/bin": {"symlink": "usr/bin"},
        "/lib": {"symlink": "usr/lib"},
        "/lib64": {"symlink": "usr/lib64"},
        "/proc": "proc",
        "/dev": "dev",
        "/tmp": "tmpfs",
        "/hello.txt": {"file": {"content": "hello from {exe_name}"}},
    },
    "env": {"FOO": "bar-{uid}", "PATH": "/usr/bin:/bin", "HOME": True},
}


@pytest.fixture
def minimal(bb):
    bb.profile("minimal", MINIMAL)
    return bb


def test_runs_command_in_sandbox(minimal):
    script = 'echo "$FOO"; cat /hello.txt; echo; [ -e "$HOME" ] && echo home-visible || echo home-hidden'
    res = minimal.run("-i", "minimal", "sh", "-c", script, real=True)
    assert res.stdout.splitlines() == [f"bar-{os.getuid()}", "hello from sh", "home-hidden"]


def test_signal_dispositions_reset_inside_sandbox(minimal):
    res = minimal.run("-i", "minimal", "sh", "-c", "grep '^SigIgn:' /proc/$$/status", real=True)
    ignored = int(res.stdout.split()[1], 16)
    assert ignored & ((1 << 12) | (1 << 24)) == 0  # SIGPIPE (13), SIGXFSZ (25)


def test_exit_status_propagates(minimal):
    res = minimal.run("-i", "minimal", "sh", "-c", "exit 3", real=True, check=False)
    assert res.returncode == 3


def test_singleton_reentry(bb):
    bb.profile("solo", {**MINIMAL, "id": "solo", "singleton": True, "unshareUser": True,
                        "newSession": True, "chdir": "/tmp"})
    env = {**bb.env, "PATH": os.environ.get("PATH", os.defpath)}
    first = subprocess.Popen([sys.executable, str(BB), "-i", "solo", "sh", "-c",
                              "readlink /proc/self/ns/mnt; exec sleep 30"],
                             env=env, cwd=bb.cwd, stdout=subprocess.PIPE, text=True)
    try:
        first_mnt = first.stdout.readline().strip()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            [info] = (bb.xdg_runtime / ".flatpak").glob("org.bubblebox-*/bwrapinfo.json") or [None]
            if info and info.read_text():
                break
            time.sleep(0.05)
        script = ('readlink /proc/self/ns/mnt; pwd; grep -E "^(CapEff|NoNewPrivs):" /proc/self/status;'
                  '[ "$(cut -d" " -f6 /proc/$$/stat)" = "$$" ] && echo own-session; exit 3')
        res = bb.run("-i", "solo", "sh", "-c", script, real=True, check=False)
        assert res.returncode == 3, res.stderr
        assert res.stdout.split() == [first_mnt, "/tmp", "CapEff:", "0000000000000000",
                                      "NoNewPrivs:", "1", "own-session"]
    finally:
        first.kill()
        first.wait()


def test_bwrapinfo_written(minimal):
    minimal.run("-i", "minimal", "true", real=True)
    [info] = (minimal.xdg_runtime / ".flatpak").glob("org.bubblebox-*/bwrapinfo.json")
    assert "child-pid" in json.loads(info.read_text())
