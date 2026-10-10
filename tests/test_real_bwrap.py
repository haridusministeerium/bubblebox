"""Smoke tests against the real bwrap binary (skipped when it can't run here;
set BB_REQUIRE_REAL_BWRAP=1 to turn that skip into a failure, as CI does)."""
import json
import os

import pytest

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


def test_bwrapinfo_written(minimal):
    minimal.run("-i", "minimal", "true", real=True)
    [info] = (minimal.xdg_runtime / ".flatpak").glob("org.bubblebox-*/bwrapinfo.json")
    assert "child-pid" in json.loads(info.read_text())
