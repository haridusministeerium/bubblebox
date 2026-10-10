"""Process-level behaviour: exec paths, signals, info-fd, singleton, logging."""
import json
import subprocess
import time
from pathlib import Path

import psutil
import pytest

from conftest import SIGPIPE_SIGXFSZ, TARGET, UNSANDBOXED


def test_disable_sandbox_execs_directly(bb):
    bb.global_config({"id": "none", "matches": [UNSANDBOXED], "disableSandbox": True})
    res = bb.run(UNSANDBOXED, "a", "b c")
    assert res.calls("bwrap") == []
    call = res.only(UNSANDBOXED)
    assert call["argv"] == ["a", "b c"]
    assert int(call["sigign"], 16) & SIGPIPE_SIGXFSZ == 0


def test_signals_restored_before_exec_of_bwrap(bb):
    bb.profile("default", {})
    assert bb.run(TARGET).bwrap.sigign & SIGPIPE_SIGXFSZ == 0


def test_info_fd_points_at_per_instance_bwrapinfo(bb):
    bb.profile("default", {})
    res = bb.run(TARGET)
    assert res.bwrap.info_fd_target == f"{bb.xdg_runtime}/.flatpak/{res.instance_id}/bwrapinfo.json"


def test_debug_logging(bb):
    bb.profile("default", {"hostname": "h"})
    assert bb.run(TARGET).stdout == ""
    out = bb.run("-l", "debug", TARGET).stdout
    assert "bwrap command: bwrap --hostname h" in out
    assert f"-- {TARGET}" in out


# --- singleton ----------------------------------------------------------------

def instance_file(bb, id: str) -> Path:
    return bb.xdg_runtime / "bubblebox" / f"{id}.instance.info"


@pytest.fixture
def running_sandbox():
    """A process with a child, standing in for bwrap and the sandboxed process it spawned."""
    proc = subprocess.Popen(["sh", "-c", "sleep 60 & wait"])
    parent = psutil.Process(proc.pid)
    deadline = time.monotonic() + 5
    while not parent.children() and time.monotonic() < deadline:
        time.sleep(0.02)
    [child] = parent.children()
    yield proc.pid, child.pid
    child.kill()
    proc.kill()
    proc.wait()


def test_singleton_records_instance(bb):
    bb.profile("solo", {"id": "solo", "singleton": True})
    res = bb.run("-i", "solo", TARGET)
    assert instance_file(bb, "solo").read_text() == res.bwrap.info_fd_target


def test_singleton_instance_named_after_effective_id(bb):
    bb.profile("base", {"id": "base", "singleton": True})
    bb.profile("solo", {"id": "solo", "include": ["base"]})
    bb.run("-i", "solo", TARGET)
    assert instance_file(bb, "solo").is_file()
    assert not instance_file(bb, "base").exists()


def test_singleton_requires_id(bb):
    bb.fails("-j", '{"singleton": true}', TARGET, match="singleton=True set, but no [id] attr configured")
    # the profile's file name is only a lookup key; it does not set [id]
    bb.profile("solo", {"singleton": True})
    bb.fails("-i", "solo", TARGET, match="singleton=True set, but no [id] attr configured")


def test_singleton_enters_running_instance(bb, running_sandbox):
    bwrap_pid, child_pid = running_sandbox
    info = bb.root / "bwrapinfo.json"
    info.write_text(json.dumps({"child-pid": bwrap_pid, "mnt-namespace": 1, "pid-namespace": 2, "net-namespace": 3}))
    instance_file(bb, "solo").parent.mkdir()
    instance_file(bb, "solo").write_text(str(info))
    bb.profile("solo", {"id": "solo", "singleton": True, "chdir": "{home}/w"})

    res = bb.run("-i", "solo", TARGET, "arg")
    assert res.calls("bwrap") == []
    call = res.only("nsenter")
    assert call["argv"] == ["--preserve-credentials", "--user", "--keep-caps", "--env",
                            "--target", str(child_pid), "--mount", "--pid", "--net",
                            f"--wdns={bb.home}/w", "--", TARGET, "arg"]
    assert int(call["sigign"], 16) & SIGPIPE_SIGXFSZ == 0


def test_singleton_ignores_dead_instance(bb):
    dead = subprocess.Popen(["true"])
    dead.wait()
    info = bb.root / "bwrapinfo.json"
    info.write_text(json.dumps({"child-pid": dead.pid, "mnt-namespace": 1}))
    instance_file(bb, "solo").parent.mkdir()
    instance_file(bb, "solo").write_text(str(info))
    bb.profile("solo", {"id": "solo", "singleton": True})

    res = bb.run("-i", "solo", TARGET)
    assert res.calls("nsenter") == []
    assert instance_file(bb, "solo").read_text() == res.bwrap.info_fd_target


@pytest.mark.parametrize("info, error", [
    ({"child-pid": 1, "bogus": 1}, "bwrap_info contains unexpected keys"),
    ({"child-pid": 1}, "bwrap_info contains only 1 key(s)"),
])
def test_singleton_rejects_malformed_bwrapinfo(bb, info, error):
    path = bb.root / "bwrapinfo.json"
    path.write_text(json.dumps(info))
    instance_file(bb, "solo").parent.mkdir()
    instance_file(bb, "solo").write_text(str(path))
    bb.profile("solo", {"id": "solo", "singleton": True})
    bb.fails("-i", "solo", TARGET, match=error)
