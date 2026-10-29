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


def test_disable_sandbox_without_executable_runs_shell(bb):
    res = bb.run("-s", "disableSandbox=true", env={"SHELL": str(bb.fakebin / UNSANDBOXED)})
    assert res.calls("bwrap") == []
    assert res.only(UNSANDBOXED)["argv"] == []


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


def recorded_bwrapinfo(bb, id: str) -> str:
    return instance_file(bb, id).read_text().split("\n")[0]


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
    assert recorded_bwrapinfo(bb, "solo") == res.bwrap.info_fd_target


def test_singleton_instance_named_after_effective_id(bb):
    bb.profile("base", {"id": "base", "singleton": True})
    bb.profile("solo", {"id": "solo", "include": ["base"]})
    bb.run("-i", "solo", TARGET)
    assert instance_file(bb, "solo").is_file()
    assert not instance_file(bb, "base").exists()


@pytest.mark.parametrize("args", [
    ("-i", "solo", "-s", "@include=base"),
    ("-s", "@include=base", "-i", "solo"),
    ("-i", "solo", "-j", '{"id": "base"}'),
])
def test_singleton_id_from_cli_profile_wins_over_later_sources(bb, args):
    bb.profile("base", {"id": "base"})
    bb.profile("solo", {"id": "solo", "singleton": True})
    bb.run(*args, TARGET)
    assert instance_file(bb, "solo").is_file()
    assert not instance_file(bb, "base").exists()


def test_singleton_id_from_matched_profile_does_not_override_cli_profile(bb):
    bb.global_config({"id": "m", "matches": [TARGET]})
    bb.profile("solo", {"id": "solo", "singleton": True})
    bb.run("-i", "solo", TARGET)
    assert instance_file(bb, "solo").is_file()
    assert not instance_file(bb, "m").exists()


def test_singleton_id_from_last_cli_profile_with_id(bb):
    bb.profile("a", {"id": "a", "singleton": True})
    bb.profile("b", {"id": "b"})
    bb.profile("anon", {})
    bb.run("-i", "a,b,anon", TARGET)
    assert instance_file(bb, "b").is_file()
    assert not instance_file(bb, "a").exists()


def test_singleton_requires_id(bb):
    bb.fails("-j", '{"singleton": true}', TARGET, match="singleton=True set, but no [id] attr configured")
    # the profile's file name is only a lookup key; it does not set [id]
    bb.profile("solo", {"singleton": True})
    bb.fails("-i", "solo", TARGET, match="singleton=True set, but no [id] attr configured")


def start_singleton(bb, running_sandbox, *args: str, profile: dict | None = None,
                    namespaces: dict | None = None) -> None:
    """Launch [solo] via bb, then make its recorded bwrapinfo describe a live sandbox."""
    bb.profile("solo", {"id": "solo", "singleton": True, **(profile or {})})
    bb.run(*args, TARGET)
    Path(recorded_bwrapinfo(bb, "solo")).write_text(
        json.dumps({"child-pid": running_sandbox[0], **(namespaces or {"mnt-namespace": 1})}))


def test_singleton_enters_running_instance(bb, running_sandbox):
    bwrap_pid, child_pid = running_sandbox
    start_singleton(bb, running_sandbox, "-i", "solo", profile={"chdir": "{home}/w"},
                    namespaces={"mnt-namespace": 1, "pid-namespace": 2, "net-namespace": 3})

    res = bb.run("-i", "solo", TARGET, "arg")
    assert res.calls("bwrap") == []
    call = res.only("nsenter")
    assert call["argv"] == ["--preserve-credentials", "--user", "--keep-caps", "--env",
                            "--target", str(child_pid), "--mount", "--pid", "--net",
                            f"--wdns={bb.home}/w", "--", TARGET, "arg"]
    assert int(call["sigign"], 16) & SIGPIPE_SIGXFSZ == 0


def test_singleton_refuses_instance_file_without_config_hash(bb, running_sandbox):
    start_singleton(bb, running_sandbox, "-i", "solo")
    instance_file(bb, "solo").write_text(recorded_bwrapinfo(bb, "solo"))
    bb.fails("-i", "solo", TARGET, match="started with a different config")


@pytest.mark.parametrize("args", [
    ("-i", "solo"),
    ("-i", "solo", "-s", "hostname=h"),
])
def test_singleton_enters_instance_started_with_same_config(bb, running_sandbox, args):
    start_singleton(bb, running_sandbox, *args)
    res = bb.run(*args, TARGET)
    assert res.calls("bwrap") == []
    assert res.only("nsenter")["argv"][-1] == TARGET


@pytest.mark.parametrize("args", [
    ("-i", "solo", "-s", "hostname=h"),
    ("-i", "solo", "-j", '{"unshareNet": true}'),
    ("-s", "hostname=h", "-i", "solo"),
])
def test_singleton_refuses_instance_started_with_other_config(bb, running_sandbox, args):
    start_singleton(bb, running_sandbox, "-i", "solo")
    res = bb.fails(*args, TARGET, match="running [solo] singleton instance was started with a different config")
    assert res.calls("nsenter") == res.calls("bwrap") == []


def test_singleton_refuses_instance_after_profile_edit(bb, running_sandbox):
    start_singleton(bb, running_sandbox, "-i", "solo")
    bb.profile("solo", {"id": "solo", "singleton": True, "hostname": "edited"})
    bb.fails("-i", "solo", TARGET, match="started with a different config")


def test_singleton_config_hash_ignores_per_run_values(bb, running_sandbox):
    start_singleton(bb, running_sandbox, "-i", "solo", "-s", "$X=x:{cwd}:{instance_id}")
    res = bb.run("-i", "solo", "-s", "$X=x:{cwd}:{instance_id}", TARGET, cwd=bb.root)
    assert res.calls("nsenter")


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
    assert recorded_bwrapinfo(bb, "solo") == res.bwrap.info_fd_target


@pytest.mark.parametrize("info, error", [
    ({"child-pid": 1, "bogus": 1}, "bwrap_info contains unexpected keys"),
    ({"child-pid": 1}, "bwrap_info contains only 1 key(s)"),
    ({"mnt-namespace": 1, "pid-namespace": 2}, "lacks [child-pid] key"),
])
def test_singleton_rejects_malformed_bwrapinfo(bb, info, error):
    path = bb.root / "bwrapinfo.json"
    path.write_text(json.dumps(info))
    instance_file(bb, "solo").parent.mkdir()
    instance_file(bb, "solo").write_text(str(path))
    bb.profile("solo", {"id": "solo", "singleton": True})
    bb.fails("-i", "solo", TARGET, match=error)


def test_singleton_ignores_unparsable_bwrapinfo(bb):
    # left behind when bwrap failed at startup, before writing its info
    info = bb.root / "bwrapinfo.json"
    info.touch()
    instance_file(bb, "solo").parent.mkdir()
    instance_file(bb, "solo").write_text(str(info))
    bb.profile("solo", {"id": "solo", "singleton": True})

    res = bb.run("-i", "solo", TARGET)
    assert f"ignoring unparsable bwrap info file [{info}] of a previous [solo] instance" in res.stderr
    assert res.calls("nsenter") == []
    assert recorded_bwrapinfo(bb, "solo") == res.bwrap.info_fd_target
