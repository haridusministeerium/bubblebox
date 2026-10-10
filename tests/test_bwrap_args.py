"""Translation of the merged sandbox config into bwrap arguments."""
import base64
import platform

import pytest

from conftest import TARGET


def run_profile(bb, profile: dict, *args: str, **kw):
    bb.profile("p", profile)
    return bb.run("-i", "p", *args, TARGET, **kw)


# --- flags & options ----------------------------------------------------------

def test_flags_are_kebab_cased_and_false_omitted(bb):
    res = run_profile(bb, {"unshareAll": True, "dieWithParent": True, "asPid1": True,
                           "unshareUserTry": True, "newSession": False, "clearenv": None})
    for flag in ("--unshare-all", "--die-with-parent", "--as-pid-1", "--unshare-user-try"):
        assert flag in res.bwrap.args
    assert "--new-session" not in res.bwrap.args
    assert "--clearenv" not in res.bwrap.args


def test_options(bb):
    res = run_profile(bb, {"argv0": "x-{exe_name}", "userns2": 5, "uid": 1000, "hostname": "h",
                           "chdir": "{home}/w", "infoFd": False, "jsonStatusFd": 9})
    for seq in (("--argv0", f"x-{TARGET}"), ("--userns2", "5"), ("--uid", "1000"),
                ("--hostname", "h"), ("--chdir", f"{bb.home}/w"), ("--json-status-fd", "9")):
        assert res.bwrap.has(*seq), seq
    assert "False" not in res.bwrap.args  # false-valued options are omitted


def test_list_options(bb):
    res = run_profile(bb, {"capDrop": ["ALL"], "remountRo": ["/a", "{home}"], "lockFile": [None, "/l"]})
    assert res.bwrap.has("--cap-drop", "ALL")
    assert res.bwrap.values("--remount-ro") == ["/a", str(bb.home)]
    assert res.bwrap.values("--lock-file") == ["/l"]


def test_argument_order(bb):
    res = run_profile(bb, {
        "unshareNet": True,
        "extraArgs": ["--pre-{exe_name}"],
        "extraArgsPost": ["--post-{exe_name}"],
        "env": {"E": "1", "U": False},
        "mounts": {"/t": "tmpfs"},
        "chmod": {"/t": "0700"},
    })
    a = res.bwrap
    order = [a.find("--unshare-net"), a.find(f"--pre-{TARGET}"), a.find("--unsetenv", "U"),
             a.find("--setenv", "E", "1"), a.find("--tmpfs", "/t"), a.find("--chmod", "0700", "/t"),
             a.find(f"--post-{TARGET}"), a.find("--info-fd")]
    assert -1 not in order and order == sorted(order), order
    assert a.args[-2] == "--info-fd"
    assert a.cmd == [TARGET]


# --- mounts -------------------------------------------------------------------

def test_simple_mount_types(bb):
    res = run_profile(bb, {"mounts": {"/proc": "proc", "/dev": "dev", "/tmp": "tmpfs",
                                      "/mq": "mqueue", "/d": "dir"}})
    for kind, dest in (("proc", "/proc"), ("dev", "/dev"), ("tmpfs", "/tmp"), ("mqueue", "/mq"), ("dir", "/d")):
        assert res.bwrap.has(f"--{kind}", dest)


def test_bind_shorthands(bb):
    res = run_profile(bb, {"mounts": {
        "/usr": "ro-bind",
        "/opt/": "bind",
        "/srv": "ro-bind-try",
        "/dev/dri": "dev-bind",
        "~/x": "bind:{xdg_data}/x",
        "~/y": "ro-bind-try:~/src",
    }})
    for seq in (("--ro-bind", "/usr", "/usr"), ("--bind", "/opt", "/opt"), ("--ro-bind-try", "/srv", "/srv"),
                ("--dev-bind", "/dev/dri", "/dev/dri"), ("--bind", f"{bb.xdg_data}/x", f"{bb.home}/x"),
                ("--ro-bind-try", f"{bb.home}/src", f"{bb.home}/y")):
        assert res.bwrap.has(*seq), seq


def test_bind_create_shorthand_creates_source(bb):
    res = run_profile(bb, {"mounts": {"~/same": "bind-create", "~/other": "ro-bind-create:{xdg_data}/src"}})
    assert res.bwrap.has("--bind", f"{bb.home}/same", f"{bb.home}/same")
    assert res.bwrap.has("--ro-bind", f"{bb.xdg_data}/src", f"{bb.home}/other")
    assert (bb.home / "same").is_dir()
    assert (bb.xdg_data / "src").is_dir()


def test_symlink_shorthand(bb):
    res = run_profile(bb, {"mounts": {"/bin": "symlink:usr/bin", "~/l": "symlink:{xdg_data}/t"}})
    assert res.bwrap.has("--symlink", "usr/bin", "/bin")
    assert res.bwrap.has("--symlink", f"{bb.xdg_data}/t", f"{bb.home}/l")


def test_falsy_mount_is_skipped(bb):
    res = run_profile(bb, {"mounts": {"/a": None, "/b": False}})
    assert "/a" not in res.bwrap.args and "/b" not in res.bwrap.args


def test_mounts_sorted_by_destination(bb):
    res = run_profile(bb, {"mounts": {"/z": "tmpfs", "/a/b": "tmpfs", "/a": "tmpfs"}})
    assert res.bwrap.find("--tmpfs", "/a") < res.bwrap.find("--tmpfs", "/a/b") < res.bwrap.find("--tmpfs", "/z")


def test_tmpfs_and_dir_dicts(bb):
    res = run_profile(bb, {"mounts": {
        "/t1": {"tmpfs": {"perms": "0o700", "size": 1024}},
        "/t2": {"tmpfs": {}},
        "/d": {"dir": {"perms": 755}},
    }})
    assert res.bwrap.has("--perms", "0700", "--size", "1024", "--tmpfs", "/t1")
    assert res.bwrap.has("--tmpfs", "/t2") and not res.bwrap.has("--perms", "0700", "--tmpfs", "/t2")
    assert res.bwrap.has("--perms", "755", "--dir", "/d")


def test_symlink_dict(bb):
    res = run_profile(bb, {"mounts": {"/s": {"symlink": "{home}/target"}}})
    assert res.bwrap.has("--symlink", f"{bb.home}/target", "/s")


def test_bind_dict(bb):
    res = run_profile(bb, {"mounts": {
        "/b1": {"bind": {"path": "{xdg_data}/p", "ro": True, "try": True}},
        "/b2": {"bind": {"dev": True}},
        "/b3": {"bind": {"path": "{xdg_data}/created", "create": True}},
    }})
    assert res.bwrap.has("--ro-bind-try", f"{bb.xdg_data}/p", "/b1")
    assert res.bwrap.has("--dev-bind", "/b2", "/b2")
    assert res.bwrap.has("--bind", f"{bb.xdg_data}/created", "/b3")
    assert (bb.xdg_data / "created").is_dir()


def test_fd_mount(bb):
    res = run_profile(bb, {"mounts": {"/f": {"fd": {"fd": 7, "ro": True}}, "/g": {"fd": {"fd": 8}}}})
    assert res.bwrap.has("--ro-bind-fd", "7", "/f")
    assert res.bwrap.has("--bind-fd", "8", "/g")


def test_file_and_data_mounts(bb):
    blob = b"\x00\x01binary"
    res = run_profile(bb, {"mounts": {
        "/f": {"file": {"content": "hi {exe_name}", "perms": 600}},
        "/raw": {"file": {"content": "{kept}", "raw": True}},
        "/d": {"data": {"content": base64.b64encode(blob).decode(), "base64": True, "ro": True}},
        "/rw": {"data": {"content": "rw"}},
    }})
    assert res.bwrap.data_for("--file", "/f") == f"hi {TARGET}".encode()
    assert res.bwrap.args[res.bwrap.find("--file") - 2:res.bwrap.find("--file")] == ["--perms", "600"]
    assert res.bwrap.data_for("--file", "/raw") == b"{kept}"
    assert res.bwrap.data_for("--ro-bind-data", "/d") == blob
    assert res.bwrap.data_for("--bind-data", "/rw") == b"rw"


def test_datasource_fd(bb):
    res = run_profile(bb, {"mounts": {"/f": {"file": {"fd": 99}}, "/d": {"data": {"fd": 98, "ro": True}}}})
    assert res.bwrap.has("--file", "99", "/f")
    assert res.bwrap.has("--ro-bind-data", "98", "/d")


def test_overlays(bb):
    res = run_profile(bb, {"mounts": {
        "/rw": {"overlay": {"lower": ["/l1", "{home}/l2"], "upper": "/up", "work": "/wk"}},
        "/tmp-ov": {"overlay": {"lower": ["/l3"]}},
        "/ro-ov": {"overlay": {"lower": ["/l4"], "mode": "ro"}},
    }})
    assert res.bwrap.has("--overlay-src", "/l3", "--tmp-overlay", "/tmp-ov")
    assert res.bwrap.has("--overlay-src", "/l4", "--ro-overlay", "/ro-ov")
    assert res.bwrap.has("--overlay-src", "/l1", "--overlay-src", f"{bb.home}/l2",
                         "--overlay", "/up", "/wk", "/rw")


@pytest.mark.parametrize("mount, error", [
    ({"bogus": 1}, "invalid mount value"),
    (5, "invalid mount (of type <class 'int'>)"),
])
def test_invalid_mount(bb, mount, error):
    bb.profile("p", {"mounts": {"/x": mount}})
    bb.fails("-i", "p", TARGET, match=error)


def test_chmod(bb):
    res = run_profile(bb, {"chmod": {"~/f": "0700", "/b": 644, "/skip": None}})
    assert res.bwrap.find("--chmod", "644", "/b") < res.bwrap.find("--chmod", "0700", f"{bb.home}/f")
    assert "/skip" not in res.bwrap.args


# --- seccomp ------------------------------------------------------------------

def test_seccomp_program_for_this_arch_is_piped(bb):
    prog = b"\x20\x00\x00\x00fake-bpf"
    res = run_profile(bb, {"seccomp": [
        {"arch": "not-this-arch", "data": base64.b64encode(b"other").decode()},
        {"arch": platform.machine(), "data": base64.b64encode(prog).decode()},
    ]})
    [fd] = res.bwrap.values("--seccomp")
    assert res.bwrap.fd_content(fd) == prog


def test_seccomp_single_dict_and_fd(bb):
    res = run_profile(bb, {"seccomp": {"arch": platform.machine(), "data": base64.b64encode(b"p").decode()}})
    assert res.bwrap.fd_content(res.bwrap.values("--seccomp")[0]) == b"p"
    assert run_profile(bb, {"seccomp": 77}).bwrap.has("--seccomp", "77")


@pytest.mark.parametrize("progs, error", [
    ([{"arch": "not-this-arch", "data": ""}], "seccomp program not found for our architecture"),
    ([{"arch": platform.machine(), "data": ""}] * 2, "2 seccomp programs found for our architecture"),
])
def test_seccomp_arch_errors(bb, progs, error):
    bb.profile("p", {"seccomp": progs})
    bb.fails("-i", "p", TARGET, match=error)
