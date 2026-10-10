"""xdg-dbus-proxy setup driven by the [dbus] block."""
import os

import pytest

from conftest import SIGPIPE_SIGXFSZ, TARGET


@pytest.fixture
def user_bus(bb):
    """Default session bus location; bb only checks that the path exists."""
    path = bb.xdg_runtime / "bus"
    path.touch()
    return path


def proxy_dir(bb, res) -> str:
    return f"{bb.xdg_runtime}/xdg-dbus-proxy/{res.instance_id}"


def test_user_bus_proxy(bb, user_bus):
    bb.profile("p", {"dbus": {
        "sloppyNames": True,
        "policies": {"org.a.*": "talk"},
        "user": {
            "policies": {"org.b": "own"},
            "rules": {"call": {"org.c": "*"}, "broadcast": {"org.d": "@/x"}},
        },
    }})
    res = bb.run("-i", "p", TARGET)
    pdir = proxy_dir(bb, res)
    proxy = res.only("xdg-dbus-proxy")
    assert proxy["argv"][1:] == [f"unix:path={user_bus}", f"{pdir}/user", "--filter", "--sloppy-names",
                                 "--talk=org.a.*", "--own=org.b", "--broadcast=org.d=@/x", "--call=org.c=*"]
    assert int(proxy["sigign"], 16) & SIGPIPE_SIGXFSZ == 0
    assert os.path.isdir(pdir)

    a = res.bwrap
    assert len(a.values("--sync-fd")) == 1
    assert a.has("--bind", f"{pdir}/user", str(user_bus))
    assert a.setenv["DBUS_SESSION_BUS_ADDRESS"] == f"unix:path={user_bus}"
    assert a.find("--sync-fd") < a.find("--info-fd")


def test_session_bus_address_from_env(bb):
    bus = bb.root / "custom-bus"
    bus.touch()
    bb.profile("p", {"dbus": {"user": {}}})
    res = bb.run("-i", "p", TARGET, env={"DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}"})
    assert res.only("xdg-dbus-proxy")["argv"][1] == f"unix:path={bus}"
    assert res.bwrap.has("--bind", f"{proxy_dir(bb, res)}/user", str(bus))


def test_bus_level_settings_override_top_level(bb, user_bus):
    bb.profile("p", {"dbus": {"sloppyNames": True, "policies": {"org.a": "talk"},
                              "user": {"sloppyNames": False, "policies": {"org.a": "see"}}}})
    argv = bb.run("-i", "p", TARGET).only("xdg-dbus-proxy")["argv"]
    assert "--sloppy-names" not in argv
    assert argv[-1] == "--see=org.a"


def test_dbus_config_merges_across_profiles(bb, user_bus):
    bb.profile("a", {"dbus": {"user": {"policies": {"org.x": "talk", "org.y": "talk"},
                                       "rules": {"call": {"org.r": "a"}}}}})
    bb.profile("b", {"dbus": {"user": {"policies": {"org.y": "own"},
                                       "rules": {"call": {"org.r": "b"}}}}})
    argv = bb.run("-i", "a,b", TARGET).only("xdg-dbus-proxy")["argv"]
    assert set(argv[4:6]) == {"--talk=org.x", "--own=org.y"}
    assert argv[6:] == ["--call=org.r=a", "--call=org.r=b"]


@pytest.mark.skipif(not os.path.exists("/run/dbus/system_bus_socket"), reason="no system bus socket")
def test_system_bus_proxy(bb):
    bb.profile("p", {"dbus": {"system": {"policies": {"org.s": "talk"}}}})
    res = bb.run("-i", "p", TARGET)
    pdir = proxy_dir(bb, res)
    assert res.only("xdg-dbus-proxy")["argv"][1:] == [
        "unix:path=/run/dbus/system_bus_socket", f"{pdir}/system", "--filter", "--talk=org.s"]
    assert res.bwrap.has("--bind", f"{pdir}/system", "/run/dbus/system_bus_socket")
    assert "DBUS_SESSION_BUS_ADDRESS" not in res.bwrap.setenv


def test_proxy_runs_inside_its_own_sandbox(bb, user_bus):
    # the proxy sandbox resolves its own vars; it does not see the main sandbox's
    bb.profile("proxy-base", {"vars": {"info": "app={fqname}"}, "mounts": {"/usr": "ro-bind"}})
    bb.profile("p", {
        "dbus": {
            "sandbox": {"include": ["proxy-base"], "asPid1": True,
                        "mounts": {"/.flatpak-info": {"data": {"content": "{info}", "ro": True}}}},
            "user": {"policies": {"org.p": "talk"}},
        },
    })
    res = bb.run("-i", "p", TARGET)
    pdir = proxy_dir(bb, res)
    proxy_sb = res.proxy_bwrap
    assert "--as-pid-1" in proxy_sb.args
    assert proxy_sb.has("--ro-bind", "/usr", "/usr")
    assert proxy_sb.has("--bind", pdir, pdir)
    assert proxy_sb.has("--bind", str(user_bus), str(user_bus))
    assert proxy_sb.data_for("--ro-bind-data", "/.flatpak-info") == f"app=org.bubblebox.{TARGET}".encode()
    assert proxy_sb.cmd[0] == "xdg-dbus-proxy" and proxy_sb.cmd[-1] == "--talk=org.p"
    assert res.only("xdg-dbus-proxy")["argv"] == proxy_sb.cmd[1:]
    assert "--as-pid-1" not in res.bwrap.args


def test_empty_dbus_block(bb):
    bb.profile("p", {"dbus": {}})
    bb.fails("-i", "p", TARGET, match="empty [dbus] key/block not allowed")


def test_dbus_block_without_buses(bb):
    bb.profile("p", {"id": "p", "dbus": {"sloppyNames": True}})
    bb.fails("-i", "p", TARGET, match="[p] sandbox has [dbus] block configured, but none of ['system', 'user']")


def test_missing_bus_socket(bb):
    bb.profile("p", {"dbus": {"user": {}}})
    bb.fails("-i", "p", TARGET, match=f"user dbus socket [{bb.xdg_runtime}/bus] does not exist")


def test_empty_bus_key(bb, user_bus):
    bb.profile("p", {"dbus": {"user": None}})
    res = bb.run("-i", "p", TARGET)
    assert res.only("xdg-dbus-proxy")["argv"][1:] == [f"unix:path={user_bus}", f"{proxy_dir(bb, res)}/user", "--filter"]


def test_null_dbus_block(bb):
    bb.profile("p", {"dbus": None})
    bb.fails("-i", "p", TARGET, match="empty [dbus] key/block not allowed")


def test_null_dict_keys_are_treated_as_empty(bb, user_bus):
    bb.profile("a", {"env": {"A": "1"}, "dbus": {"user": {"policies": {"org.a": "talk"}}}})
    bb.profile("b", {"env": None, "vars": None, "dbus": {"user": None}})
    res = bb.run("-i", "a,b", TARGET)
    assert res.bwrap.setenv["A"] == "1"
    assert res.only("xdg-dbus-proxy")["argv"][-1] == "--talk=org.a"


@pytest.mark.parametrize("profile, key, got", [
    ({"dbus": {"user": {"policies": []}}}, "dbus.user.policies", "[]"),
    ({"env": "x"}, "env", "'x'"),
], ids=["dbus.user.policies", "env"])
def test_non_mapping_dict_key_is_rejected(bb, profile, key, got):
    bb.profile("p", profile)
    bb.fails("-i", "p", TARGET, match=f"config key [{key}] must be a mapping, got: {got}")
