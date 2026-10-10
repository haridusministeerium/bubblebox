"""End-to-end resolution of a realistic multi-profile config (fixtures/config.yaml)."""
import base64
import platform
import shutil

import pytest
import yaml

from conftest import FIXTURES, TARGET, UNSANDBOXED

pytestmark = pytest.mark.skipif(platform.machine() != "x86_64",
                                reason="fixture's seccomp program is x86_64-only")

SECCOMP = base64.b64decode(next(
    d for d in yaml.safe_load_all((FIXTURES / "config.yaml").read_text()) if d and d.get("id") == "base-simple"
)["seccomp"][0]["data"])


@pytest.fixture
def example(bb):
    shutil.copy(FIXTURES / "config.yaml", bb.sb_config / "config.yaml")
    (bb.xdg_runtime / "bus").touch()
    bb.env |= {"TERM": "xterm", "DISPLAY": ":0", "TMUX": "/tmp/tmux", "EDITOR": "vim"}
    return bb


def flatpak_info(res) -> bytes:
    return f"[Application]\nname=org.bubblebox.{TARGET}\n[Instance]\ninstance-id={res.instance_id}".encode()


def test_default_profile(example):
    bb = example
    res = bb.run(TARGET)
    a = res.bwrap
    h, d, rt = bb.home, bb.xdg_data, bb.xdg_runtime

    for flag in ("--clearenv", "--die-with-parent", "--unshare-pid"):
        assert flag in a.args
    assert a.fd_content(a.values("--seccomp")[0]) == SECCOMP
    for seq in (("--proc", "/proc"), ("--tmpfs", str(h)), ("--symlink", "usr/bin", "/bin"),
                ("--perms", "700", "--tmpfs", str(rt)), ("--ro-bind-try", f"{h}/.gtkrc-2.0", f"{h}/.gtkrc-2.0"),
                ("--ro-bind", "/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0"),
                ("--ro-bind", f"{rt}/pipewire-0", f"{rt}/pipewire-0"),
                ("--bind-try", f"{rt}/doc/by-app/org.bubblebox.{TARGET}", f"{rt}/doc"),
                ("--overlay-src", "/usr/bin", "--tmp-overlay", "/usr/bin")):
        assert a.has(*seq), seq
    assert (bb.xdg_cache / "vifm").is_dir()  # bind-create from app-configs, included by base

    assert a.setenv == {"PATH": bb.env["PATH"], "LANG": "C.UTF-8", "XDG_RUNTIME_DIR": str(rt),
                        "TERM": "xterm", "HOME": str(h), "BB_SANDBOXED": "TRUE", "EDITOR": "vim",
                        "XKB_DEFAULT_LAYOUT": "custom", "DISPLAY": ":0",
                        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={rt}/bus"}
    assert a.unsetenv == {"SSH_AGENT_PID", "TMUX"}

    assert a.data_for("--ro-bind-data", "/.flatpak-info") == flatpak_info(res)
    assert a.data_for("--ro-bind-data", f"{rt}/flatpak-info") == flatpak_info(res)
    assert a.data_for("--ro-bind-data", "/usr/bin/flatpak-spawn") == b'#!/bin/sh\nexec "$@"\n'
    assert a.args[a.find("--perms", "500") + 2] == "--ro-bind-data"
    # /usr/bin may only be remounted read-only after flatpak-spawn was written into its tmp overlay
    assert a.args.index("/usr/bin/flatpak-spawn") < a.find("--remount-ro", "/usr/bin")
    assert a.find("--remount-ro", "/usr/bin") < a.find("--sync-fd") < a.find("--info-fd")


def test_default_profile_dbus_proxy_is_sandboxed(example):
    res = example.run(TARGET)
    rt = example.xdg_runtime
    proxy_sb = res.proxy_bwrap
    assert "--as-pid-1" in proxy_sb.args and "--clearenv" in proxy_sb.args
    assert proxy_sb.data_for("--ro-bind-data", "/.flatpak-info") == flatpak_info(res)
    assert proxy_sb.fd_content(proxy_sb.values("--seccomp")[0]) == SECCOMP
    assert "--remount-ro" not in proxy_sb.args  # portal's extraArgsPost is not part of the proxy sandbox

    argv = res.only("xdg-dbus-proxy")["argv"]
    assert argv[1:4] == [f"unix:path={rt}/bus", f"{rt}/xdg-dbus-proxy/{res.instance_id}/user", "--filter"]
    assert set(argv[4:6]) == {"--talk=org.freedesktop.portal.*", "--own=org.mozilla.firefox.*"}
    assert argv[6:] == ["--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
                        "--call=org.freedesktop.portal.*=*",
                        "--call=org.freedesktop.Notifications=@/org/freedesktop/Notifications"]


def test_cli_profile_matched_by_executable(example):
    bb = example
    res = bb.run("npm", "install")
    a = res.bwrap
    assert a.cmd == ["npm", "install"]
    assert a.has("--bind", f"{bb.xdg_data}/bubblebox/homes/cli", str(bb.home))
    assert (bb.xdg_data / "bubblebox/homes/cli").is_dir()
    assert a.has("--chdir", str(bb.cwd)) and a.has("--bind", str(bb.cwd), str(bb.cwd))
    assert a.setenv["PATH"] == f"{bb.xdg_data}/npm/bin:{bb.home}/.local/pipx-bin:{bb.home}/.local/uv-bin:{bb.env['PATH']}"
    assert a.setenv["PIPX_BIN_DIR"] == f"{bb.home}/.local/pipx-bin"
    # private-home's bind of ~ replaces base-simple's tmpfs on ~
    assert not a.has("--tmpfs", str(bb.home))
    assert res.calls("bwrap-proxy") == [] and res.calls("xdg-dbus-proxy") == []


def test_dev_personal(example):
    bb = example
    res = bb.run("-i", "dev-personal", TARGET)
    a = res.bwrap
    d, h, cfg, rt = bb.xdg_data, bb.home, bb.xdg_config, bb.xdg_runtime

    assert "--clearenv" not in a.args  # dev-common overrides base-simple
    assert a.has("--bind", f"{d}/bubblebox/homes/dev-personal", str(h))
    assert a.has("--ro-bind", f"{d}/bubblebox/common/ssh/personal.pub", f"{h}/.ssh/main.pub")
    assert a.has("--bind", f"{d}/bubblebox/common/serena", f"{cfg}/serena")
    assert a.has("--symlink", f"{cfg}/gradle", f"{h}/.gradle")
    assert a.has("--symlink", f"{cfg}/claude/personal", f"{h}/.claude")
    assert a.has("--bind", "/data/dev", "/data/dev")
    assert a.setenv["DOCKER_HOST"] == f"unix://{rt}/shared/podman.sock"
    assert a.setenv["CLAUDE_CONFIG_DIR"] == f"{cfg}/claude/personal"
    assert a.setenv["DISABLE_AUTOUPDATER"] == "1"
    assert a.setenv["PATH"] == (f"{d}/bubblebox/common/PATH-shims:{d}/npm/bin:"
                                f"{h}/.local/pipx-bin:{h}/.local/uv-bin:{bb.env['PATH']}")
    assert (cfg / "claude/personal").is_dir()
    assert (rt / "bubblebox/dev-personal.instance.info").read_text() == a.info_fd_target


def test_unsandboxed_match(example):
    res = example.run(UNSANDBOXED, "x")
    assert res.calls("bwrap") == []
    assert res.only(UNSANDBOXED)["argv"] == ["x"]
