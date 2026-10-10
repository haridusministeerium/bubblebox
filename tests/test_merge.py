"""Profile merging (MERGE_POLICIES, include) and vars/env resolution."""
import os

import pytest

from conftest import TARGET


# --- merge policies & includes ----------------------------------------------

def test_literal_later_wins_and_list_concatenates(bb):
    bb.profile("a", {"hostname": "a", "extraArgs": ["--a"], "capAdd": ["CAP_A"]})
    bb.profile("b", {"hostname": "b", "extraArgs": ["--b"], "capAdd": ["CAP_B"]})
    res = bb.run("-i", "a,b", TARGET)
    assert res.bwrap.values("--hostname") == ["b"]
    assert res.bwrap.has("--a", "--b")
    assert res.bwrap.values("--cap-add") == ["CAP_A", "CAP_B"]


def test_includer_overrides_includes_and_later_include_wins(bb):
    bb.profile("inc1", {"hostname": "inc1", "chdir": "/inc1", "extraArgs": ["--inc1"]})
    bb.profile("inc2", {"hostname": "inc2", "extraArgs": ["--inc2"]})
    bb.profile("top", {"include": ["inc1", "inc2"], "hostname": "top", "extraArgs": ["--top"]})
    res = bb.run("-i", "top", TARGET)
    assert res.bwrap.values("--hostname") == ["top"]
    assert res.bwrap.values("--chdir") == ["/inc1"]
    assert res.bwrap.has("--inc1", "--inc2", "--top")


def test_nested_includes(bb):
    bb.profile("c", {"extraArgs": ["--c"]})
    bb.profile("b", {"include": ["c"], "extraArgs": ["--b"]})
    bb.profile("a", {"include": ["b"], "extraArgs": ["--a"]})
    assert bb.run("-i", "a", TARGET).bwrap.has("--c", "--b", "--a")


def test_include_forms(bb):
    path = bb.profile("by-path", {"extraArgs": ["--by-path"]}, dir=bb.root)
    bb.profile("by-id", {"extraArgs": ["--by-id"]})
    bb.profile("top", {"include": [
        {"id": "by-id"},
        {"path": str(path)},
        {"id": "missing", "try": True},
        {"path": str(bb.root / "missing.yml"), "try": True},
    ]})
    assert bb.run("-i", "top", TARGET).bwrap.has("--by-id", "--by-path")


def test_missing_include_without_try(bb):
    bb.profile("top", {"include": ["missing"]})
    bb.fails("-i", "top", TARGET, match="[missing] sandbox not found")


def test_include_entry_needs_id_or_path(bb):
    bb.profile("top", {"include": [{"try": True}]})
    bb.fails("-i", "top", TARGET, match="AssertionError")


def test_unknown_key_is_rejected(bb):
    bb.profile("p", {"bogusKey": 1})
    bb.fails("-i", "p", TARGET, match="Unknown key while merging: bogusKey")


def test_unknown_nested_key_is_rejected(bb):
    bb.profile("p", {"dbus": {"bogus": 1}})
    bb.fails("-i", "p", TARGET, match="Unknown key while merging: dbus.bogus")


def test_later_mount_for_same_target_wins(bb):
    bb.profile("a", {"mounts": {"/x": "ro-bind"}})
    bb.profile("b", {"mounts": {"/x": "bind"}})
    res = bb.run("-i", "a,b", TARGET)
    assert res.bwrap.has("--bind", "/x", "/x")
    assert not res.bwrap.has("--ro-bind", "/x", "/x")


# --- env --------------------------------------------------------------------

def test_env_value_kinds(bb):
    bb.profile("p", {"env": {
        "INHERITED": True,
        "INHERITED_MISSING": True,
        "CLEARED": False,
        "IGNORED": None,
        "STR": "{home}/s",
        "TILDE": "~/t",
        "INT": 42,
        "FLOAT": 1.5,
        "DEFAULTED": {"inherits": True, "defaultValue": "dflt"},
        "DEFAULT_UNUSED": {"inherits": True, "defaultValue": "dflt"},
        "RAW": {"value": "{not_expanded}", "raw": True},
        "VALUE": {"value": "{exe_name}"},
    }})
    res = bb.run("-i", "p", TARGET, env={"INHERITED": "host-val", "DEFAULT_UNUSED": "host-val",
                                         "IGNORED": "host-val"})
    assert res.bwrap.setenv == {
        "INHERITED": "host-val",
        "STR": f"{bb.home}/s",
        "TILDE": f"{bb.home}/t",
        "INT": "42",
        "FLOAT": "1.5",
        "DEFAULTED": "dflt",
        "DEFAULT_UNUSED": "host-val",
        "RAW": "{not_expanded}",
        "VALUE": TARGET,
    }
    assert res.bwrap.unsetenv == {"CLEARED"}


def test_invalid_env_dict(bb):
    bb.profile("p", {"env": {"BAD": {"foo": 1}}})
    bb.fails("-i", "p", TARGET, match="Invalid value for environment variable BAD")


def test_env_stacks_across_profiles(bb):
    bb.profile("a", {"env": {"PATH": True}})
    bb.profile("b", {"env": {"PATH": "/b:{PATH}"}})
    bb.profile("c", {"env": {"PATH": "/c:{PATH}"}})
    res = bb.run("-i", "a,b,c", TARGET)
    assert res.bwrap.setenv["PATH"] == f"/c:/b:{bb.env['PATH']}"


def test_vars_resolve_regardless_of_definition_order(bb):
    bb.profile("p", {
        "vars": {"a": "{b}/a", "b": "{home}/b"},
        "env": {"X": "{a}"},
    })
    assert bb.run("-i", "p", TARGET).bwrap.setenv["X"] == f"{bb.home}/b/a"


def test_vars_override_and_stack_across_profiles(bb):
    bb.profile("a", {"vars": {"v": "a", "dir": "/base"}})
    bb.profile("b", {"vars": {"v": "b", "dir": "{dir}/sub"}, "env": {"V": "{v}", "DIR": "{dir}"}})
    res = bb.run("-i", "a,b", TARGET)
    assert res.bwrap.setenv["V"] == "b"
    assert res.bwrap.setenv["DIR"] == "/base/sub"


def test_circular_vars(bb):
    bb.profile("p", {"vars": {"a": "{b}", "b": "{a}"}})
    bb.fails("-i", "p", TARGET, match="circular def")


def test_undefined_var(bb):
    bb.profile("p", {"env": {"X": "{undefined}"}})
    bb.fails("-i", "p", TARGET, match="circular def")


def test_default_vars(bb):
    bb.profile("p", {"env": {
        "HOME_": "{home}", "UID_": "{uid}", "RUNTIME": "{xdg_runtime}", "CONFIG": "{xdg_config}",
        "DATA": "{xdg_data}", "STATE": "{xdg_state}", "CACHE": "{xdg_cache}", "CWD": "{cwd}",
        "EXE_ARG": "{exe_arg}", "EXE_NAME": "{exe_name}", "NAME": "{name}", "FQNAME": "{fqname}",
        "INSTANCE": "{instance_id}",
    }})
    exe = str(bb.fakebin / TARGET)
    res = bb.run("-i", "p", exe)
    assert res.bwrap.setenv == {
        "HOME_": str(bb.home), "UID_": str(os.getuid()), "RUNTIME": str(bb.xdg_runtime),
        "CONFIG": str(bb.xdg_config), "DATA": str(bb.xdg_data), "STATE": str(bb.xdg_state),
        "CACHE": str(bb.xdg_cache), "CWD": str(bb.cwd), "EXE_ARG": exe, "EXE_NAME": TARGET,
        "NAME": TARGET, "FQNAME": f"org.bubblebox.{TARGET}", "INSTANCE": res.instance_id,
    }


def test_xdg_vars_fall_back_to_home(bb):
    bb.profile("p", {"env": {"D": "{xdg_data}", "S": "{xdg_state}", "C": "{xdg_cache}"}})
    res = bb.run("-i", "p", TARGET, env={"XDG_DATA_HOME": None, "XDG_STATE_HOME": None,
                                         "XDG_CACHE_HOME": None})
    assert res.bwrap.setenv == {"D": f"{bb.home}/.local/share", "S": f"{bb.home}/.local/state",
                                "C": f"{bb.home}/.cache"}


def test_name_var_can_be_overridden(bb):
    bb.profile("p", {"vars": {"name": "custom"}, "env": {"N": "{name}", "FQ": "{fqname}"}})
    res = bb.run("-i", "p", TARGET)
    assert res.bwrap.setenv == {"N": "custom", "FQ": f"org.bubblebox.{TARGET}"}


def test_sandbox_env_usable_in_mount_keys_and_options(bb):
    bb.profile("p", {
        "env": {"FOO": "bar"},
        "chdir": "/w/{env[FOO]}",
        "mounts": {"/m/{env[FOO]}": "tmpfs", "/h/{env[HOME]}": "tmpfs"},
    })
    res = bb.run("-i", "p", TARGET)
    assert res.bwrap.has("--chdir", "/w/bar")
    assert res.bwrap.has("--tmpfs", "/m/bar")
    assert res.bwrap.has("--tmpfs", f"/h/{bb.home}")


def test_env_reference_in_env_and_vars_values(bb):
    bb.profile("a", {"env": {"PATH": "/a:{PATH}", "BASE": "{home}/base"}})
    bb.profile("b", {
        "vars": {"v": "{env[BASE]}/v"},
        "env": {
            "HOST_HOME": "{env[HOME]}/x",
            "FROM_SANDBOX_ENV": "{env[BASE]}/sub",
            "FROM_VAR": "{v}",
            "MIXED": "{env[BASE]}:{PATH}",
            "INHERITED": True,
            "FROM_INHERITED": "{env[INHERITED]}!",
        },
    })
    res = bb.run("-i", "a,b", TARGET, env={"INHERITED": "host-val"})
    base = f"{bb.home}/base"
    assert res.bwrap.setenv == {
        "PATH": f"/a:{bb.env['PATH']}",
        "BASE": base,
        "HOST_HOME": f"{bb.home}/x",
        "FROM_SANDBOX_ENV": f"{base}/sub",
        "FROM_VAR": f"{base}/v",
        "MIXED": f"{base}:/a:{bb.env['PATH']}",
        "INHERITED": "host-val",
        "FROM_INHERITED": "host-val!",
    }


def test_undefined_env_reference(bb):
    bb.profile("p", {"env": {"X": "{env[UNDEFINED_VAR]}"}})
    bb.fails("-i", "p", TARGET, match="circular def")


def test_unresolved_placeholders_keep_format_spec(bb):
    bb.profile("p", {"vars": {"w": "{later:>5}"}, "env": {"W": "[{w}]"}})
    bb.profile("q", {"vars": {"later": "ab"}})
    assert bb.run("-i", "p,q", TARGET).bwrap.setenv["W"] == "[   ab]"
