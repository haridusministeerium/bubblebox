"""Which profiles get loaded: lookup paths, CLI sources, matches, autoload, default."""
import json

from conftest import TARGET


def hostname(res) -> str:
    [value] = res.bwrap.values("--hostname")
    return value


# --- lookup -----------------------------------------------------------------

def test_profile_loaded_from_config_dir_yml(bb):
    bb.profile("p", {"hostname": "from-yml"})
    assert hostname(bb.run("-i", "p", TARGET)) == "from-yml"


def test_profile_loaded_from_config_dir_yaml(bb):
    bb.profile("p", {"hostname": "from-yaml"}, ext="yaml")
    assert hostname(bb.run("-i", "p", TARGET)) == "from-yaml"


def test_cwd_profile_shadows_config_dir(bb):
    bb.profile("p", {"hostname": "config-dir"})
    bb.profile("p", {"hostname": "cwd"}, dir=bb.cwd)
    assert hostname(bb.run("-i", "p", TARGET)) == "cwd"


def test_profile_by_path(bb):
    path = bb.profile("whatever", {"hostname": "by-path"}, dir=bb.root)
    assert hostname(bb.run("-i", str(path), TARGET)) == "by-path"


def test_comma_separated_ids_tolerate_spaces_and_empties(bb):
    bb.profile("a", {"extraArgs": ["--a"]})
    bb.profile("b", {"extraArgs": ["--b"]})
    res = bb.run("-i", " a,, b ", TARGET)
    assert res.bwrap.has("--a", "--b")


def test_profile_from_global_config(bb):
    bb.global_config({"id": "in-global", "hostname": "global"})
    assert hostname(bb.run("-i", "in-global", TARGET)) == "global"


def test_extra_docs_of_a_profile_file_are_addressable_by_id(bb):
    bb.profile("multi", {"hostname": "first"}, {"id": "second", "extraArgs": ["--second"]})
    res = bb.run("-i", "multi,second", TARGET)
    assert hostname(res) == "first"
    assert res.bwrap.has("--second")


def test_missing_profile(bb):
    bb.fails("-i", "nope", TARGET, match="[nope] sandbox not found")


def test_config_is_a_reserved_id(bb):
    bb.fails("-i", "config", TARGET, match="profile/config id cannot be [config]")


# --- CLI sources ------------------------------------------------------------

def test_json_source(bb):
    res = bb.run("-j", json.dumps({"hostname": "j", "unshareNet": True}), TARGET)
    assert hostname(res) == "j"
    assert res.bwrap.has("--unshare-net")


def test_file_source_merges_all_documents(bb):
    path = bb.profile("f", {"hostname": "doc1"}, {"extraArgs": ["--doc2"]}, dir=bb.root)
    res = bb.run("-f", str(path), TARGET)
    assert hostname(res) == "doc1"
    assert res.bwrap.has("--doc2")


def test_sources_apply_in_command_line_order(bb):
    bb.profile("p", {"hostname": "profile"})
    assert hostname(bb.run("-j", '{"hostname": "json"}', "-i", "p", TARGET)) == "profile"
    assert hostname(bb.run("-i", "p", "-j", '{"hostname": "json"}', TARGET)) == "json"


def test_set_vars_and_env_shorthands(bb):
    res = bb.run("-s", ":greeting=hi", "-s", "$GREET=say {greeting}", TARGET)
    assert res.bwrap.setenv["GREET"] == "say hi"


def test_set_nested_path_and_quoted_key(bb):
    res = bb.run("-s", "mounts./data=ro-bind", "-s", 'mounts."/a.b"=tmpfs', TARGET)
    assert res.bwrap.has("--ro-bind", "/data", "/data")
    assert res.bwrap.has("--tmpfs", "/a.b")


def test_set_parses_json_values(bb):
    res = bb.run("-s", "unshareNet=true", "-s", 'capAdd=["CAP_NET_RAW"]', "-s", "hostname=false", TARGET)
    assert res.bwrap.has("--unshare-net")
    assert res.bwrap.has("--cap-add", "CAP_NET_RAW")
    assert "--hostname" not in res.bwrap.args


def test_set_array_marker(bb):
    res = bb.run("-s", "@extraArgs=--from-set", TARGET)
    assert res.bwrap.has("--from-set")


# --- implicit selection -----------------------------------------------------

def test_default_profile_used_when_nothing_selected(bb):
    bb.profile("default", {"hostname": "default"})
    assert hostname(bb.run(TARGET)) == "default"


def test_missing_default_profile(bb):
    bb.fails(TARGET, match="[default] sandbox not found")


def test_no_default_flag(bb):
    bb.profile("default", {"hostname": "default"})
    bb.fails("-D", TARGET, match="defaulting to [default] sandbox is disallowed")


def test_alternative_default_sandbox(bb):
    bb.profile("fallback", {"hostname": "fallback"})
    assert hostname(bb.run("--default-sandbox", "fallback", TARGET)) == "fallback"


def test_global_matches_select_profile_by_executable_name(bb):
    bb.profile("default", {"hostname": "default"})
    bb.global_config({"id": "m", "matches": ["other", TARGET], "hostname": "matched"})
    assert hostname(bb.run(TARGET)) == "matched"
    assert hostname(bb.run(str(bb.fakebin / TARGET))) == "matched"  # basename is matched


def test_no_match_flag(bb):
    bb.profile("default", {"hostname": "default"})
    bb.global_config({"id": "m", "matches": [TARGET], "hostname": "matched"})
    assert hostname(bb.run("-M", TARGET)) == "default"


def test_matches_also_apply_alongside_explicit_ids(bb):
    bb.profile("p", {"extraArgs": ["--explicit"]})
    bb.global_config({"id": "m", "matches": [TARGET], "extraArgs": ["--matched"]})
    res = bb.run("-i", "p", TARGET)
    assert res.bwrap.has("--explicit", "--matched")


def test_autoload_by_executable_name(bb):
    bb.profile("default", {"hostname": "default"})
    bb.profile(TARGET, {"hostname": "autoloaded"})
    assert hostname(bb.run(TARGET)) == "default"
    assert hostname(bb.run("-a", TARGET)) == "autoloaded"


def test_executable_defaults_to_shell_basename(bb):
    bb.global_config({"id": "m", "matches": ["sh"], "hostname": "shell"})
    res = bb.run(env={"SHELL": "/bin/sh"})
    assert hostname(res) == "shell"
    assert res.bwrap.cmd == ["sh"]


def test_executable_args_are_passed_through(bb):
    bb.profile("default", {})
    res = bb.run(TARGET, "-i", "x", "--flag", "a b")
    assert res.bwrap.cmd == [TARGET, "-i", "x", "--flag", "a b"]
