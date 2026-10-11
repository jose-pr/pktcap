"""The settings file of the command line: duho's ``ConfigArgs`` on the root, and
what pktcap adds to it.

The root takes ``--config``/``-c FILE`` before the command name, ``PKTCAP_CONFIG``,
else the user's own ``pktcap/pktcap.ini``. A table named for a command sets that
command's options and a top-level ``load`` is the plugin list of every command.
What is refused (an unknown key, a file other users may write) is refused with
one line that never holds text of the file. The plugin module is written by the
test (``plugin_module``).
"""

import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("duho")

import captures as build  # noqa: E402
from duho import main as run  # noqa: E402
from duho.mcp import call_tool  # noqa: E402

from pktcap.cli import Capture, Convert, Plugins, Replay, main  # noqa: E402
from pktcap.cli import _settings  # noqa: E402
from pktcap.cli._loader import read_settings  # noqa: E402
from pktcap.cli._root import Pktcap  # noqa: E402

IS_WINDOWS = os.name == "nt"
SECRET = "s3cr3t-marker-text"
OTHER = """
import pathlib
pathlib.Path(__file__).with_name("other-imported.txt").write_text("imported")
import pktcap

def pktcap_plugin(registry):
    registry.register("udp", 9998, lambda data: pktcap.Dissected(None, data))
"""
THIRD = """
import pktcap

def pktcap_plugin(registry):
    registry.register("udp", 9997, lambda data: pktcap.Dissected(None, data))
"""


def frame(payload, port=9999):
    return build.ethernet(
        build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, port, payload))
    )


@pytest.fixture
def trace(tmp_path):
    path = tmp_path / "trace.pcap"
    path.write_bytes(build.pcap([frame(b"\x01boot"), frame(b"\x02lease")]))
    return path


@pytest.fixture
def home(tmp_path, monkeypatch):
    """The user's configuration directory, by this platform's variable."""
    base = tmp_path / "config-home"
    base.mkdir()
    monkeypatch.setenv("APPDATA" if IS_WINDOWS else "XDG_CONFIG_HOME", str(base))
    return base


def default_file(home, text, *, raw=None):
    target = home / "pktcap"
    target.mkdir(exist_ok=True)
    path = target / "pktcap.ini"
    path.write_bytes(raw if raw is not None else text.encode("utf-8"))
    return path


def written(tmp_path, name, text):
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))
    return path


def go(capsys, *argv):
    status = main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return status, out, err


def listed(capsys, *argv):
    """``pktcap [argv] plugins --json``: the status and the report."""
    status, out, err = go(capsys, *argv, "plugins", "--json")
    return status, (json.loads(out) if status == 0 else None), err


def names(report):
    return [plugin["name"] for plugin in report["plugins"]]


# -- the root takes the file, the commands set from its tables ----------------


@pytest.mark.parametrize(
    "name, text",
    [
        ("s.toml", '[convert]\nformat = "text"\n'),
        ("s.json", '{"convert": {"format": "text"}}'),
        ("s.ini", "[convert]\nformat = text\n"),
    ],
)
def test_a_table_for_a_command_sets_its_options_and_the_argument_beats_it(
    name, text, tmp_path, trace, capsys
):
    path = written(tmp_path, name, text)
    status, out, _ = go(capsys, "-c", path, "convert", "-i", trace)
    lines = out.splitlines()
    assert status == 0 and len(lines) == 2 and "{" not in lines[0]
    status, out, _ = go(capsys, "--config", path, "convert", "-i", trace)
    assert status == 0 and out.splitlines() == lines
    status, out, _ = go(capsys, "-c", path, "convert", "-i", trace, "--format", "json")
    assert status == 0 and json.loads(out.splitlines()[0])["layers"]


def test_a_top_level_key_sets_the_roots_own_option(tmp_path, trace, capsys, caplog):
    path = written(tmp_path, "s.toml", "verbose = 2\n")
    status, _, err = go(capsys, "-c", path, "convert", "-i", trace, "--format", "json")
    assert status == 0 and "3 frames read" not in err and "2 frames read" in err


def test_a_top_level_load_reaches_every_command_and_a_commands_own_wins(
    tmp_path, plugin_module
):
    path = written(
        tmp_path, "s.toml", 'load = ["every.one"]\n[plugins]\nload = ["its.own"]\n'
    )
    tables = read_settings(path, Pktcap)
    assert tables is not None
    assert {k: v["load"] for k, v in tables.items()} == {
        "capture": ["every.one"],
        "replay": ["every.one"],
        "convert": ["every.one"],
        "plugins": ["its.own"],
    }


def test_the_top_level_load_is_the_list_of_a_command_that_runs(
    tmp_path, plugin_module, trace, capsys
):
    mod, own = plugin_module(), plugin_module(OTHER)
    path = written(
        tmp_path,
        "s.toml",
        'load = ["%s"]\n[plugins]\nload = ["%s"]\n' % (mod.name, own.name),
    )
    status, out, _ = go(
        capsys, "-c", path, "convert", "-i", trace, "-f", "demo.opcode=1"
    )
    assert status == 0 and len(out.splitlines()) == 1
    status, report, _ = listed(capsys, "-c", path)
    assert status == 0 and names(report) == [own.name]
    assert report["plugins"][0]["source"] == str(path)


def test_the_variable_beats_the_file_and_the_argument_beats_both(
    tmp_path, plugin_module, monkeypatch, capsys
):
    in_file, in_variable, in_argument = (
        plugin_module(),
        plugin_module(OTHER),
        plugin_module(THIRD),
    )
    path = written(tmp_path, "s.toml", 'load = "%s"\n' % in_file.name)
    status, report, _ = listed(capsys, "-c", path)
    assert (names(report), report["plugins"][0]["source"]) == (
        [in_file.name],
        str(path),
    )
    monkeypatch.setenv("PKTCAP_LOAD", in_variable.name)
    status, report, _ = listed(capsys, "-c", path)
    assert (names(report), report["plugins"][0]["source"]) == (
        [in_variable.name],
        "PKTCAP_LOAD",
    )
    status, out, _ = go(
        capsys, "-c", path, "plugins", "--json", "--load", in_argument.name
    )
    report = json.loads(out)
    assert (names(report), report["plugins"][0]["source"]) == (
        [in_argument.name],
        "argument",
    )
    assert report["configuration"] == str(path)


def test_a_file_that_applies_is_read_even_when_the_argument_names_the_list(
    tmp_path, plugin_module, capsys
):
    mod = plugin_module()
    bad = written(tmp_path, "bad.toml", "top = \n")
    status, _, err = go(capsys, "-c", bad, "plugins", "--load", mod.name)
    assert status == 2 and "invalid TOML" in err and not mod.imported


def test_none_is_the_empty_list_in_the_variable_the_file_and_the_argument(
    tmp_path, plugin_module, monkeypatch, capsys
):
    mod = plugin_module()
    path = written(tmp_path, "s.toml", 'load = "none"\n')
    status, report, _ = listed(capsys, "-c", path)
    assert status == 0 and report["plugins"] == []
    monkeypatch.setenv("PKTCAP_LOAD", "None")
    status, report, _ = listed(capsys)
    assert status == 0 and report["plugins"] == []
    monkeypatch.setenv("PKTCAP_LOAD", mod.name)
    status, out, _ = go(capsys, "plugins", "--json", "--load", "none")
    assert status == 0 and json.loads(out)["plugins"] == [] and not mod.imported


def test_an_empty_variable_is_unset(tmp_path, plugin_module, monkeypatch, capsys):
    mod = plugin_module()
    path = written(tmp_path, "s.toml", 'load = "%s"\n' % mod.name)
    monkeypatch.setenv("PKTCAP_LOAD", "")
    status, report, _ = listed(capsys, "-c", path)
    assert status == 0 and report["plugins"][0]["source"] == str(path)


# -- what a settings file may hold --------------------------------------------


@pytest.mark.parametrize(
    "text, problem",
    [
        ("unknown_root = %r\n" % SECRET, "unknown key 'unknown_root'"),
        ("[nosuch]\nx = %r\n" % SECRET, "unknown table 'nosuch'"),
        ("[convert]\nnosuch = %r\n" % SECRET, "unknown key 'nosuch' in [convert]"),
        ('[pktcap]\nload = "%s"\n' % SECRET, "write load at the top level"),
        ("config = %r\n" % SECRET, "unknown key 'config'"),
        ("convert = %r\n" % SECRET, "'convert' must be a table"),
        ('top = "%s\n' % SECRET, "invalid TOML"),
        ("[convert]\n%s = 1\n" % ("k" * 500), "unknown key 'kkkkkkkk"),
    ],
)
def test_a_file_that_holds_something_nobody_has_is_one_line_and_no_text_of_it(
    text, problem, tmp_path, trace, capsys
):
    path = written(tmp_path, "s.toml", text)
    status, out, err = go(capsys, "-c", path, "convert", "-i", trace)
    assert status == 2 and out == ""
    (line,) = err.splitlines()
    assert line.startswith("pktcap: error: ") and problem in line
    assert SECRET not in line and "k" * 41 not in line


def test_the_old_layout_says_where_load_goes(home, capsys):
    default_file(home, "[pktcap]\nload = a.b\n")
    status, _, err = go(capsys, "plugins")
    assert status == 2
    assert "[pktcap] is not a settings table" in err and "top level" in err


def test_a_name_no_format_claims_is_refused(tmp_path, capsys):
    path = written(tmp_path, "settings.conf", "load = a.b\n")
    status, _, err = go(capsys, "-c", path, "plugins")
    assert status == 2 and "cannot tell the config format" in err


def test_the_file_is_read_as_utf_8_with_its_byte_order_mark_dropped(
    tmp_path, plugin_module, capsys
):
    one, two = plugin_module(), plugin_module(OTHER)
    text = "# a comment\n; and another\n\n[DEFAULT]\nload = %s,\n   %s\n" % (
        one.name,
        two.name,
    )
    path = tmp_path / "s.ini"
    path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
    status, report, _ = listed(capsys, "-c", path)
    assert status == 0 and names(report) == [one.name, two.name]
    bad = tmp_path / "bad.ini"
    bad.write_bytes(b"[DEFAULT]\nload = \xff\n")
    status, _, err = go(capsys, "-c", bad, "plugins")
    assert status == 2 and "not valid UTF-8 (byte offset 17)" in err


def test_a_percent_sign_is_text_and_is_no_dotted_name(tmp_path, capsys):
    path = written(tmp_path, "s.ini", "[DEFAULT]\nload = %(x)s\n")
    status, _, err = go(capsys, "-c", path, "plugins")
    assert status == 2 and "not a dotted Python name" in err and str(path) in err


def test_an_empty_file_or_value_names_nothing(tmp_path, capsys):
    for text in ("", "# only a comment\n", "[DEFAULT]\n", "[DEFAULT]\nload =\n"):
        path = written(tmp_path, "s.ini", text)
        status, report, _ = listed(capsys, "-c", path)
        assert status == 0 and report["plugins"] == []


def test_a_file_over_65536_octets_is_refused_and_one_of_exactly_that_is_read(
    tmp_path, capsys
):
    head = b"[DEFAULT]\nload = none\n"
    padding = b"# " + b"x" * 60 + b"\n"
    exact = head + (padding * 1100)[: 65536 - len(head)]
    assert len(exact) == 65536
    path = tmp_path / "s.ini"
    path.write_bytes(exact)
    assert listed(capsys, "-c", path)[0] == 0
    path.write_bytes(exact + b"#")
    status, _, err = go(capsys, "-c", path, "plugins")
    assert status == 2 and "over 65536 octets" in err


# -- where the file is ---------------------------------------------------------


def test_the_file_is_under_the_platforms_configuration_directory(home):
    assert _settings.default_path() == home / "pktcap" / "pktcap.ini"


def test_the_configuration_directory_falls_back_to_the_users_home(
    tmp_path, monkeypatch
):
    user = tmp_path / "user"
    user.mkdir()
    for name in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.setenv("USERPROFILE", str(user))
    tail = ("AppData", "Roaming") if IS_WINDOWS else (".config",)
    expected = user.joinpath(*tail, "pktcap", "pktcap.ini")
    assert _settings.default_path() == expected


def test_a_relative_configuration_directory_is_ignored(tmp_path, monkeypatch):
    user = tmp_path / "user"
    user.mkdir()
    monkeypatch.setenv("APPDATA" if IS_WINDOWS else "XDG_CONFIG_HOME", "zzrel/dir")
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.setenv("USERPROFILE", str(user))
    path = _settings.default_path()
    assert path is not None and path.is_absolute()
    assert str(user) in str(path) and "zzrel" not in str(path)


def test_the_users_own_file_is_read_and_a_missing_one_is_no_error(
    home, plugin_module, capsys
):
    status, report, _ = listed(capsys)
    assert status == 0 and report["configuration"] is None
    mod = plugin_module()
    path = default_file(home, "[DEFAULT]\nload = %s\n" % mod.name)
    status, report, _ = listed(capsys)
    assert status == 0 and report["configuration"] == str(path)
    assert report["plugins"][0]["source"] == str(path)


def test_the_variable_names_the_file_and_the_argument_names_it_before_the_variable(
    home, tmp_path, plugin_module, monkeypatch, capsys
):
    in_default, in_variable, in_argument = (
        plugin_module(),
        plugin_module(OTHER),
        plugin_module(THIRD),
    )
    default_file(home, "[DEFAULT]\nload = %s\n" % in_default.name)
    variable = written(tmp_path, "v.ini", "[DEFAULT]\nload = %s\n" % in_variable.name)
    argument = written(tmp_path, "a.ini", "[DEFAULT]\nload = %s\n" % in_argument.name)
    monkeypatch.setenv("PKTCAP_CONFIG", str(variable))
    assert names(listed(capsys)[1]) == [in_variable.name]
    assert names(listed(capsys, "-c", argument)[1]) == [in_argument.name]


def test_a_relative_variable_is_refused_as_one_that_outlives_its_directory(
    monkeypatch, capsys
):
    monkeypatch.setenv("PKTCAP_CONFIG", "pktcap.ini")
    status, _, err = go(capsys, "plugins")
    assert status == 2 and "PKTCAP_CONFIG must be an absolute path" in err


def test_the_working_directory_names_nothing(
    tmp_path, plugin_module, home, monkeypatch, capsys
):
    mod = plugin_module()
    work = tmp_path / "work"
    work.mkdir()
    for name in ("pktcap.ini", ".pktcap.ini", ".pkcap.ini", "setup.cfg"):
        (work / name).write_text("[DEFAULT]\nload = %s\n" % mod.name, encoding="utf-8")
    monkeypatch.chdir(work)
    status, report, _ = listed(capsys)
    assert status == 0 and report["plugins"] == [] and not mod.imported


def test_a_directory_in_place_of_the_default_file_is_refused(home, capsys):
    (home / "pktcap" / "pktcap.ini").mkdir(parents=True)
    status, _, err = go(capsys, "plugins")
    if hasattr(os, "geteuid"):  # the default file is checked where owners are
        assert status == 2 and "not a regular file" in err
    else:
        assert status == 1


def test_a_missing_file_named_by_the_option_is_a_usage_error(tmp_path, capsys):
    status, _, err = go(capsys, "-c", tmp_path / "missing.ini", "plugins")
    assert status == 2 and "no such file" in err


def test_the_option_comes_before_the_command_name_only(tmp_path, trace, capsys):
    path = written(tmp_path, "s.toml", "")
    status, _, err = go(capsys, "convert", "-i", trace, "-c", path)
    assert status == 2 and "unrecognized arguments" in err


# -- the user's own file is checked where owners are, a named one is not ----------


def _can_set_everyone_write(tmp_path):
    probe = tmp_path / "probe"
    probe.write_text("x")
    os.chmod(probe, 0o600)
    closed = not probe.stat().st_mode & 0o002
    os.chmod(probe, 0o666)
    return closed and bool(probe.stat().st_mode & 0o002)


def test_a_default_file_everyone_may_write_is_not_read_and_a_named_one_is(
    home, plugin_module, tmp_path, monkeypatch, capsys
):
    if not _can_set_everyone_write(tmp_path):
        pytest.skip("this platform records no write permission for everyone")
    mod = plugin_module()
    path = default_file(home, "[DEFAULT]\nload = %s\n" % mod.name)
    os.chmod(path, 0o666)
    for argv in (("plugins",), ("plugins", "--load", "none")):
        status, _, err = go(capsys, *argv)
        assert status == 2 and "everyone may write it" in err and str(path) in err
        assert not mod.imported
    # A file the user names is theirs: read as it is, whatever its mode.
    status, report, _ = listed(capsys, "-c", path)
    assert status == 0 and names(report) == [mod.name]
    monkeypatch.setenv("PKTCAP_CONFIG", str(path))
    status, report, _ = listed(capsys)
    assert status == 0 and names(report) == [mod.name]


def test_a_default_file_another_user_owns_is_not_read_and_a_named_one_is(
    home, plugin_module, capsys
):
    if not hasattr(os, "geteuid") or os.geteuid() != 0 or not hasattr(os, "chown"):
        pytest.skip("only root can make a file another user owns")
    mod = plugin_module()
    path = default_file(home, "[DEFAULT]\nload = %s\n" % mod.name)
    os.chown(path, 65534, 65534)  # nobody
    status, _, err = go(capsys, "plugins")
    assert status == 2 and "another user owns it" in err and not mod.imported
    status, report, _ = listed(capsys, "-c", path)
    assert status == 0 and names(report) == [mod.name]


def test_a_default_file_the_user_owns_is_read(home, plugin_module, capsys):
    mod = plugin_module()
    default_file(home, "[DEFAULT]\nload = %s\n" % mod.name)
    status, report, _ = listed(capsys)
    assert status == 0 and names(report) == [mod.name]


def test_naming_a_file_makes_the_users_own_moot():
    commands = {"capture", "convert"}
    assert _settings.names_a_file(["-c", "x", "convert"], commands)
    assert _settings.names_a_file(["--config=x", "convert"], commands)
    assert _settings.names_a_file(["--conf", "x", "convert"], commands)
    assert _settings.names_a_file(["-cx", "convert"], commands)
    assert not _settings.names_a_file(["-v", "convert", "-c", "x"], commands)
    assert not _settings.names_a_file([], commands)


def test_the_variable_makes_the_users_own_file_moot(monkeypatch):
    monkeypatch.setenv("PKTCAP_CONFIG", os.path.abspath("x.ini"))
    assert _settings.choose_default([], {"convert"}) is None
    monkeypatch.delenv("PKTCAP_CONFIG")
    assert _settings.choose_default([], {"convert"}) == str(_settings.default_path())
    assert _settings.choose_default(["-c", "x"], {"convert"}) is None
    _settings.forget()


def test_a_run_leaves_no_state_behind(home, plugin_module, capsys):
    mod = plugin_module()
    default_file(home, "[DEFAULT]\nload = %s\n" % mod.name)
    assert main(["plugins"]) == 0
    capsys.readouterr()
    assert Pktcap._config_ is None and _settings.file_read() is None


# -- a served tree is given no settings file ------------------------------------


def test_a_served_tree_is_given_no_default_file(home, monkeypatch):
    monkeypatch.setenv("PKTCAP_MCP", "stdio")
    assert _settings.choose_default([], {"convert"}) is None
    monkeypatch.setenv("PKTCAP_MCP", " ")
    assert _settings.choose_default([], {"convert"}) is not None
    _settings.forget()


def _serve(requests, env):
    done = subprocess.run(
        [sys.executable, "-m", "pktcap"],
        input="".join(json.dumps(r) + "\n" for r in requests),
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return {r["id"]: r for r in map(json.loads, done.stdout.splitlines())}


def _call(identifier, name, arguments):
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def test_the_real_server_reads_neither_the_users_file_nor_the_variables(
    home, tmp_path, trace, plugin_module
):
    """The file would make ``convert`` write text and load a plugin; the
    answers are JSON records of a capture read with no plugin."""
    mod = plugin_module()
    text = "[DEFAULT]\nload = %s\n[convert]\nformat = text\n" % mod.name
    default_file(home, text)
    named = written(tmp_path, "named.ini", text)
    env = dict(os.environ, PKTCAP_MCP="stdio", PKTCAP_CONFIG=str(named))
    env.update(
        PYTHONPATH=str(mod.directory), APPDATA=str(home), XDG_CONFIG_HOME=str(home)
    )
    env.pop("PKTCAP_LOAD", None)
    arguments = {"input": str(trace), "limit": 1}
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        _call(2, "pktcap.convert", arguments),
        _call(3, "pktcap.convert", dict(arguments, config=str(named))),
        _call(4, "pktcap.convert", dict(arguments, load=[mod.name])),
        _call(5, "pktcap.plugins", {}),
    ]
    replies = _serve(requests, env)
    for identifier in (2, 3):
        body = replies[identifier]["result"]["content"][0]["text"]
        assert json.loads(body)["layers"][0]["layer"] == "ethernet"
    assert "cannot name plugins" in json.dumps(replies[4])
    listing = replies[5]["result"]["content"][0]["text"]
    assert "configuration: none" in listing and "plugins: none" in listing
    assert not mod.imported


def test_a_tool_call_that_names_config_reads_no_file(tmp_path, trace):
    path = written(tmp_path, "s.ini", "[convert]\nformat = text\n")
    result = call_tool(
        Pktcap, "pktcap.convert", {"input": str(trace), "limit": 1, "config": str(path)}
    )
    assert not result.get("isError")
    assert json.loads(result["content"][0]["text"])["layers"]


# -- no command declares a configuration option ---------------------------------


def test_no_command_class_declares_a_configuration_option(capsys):
    from pktcap.cli import Loading, Selecting, Writing

    for command in (Loading, Selecting, Writing, Capture, Convert, Replay, Plugins):
        fields = {builder.name for builder in command._getargs_()}
        assert not fields & {"config", "plugin_config"}, command.__name__
    status, out, _ = go(capsys, "--help")
    assert status == 0 and "--config" in out and "-c" in out
    status, out, _ = go(capsys, "convert", "--help")
    assert status == 0 and "--config" not in out and "-c FILE" not in out


# -- a subclass narrows the layers the list may come from --------------------------


class NarrowConvert(Convert):
    _parsername_ = "convert"
    _load_from_ = ("argument",)


class TakesConvert(Convert):
    _parsername_ = "convert"


def _root(command):
    return type("Root", (Pktcap,), {"_subcommands_": [command]})


def _status(root, argv):
    try:
        run(root, argv)
    except SystemExit as stop:
        return stop.code
    except ValueError:
        return 2
    return 0


def test_a_class_that_narrows_the_layers_refuses_the_files_list_and_the_default_takes_it(
    tmp_path, plugin_module, trace, capsys
):
    mod = plugin_module()
    path = written(tmp_path, "s.toml", 'load = ["%s"]\n' % mod.name)
    argv = ["-c", str(path), "convert", "-i", str(trace), "-f", "demo.opcode=1"]
    assert _status(_root(NarrowConvert), argv) == 2
    assert "--load was set from the file layer" in str(
        pytest.raises(ValueError, run, _root(NarrowConvert), argv).value
    )
    assert not mod.imported
    assert _status(_root(TakesConvert), argv) == 0
    assert mod.imported
    assert len(capsys.readouterr().out.splitlines()) == 1
