"""Where a hook and a plugin list may come from.

A library that serves the commands from a root of its own can give the root a
settings file or a variable, and duho applies those to every declared field.
A hook command and a plugin list run code, so they come from the command line
alone unless a subclass says more (``Capture._hook_from_``), and the plugin list
never comes from a root's layers.
"""

from typing import Annotated, Optional

import pytest

pytest.importorskip("duho")

from duho import Cli, LoggingArgs, Meta, main as run  # noqa: E402
from duho.mcp import call_tool  # noqa: E402

from pktcap.cli import Capture  # noqa: E402
from pktcap.cli._root import Pktcap  # noqa: E402
from test_cli_listen import listen_and_send  # noqa: E402

HOOK = """
import pathlib
def ran(frame):
    pathlib.Path(__file__).with_name("hook-ran.txt").write_text("ran")
"""
PLUGIN = """
import pathlib
pathlib.Path(__file__).with_name("plugin-imported.txt").write_text("imported")
def pktcap_plugin(registry):
    pass
"""
SHORT = ["--duration", "3"]
LISTEN = ["capture", "--listen", "127.0.0.1:0", "--count", "1"]


def outcome(root, argv):
    """``(status, the one line the root would print)``, as ``main`` maps them."""
    try:
        status = run(root, argv)
    except SystemExit as stop:
        return stop.code, ""
    except ValueError as exc:
        return 2, str(exc)
    return (0 if status is None else status), ""


def root_of(command, config=None):
    attributes = {"_parsername_": "root", "_subcommands_": [command]}
    if config is not None:
        attributes["_config_"] = str(config)
    return type("Root", (LoggingArgs, Cli), attributes)


@pytest.fixture
def modules(plugin_module):
    hook = plugin_module(HOOK)
    plugin = plugin_module(PLUGIN)
    return hook, plugin


def settings(tmp_path, hook, plugin, *, hook_line=True, plugin_line=True):
    lines = ["[capture]"]
    if hook_line:
        lines.append('hook = "%s:ran"' % hook.name)
    if plugin_line:
        lines.append('plugins = ["%s"]' % plugin.name)
    path = tmp_path / "root-settings.toml"
    path.write_bytes(("\n".join(lines) + "\n").encode("ascii"))
    return path


def test_a_hook_from_a_roots_settings_file_is_refused_before_anything_is_bound(
    modules, tmp_path, caplog
):
    hook, plugin = modules
    root = root_of(Capture, settings(tmp_path, hook, plugin, plugin_line=False))
    status, line = outcome(root, LISTEN + SHORT + ["-v"])
    assert status == 2
    assert "--hook" in line and "file" in line and "argument" in line
    assert not (hook.directory / "hook-ran.txt").exists()
    assert "listening on" not in caplog.text


def test_a_plugin_list_from_a_roots_settings_file_is_refused_and_not_imported(
    modules, tmp_path
):
    hook, plugin = modules
    root = root_of(Capture, settings(tmp_path, hook, plugin, hook_line=False))
    status, line = outcome(root, LISTEN + SHORT)
    assert status == 2
    assert "--load" in line and "PKTCAP_LOAD" in line and "file" in line
    assert (
        not plugin.imported and not (plugin.directory / "plugin-imported.txt").exists()
    )


def test_the_reviewers_root_runs_neither_and_names_the_layer(modules, tmp_path):
    hook, plugin = modules
    root = root_of(Capture, settings(tmp_path, hook, plugin))
    status, line = outcome(root, LISTEN + SHORT)
    assert status == 2 and "file" in line
    assert not (hook.directory / "hook-ran.txt").exists()
    assert not (plugin.directory / "plugin-imported.txt").exists()


class FromVariable(Capture):
    """A command with a variable of its own for the hook and the plugin list."""

    _parsername_ = "capture"

    hook: Annotated[Optional[str], Meta(env="ORIGIN_TEST_HOOK")] = None
    "the hook, from a variable too"
    ("--hook",)

    plugins: Annotated[Optional[list], Meta(env="ORIGIN_TEST_PLUGINS")] = None
    "the plugins, from a variable too"
    ("--load",)


def test_a_hook_from_a_variable_a_root_reads_is_refused(modules, monkeypatch, caplog):
    hook, _ = modules
    monkeypatch.setenv("ORIGIN_TEST_HOOK", "%s:ran" % hook.name)
    status, line = outcome(root_of(FromVariable), LISTEN + SHORT)
    assert status == 2
    assert "environment" in line and "--hook" in line
    assert not (hook.directory / "hook-ran.txt").exists()


def test_a_plugin_list_from_a_variable_a_root_reads_is_refused(modules, monkeypatch):
    _, plugin = modules
    monkeypatch.setenv("ORIGIN_TEST_PLUGINS", plugin.name)
    status, line = outcome(root_of(FromVariable), LISTEN + SHORT)
    assert status == 2 and "environment" in line
    assert not (plugin.directory / "plugin-imported.txt").exists()


class FromFile(Capture):
    """A library that has a settings file the user names and says so."""

    _parsername_ = "capture"
    _hook_from_ = ("argument", "file")


def test_a_subclass_can_take_the_hook_from_a_file_and_still_not_the_plugins(
    modules, tmp_path, caplog
):
    hook, plugin = modules
    both = settings(tmp_path, hook, plugin)
    status, line = outcome(root_of(FromFile, both), LISTEN + SHORT)
    assert status == 2 and "--load" in line  # the plugin list is still refused
    assert not (plugin.directory / "plugin-imported.txt").exists()
    only_hook = settings(tmp_path, hook, plugin, plugin_line=False)
    status, _ = listen_and_send(
        LISTEN + SHORT,
        caplog,
        [b"a"],
        runner=lambda argv: outcome(root_of(FromFile, only_hook), argv)[0],
    )
    assert status == 0
    assert (hook.directory / "hook-ran.txt").exists()


def test_the_default_allows_the_argument_alone():
    assert Capture._hook_from_ == ("argument",)


def test_the_argument_works_whatever_the_file_says(modules, tmp_path, caplog):
    hook, plugin = modules
    root = root_of(Capture, settings(tmp_path, hook, plugin, plugin_line=False))
    argv = LISTEN + SHORT + ["--hook", "%s:ran" % hook.name]
    status, _ = listen_and_send(
        argv, caplog, [b"a"], runner=lambda argv: outcome(root, argv)[0]
    )
    assert status == 0
    assert (hook.directory / "hook-ran.txt").exists()


def test_the_argument_works_for_the_plugin_list_whatever_the_file_says(
    modules, tmp_path
):
    hook, plugin = modules
    root = root_of(Capture, settings(tmp_path, hook, plugin, hook_line=False))
    argv = ["capture", "--listen", "127.0.0.1:0", "--count", "0", "--load", plugin.name]
    assert outcome(root, argv) == (0, "")
    assert (plugin.directory / "plugin-imported.txt").exists()


def test_a_tool_call_cannot_name_append(tmp_path):
    cap = tmp_path / "in.pcap"
    from pktcap import PcapWriter

    writer = PcapWriter(str(cap))
    writer.write(1.0, ("10.0.0.5", 5), ("10.0.0.1", 9999), b"hello")
    writer.close()
    target = tmp_path / "existing.txt"
    target.write_bytes(b"existing\n")
    result = call_tool(
        Pktcap,
        "pktcap.convert",
        {"input": str(cap), "output": str(target), "format": "text", "append": True},
    )
    assert result["isError"] is True
    assert "append" in result["content"][0]["text"]
    assert target.read_bytes() == b"existing\n"
    plain = call_tool(Pktcap, "pktcap.convert", {"input": str(cap), "format": "text"})
    assert plain.get("isError") is not True


def test_the_origin_of_a_field_nobody_parsed_is_the_argument():
    command = Capture(hook="x:y")
    assert command._origin("hook") == "argument"
