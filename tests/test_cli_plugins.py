"""The commands load plugins into a registry of their own, and ``pktcap plugins``.

The plugin module is written by the test (``plugin_module``): a layer named
``demo`` and a dissector on UDP 9999. The trust tests run a child process whose
working directory, capture and environment are all hostile, and look for the
marker file the plugin writes when it is imported.
"""

import json
import os
import socket
import struct
import subprocess
import sys

import pytest

pytest.importorskip("duho")

import captures as build  # noqa: E402
from duho.mcp import call_tool, describe_tools  # noqa: E402
from pktcap import default_registry  # noqa: E402
from pktcap.cli import main  # noqa: E402
from pktcap.cli._root import Pktcap  # noqa: E402
from test_live import _read, packet_socket  # noqa: E402,F401


def frame(payload, port=9999):
    return build.ethernet(
        build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, port, payload))
    )


BOOT, LEASE, OTHER = frame(b"\x01boot"), frame(b"\x02lease"), frame(b"query", 53)


@pytest.fixture
def trace(tmp_path):
    path = tmp_path / "trace.pcap"
    path.write_bytes(build.pcap([BOOT, LEASE, OTHER]))
    return path


@pytest.fixture
def config_home(tmp_path, monkeypatch):
    """The user's configuration directory, by this platform's variable."""
    base = tmp_path / "config-home"
    base.mkdir()
    monkeypatch.delenv("PKTCAP_CONFIG")
    monkeypatch.setenv("APPDATA" if os.name == "nt" else "XDG_CONFIG_HOME", str(base))
    return base


def records(text):
    return [json.loads(line) for line in text.splitlines()]


def convert(trace, *extra):
    return ["convert", "-i", str(trace), "--format", "json", *extra]


def test_an_option_loads_the_plugin_and_its_keys_select_its_frames(
    trace, plugin_module, capsys
):
    mod = plugin_module()
    before = default_registry().selectors()
    argv = convert(trace, "--load", mod.name, "-f", "demo.opcode=1")
    assert main(argv) == 0
    out, err = capsys.readouterr()
    (record,) = records(out)
    assert record["layers"][-1] == {"layer": "demo", "opcode": 1, "name": "boot"}
    assert "1 frames read" not in err and "3 frames read, 1 written" in err
    assert default_registry().selectors() == before
    assert default_registry().layers() == {}


def test_the_bare_layer_name_and_proto_work_too(trace, plugin_module, capsys):
    mod = plugin_module()
    assert main(convert(trace, "--load", mod.name, "-f", "proto=demo")) == 0
    assert len(records(capsys.readouterr().out)) == 2


def test_the_variable_and_the_file_give_the_same_output(
    trace, plugin_module, config_home, monkeypatch, capsys, tmp_path
):
    mod = plugin_module()
    argv = convert(trace, "-f", "demo.opcode=1")
    assert main(convert(trace, "--load", mod.name, "-f", "demo.opcode=1")) == 0
    by_option = capsys.readouterr().out

    monkeypatch.setenv("PKTCAP_LOAD", mod.name)
    assert main(argv) == 0
    assert capsys.readouterr().out == by_option
    monkeypatch.delenv("PKTCAP_LOAD")

    (config_home / "pktcap").mkdir()
    (config_home / "pktcap" / "pktcap.ini").write_text(
        "[pktcap]\nload = %s\n" % mod.name, encoding="utf-8"
    )
    assert main(argv) == 0
    assert capsys.readouterr().out == by_option

    named = tmp_path / "named.ini"
    named.write_text("[pktcap]\nload = %s\n" % mod.name, encoding="utf-8")
    for flag in ("--config", "-c"):
        assert main(convert(trace, flag, str(named), "-f", "demo.opcode=1")) == 0
        assert capsys.readouterr().out == by_option
    monkeypatch.setenv("PKTCAP_CONFIG", str(named))
    (config_home / "pktcap" / "pktcap.ini").unlink()
    assert main(argv) == 0
    assert capsys.readouterr().out == by_option


def test_none_over_the_variable_or_the_file_leaves_the_key_unknown(
    trace, plugin_module, config_home, monkeypatch, capsys
):
    mod = plugin_module()
    argv = convert(trace, "--load", "none", "-f", "demo.opcode=1")
    monkeypatch.setenv("PKTCAP_LOAD", mod.name)
    assert main(argv) == 2
    assert "unknown filter key 'demo.opcode'" in capsys.readouterr().err
    monkeypatch.delenv("PKTCAP_LOAD")
    (config_home / "pktcap").mkdir()
    (config_home / "pktcap" / "pktcap.ini").write_text(
        "[pktcap]\nload = %s\n" % mod.name, encoding="utf-8"
    )
    assert main(argv) == 2
    assert main(convert(trace, "--config", "none", "-f", "demo.opcode=1")) == 2
    assert not mod.imported


def test_a_name_that_does_not_import_is_one_line_and_nothing_is_written(
    trace, tmp_path, capsys, monkeypatch
):
    out = tmp_path / "out.jsonl"
    assert main(convert(trace, "--load", "pydemo.captur", "-o", str(out))) == 2
    err = capsys.readouterr().err.strip().splitlines()
    assert err == [
        "pktcap: error: the plugins argument names 'pydemo.captur': no module of that name"
    ]
    assert not out.exists()
    monkeypatch.setenv("PKTCAP_LOAD", "pydemo.captur")
    assert main(convert(trace, "-o", str(out))) == 2
    assert capsys.readouterr().err.strip() == (
        "pktcap: error: PKTCAP_LOAD names 'pydemo.captur': no module of that name"
    )
    assert not out.exists()


def test_a_named_file_that_is_missing_is_status_1(trace, tmp_path, capsys):
    assert main(convert(trace, "-c", str(tmp_path / "missing.ini"))) == 1
    assert capsys.readouterr().err.startswith("pktcap: error: ")


def test_a_malformed_file_is_status_2_with_its_path_and_line(trace, tmp_path, capsys):
    bad = tmp_path / "bad.ini"
    bad.write_text("[pktcap]\nnonsense\n", encoding="utf-8")
    assert main(convert(trace, "--config", str(bad))) == 2
    assert capsys.readouterr().err.startswith("pktcap: error: %s:2: " % bad)


def test_replay_sends_only_the_datagrams_the_plugin_key_selects(
    trace, plugin_module, capsys
):
    mod = plugin_module()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)
    try:
        to = "127.0.0.1:%d" % sock.getsockname()[1]
        argv = ["replay", "-i", str(trace), "--to", to, "--no-delay", "--json"]
        assert main(argv + ["--load", mod.name, "-f", "demo.opcode=2"]) == 0
        assert json.loads(capsys.readouterr().out) == {"sent": 1, "partial": 0}
        assert sock.recvfrom(2048)[0] == b"\x02lease"
        sock.settimeout(0.2)
        with pytest.raises(socket.timeout):
            sock.recvfrom(2048)
    finally:
        sock.close()


def test_capture_takes_a_plugin_key(packet_socket, plugin_module, capsys):
    mod = plugin_module()
    ip = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 9999, b"\x01boot"))
    other = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 9999, b"\x02lease"))
    packet_socket(_read(ip, 0x0800), _read(other, 0x0800))
    argv = ["capture", "--count", "1", "--format", "json", "--load", mod.name]
    assert main(argv + ["-f", "demo.opcode=2"]) == 0
    (record,) = records(capsys.readouterr().out)
    assert record["layers"][-1]["name"] == "lease"


def test_dash_c_is_the_configuration_file_on_every_command_and_count_has_no_short_flag():
    from pktcap.cli.capture import Capture
    from pktcap.cli.convert import Convert
    from pktcap.cli.plugins import Plugins
    from pktcap.cli.replay import Replay

    for command in (Capture, Convert, Replay, Plugins):
        owners = {
            option: action.dest
            for action in command._parser_()._actions
            for option in action.option_strings
        }
        assert owners["-c"] == owners["--config"] == "config", command.__name__
    assert "-c" not in [
        o
        for a in Capture._parser_()._actions
        if a.dest == "count"
        for o in a.option_strings
    ]


# -- pktcap plugins ------------------------------------------------------------


def test_the_plugins_command_lists_what_was_loaded(plugin_module, capsys):
    mod = plugin_module()
    assert main(["plugins", "--load", mod.name, "-c", "none"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "configuration: none"
    assert lines[1] == "plugins: 1 from argument"
    assert lines[2] == "  %s: udp 9999; layer demo" % mod.name
    assert lines[3].startswith("keys: dport, dst, host,")
    assert lines[4].startswith("layers: demo, ethernet,")
    assert len(lines) == 5


def test_the_plugins_command_says_when_the_file_is_absent_and_nothing_is_loaded(
    config_home, capsys
):
    assert main(["plugins"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "configuration: %s (absent)" % (
        config_home / "pktcap" / "pktcap.ini"
    )
    assert lines[1] == "plugins: none"


def test_the_plugins_command_names_the_file_when_it_is_there(
    plugin_module, config_home, capsys
):
    mod = plugin_module()
    path = config_home / "pktcap" / "pktcap.ini"
    path.parent.mkdir()
    path.write_text("[pktcap]\nload = %s\n" % mod.name, encoding="utf-8")
    assert main(["plugins"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "configuration: %s" % path
    assert lines[1] == "plugins: 1 from %s" % path


def test_the_plugins_command_prints_one_layers_keys(plugin_module, capsys):
    mod = plugin_module()
    assert main(["plugins", "--load", mod.name, "--layer", "demo"]) == 0
    assert capsys.readouterr().out.splitlines() == ["demo.name", "demo.opcode"]
    assert main(["plugins", "--layer", "IPV4"]) == 0
    assert "ipv4.ttl" in capsys.readouterr().out.splitlines()
    assert main(["plugins", "--layer", "demo"]) == 2
    err = capsys.readouterr().err
    assert "no layer named 'demo'" in err and "ipv4" in err


def test_the_plugins_command_prints_json(plugin_module, capsys):
    mod = plugin_module()
    assert main(["plugins", "--json", "--load", mod.name]) == 0
    report = json.loads(capsys.readouterr().out)
    assert set(report) == {"configuration", "plugins", "keys"}
    assert report["plugins"] == [
        {
            "name": mod.name,
            "source": "argument",
            "selectors": [["udp", 9999]],
            "layers": ["demo"],
        }
    ]
    assert "demo.opcode" in report["keys"] and "ipv4.ttl" in report["keys"]
    assert main(["plugins", "--json", "-c", "none"]) == 0
    assert json.loads(capsys.readouterr().out)["configuration"] is None


# -- a tool call names neither plugins nor a file ---------------------------------


def test_the_tools_served_are_convert_and_plugins():
    assert [tool["name"] for tool in describe_tools(Pktcap)] == [
        "pktcap.convert",
        "pktcap.plugins",
    ]


@pytest.mark.parametrize("command", ["pktcap.convert", "pktcap.plugins"])
@pytest.mark.parametrize(
    "field, value",
    [("plugins", ["NAME"]), ("config", "FILE")],
    ids=["plugins", "config"],
)
def test_a_tool_call_that_names_plugins_or_a_file_is_refused_and_imports_nothing(
    command, field, value, trace, plugin_module, tmp_path
):
    mod = plugin_module()
    named = tmp_path / "named.ini"
    named.write_text("[pktcap]\nload = %s\n" % mod.name, encoding="utf-8")
    value = [mod.name] if field == "plugins" else str(named)
    arguments = {field: value}
    if command == "pktcap.convert":
        arguments["input"] = str(trace)
    result = call_tool(Pktcap, command, arguments)
    assert result["isError"] is True
    assert "PKTCAP_LOAD" in result["content"][0]["text"]
    assert not mod.imported


def test_a_tool_call_loads_what_the_servers_own_variable_names(
    trace, plugin_module, monkeypatch
):
    mod = plugin_module()
    monkeypatch.setenv("PKTCAP_LOAD", mod.name)
    result = call_tool(
        Pktcap, "pktcap.convert", {"input": str(trace), "filter": "demo.opcode=1"}
    )
    assert not result.get("isError")
    (record,) = records(result["content"][0]["text"])
    assert record["layers"][-1]["name"] == "boot"
    listing = call_tool(Pktcap, "pktcap.plugins", {})
    assert "plugins: 1 from PKTCAP_LOAD" in listing["content"][0]["text"]


def test_the_real_server_answers_a_filter_with_the_servers_variable(
    trace, plugin_module, tmp_path
):
    mod = plugin_module()
    env = dict(
        os.environ,
        PKTCAP_MCP="stdio",
        PKTCAP_LOAD=mod.name,
        PYTHONPATH=str(mod.directory),
    )
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
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "pktcap.convert",
                "arguments": {"input": str(trace), "filter": "demo.opcode=1"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "pktcap.convert",
                "arguments": {"input": str(trace), "plugins": [mod.name]},
            },
        },
    ]
    done = subprocess.run(
        [sys.executable, "-m", "pktcap"],
        input="".join(json.dumps(r) + "\n" for r in requests),
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    replies = {r["id"]: r for r in map(json.loads, done.stdout.splitlines())}
    text = replies[2]["result"]["content"][0]["text"]
    assert json.loads(text)["layers"][-1]["name"] == "boot"
    refused = replies[3]
    flat = json.dumps(refused)
    assert "PKTCAP_LOAD" in flat and "cannot name plugins" in flat


# -- the working directory, a capture and a file name name nothing ----------------


def test_nothing_a_capture_or_its_directory_holds_is_imported(plugin_module, tmp_path):
    """The marker plugin is importable (PYTHONPATH) and named by every file the
    working directory has and by the capture's own contents and name; none of
    them is a place a list is read from, so it is never imported."""
    mod = plugin_module()
    work = tmp_path / "work"
    (work / "pktcap").mkdir(parents=True)
    line = "[pktcap]\nload = %s\n" % mod.name
    for name in ("pktcap.ini", ".pktcap.ini", ".pkcap.ini", "pktcap/pktcap.ini"):
        (work / name).write_text(line, encoding="utf-8")
    (work / "setup.cfg").write_text(line + "[tool:pytest]\n", encoding="utf-8")
    (work / "pyproject.toml").write_text(
        '[tool.pktcap]\nload = ["%s"]\n' % mod.name, encoding="utf-8"
    )
    name = mod.name.encode()
    payload = frame(b"PKTCAP_LOAD=" + name + b"\n[pktcap]\nload = " + name)
    capture = work / (mod.name + ".pcap")
    capture.write_bytes(build.pcap([payload, frame(b"x" + name)]))
    empty = tmp_path / "empty"
    empty.mkdir()
    env = dict(
        os.environ,
        PYTHONPATH=str(mod.directory),
        APPDATA=str(empty),
        XDG_CONFIG_HOME=str(empty),
        HOME=str(empty),
        USERPROFILE=str(empty),
    )
    env.pop("PKTCAP_LOAD", None)
    env.pop("PKTCAP_CONFIG", None)  # so the user's own, empty, directory is read
    for argv in (
        [
            sys.executable,
            "-m",
            "pktcap",
            "convert",
            "-i",
            str(capture),
            "-f",
            "port=9999",
        ],
        [
            sys.executable,
            "-c",
            "from pktcap.cli import main; raise SystemExit(main(['convert', '-i', %r]))"
            % str(capture),
        ],
    ):
        done = subprocess.run(
            argv, cwd=str(work), env=env, capture_output=True, text=True, timeout=120
        )
        assert done.returncode == 0, done.stderr[-2000:]
        assert "demo" not in done.stdout.replace(mod.name, "")
    assert not mod.imported


def test_the_plugin_name_in_a_pcapng_comment_and_a_file_name_is_not_imported(
    plugin_module, tmp_path
):
    mod = plugin_module()
    work = tmp_path / "work"
    work.mkdir()
    name = mod.name.encode()
    raw = frame(b"boot")
    # An enhanced packet block whose opt_comment option holds the plugin's name.
    body = struct.pack("<IIIII", 0, 0, 1_000_000, len(raw), len(raw)) + raw
    body += b"\0" * (-len(raw) % 4)
    body += struct.pack("<HH", 1, len(name)) + name + b"\0" * (-len(name) % 4)
    body += struct.pack("<HH", 0, 0)
    capture = work / ("%s.pcapng" % mod.name)
    capture.write_bytes(build.section() + build.interface() + build.block(6, body))
    empty = tmp_path / "empty"
    empty.mkdir()
    env = dict(
        os.environ,
        PYTHONPATH=str(mod.directory),
        APPDATA=str(empty),
        XDG_CONFIG_HOME=str(empty),
        HOME=str(empty),
        USERPROFILE=str(empty),
    )
    env.pop("PKTCAP_LOAD", None)
    env.pop("PKTCAP_CONFIG", None)
    done = subprocess.run(
        [sys.executable, "-m", "pktcap", "convert", "-i", str(capture)],
        cwd=str(work),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert json.loads(done.stdout.splitlines()[0])["length"] == len(raw)
    assert not mod.imported
