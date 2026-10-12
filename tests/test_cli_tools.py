"""``convert`` served as a tool, and ``capture`` and ``replay`` not served.

``duho.mcp.call_tool`` runs a tool in process, with standard output captured as
text; one test drives the real server over pipes with ``PKTCAP_MCP=stdio``.
"""

import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("duho")

import captures as build  # noqa: E402
from duho.mcp import UnknownToolError, call_tool, describe_tools  # noqa: E402
from pktcap import read_frames  # noqa: E402
from pktcap.cli._root import Pktcap  # noqa: E402

FRAME = build.ethernet(build.ipv4("10.0.0.5", "10.0.0.1", build.udp(68, 67, b"x")))


@pytest.fixture
def trace(tmp_path):
    path = tmp_path / "trace.pcap"
    path.write_bytes(build.pcap([FRAME, FRAME, FRAME]))
    return path


def test_the_tools_served_are_convert_and_plugins_alone():
    names = [tool["name"] for tool in describe_tools(Pktcap)]
    assert names == ["pktcap.convert", "pktcap.plugins"]
    for name in ("pktcap.capture", "pktcap.replay"):
        with pytest.raises(UnknownToolError):
            call_tool(Pktcap, name, {})


def test_every_field_of_the_tool_says_what_it_is_and_what_omitting_it_means():
    (tool,) = [t for t in describe_tools(Pktcap) if t["name"] == "pktcap.convert"]
    properties = tool["inputSchema"]["properties"]
    assert tool["inputSchema"]["required"] == ["input"]
    own = set(properties) - {"loglevels", "verbose", "quiet", "config", "--"}
    assert own == {
        "filter",
        "output",
        "format",
        "per_record",
        "max_files",
        "datagrams",
        "input",
        "limit",
        "load",
        "append",
    }
    for name in own:
        assert properties[name]["description"], name


def test_a_call_converts_a_capture_and_the_records_are_the_result(trace):
    result = call_tool(Pktcap, "pktcap.convert", {"input": str(trace), "limit": 2})
    assert "isError" not in result or not result["isError"]
    (item,) = result["content"]
    records = [json.loads(line) for line in item["text"].splitlines()]
    assert len(records) == 2
    assert [layer["layer"] for layer in records[0]["layers"]] == [
        "ethernet",
        "ipv4",
        "udp",
    ]


def test_a_call_may_write_a_capture_to_the_file_it_names(trace, tmp_path):
    out = tmp_path / "out.pcapng"
    result = call_tool(
        Pktcap, "pktcap.convert", {"input": str(trace), "output": str(out)}
    )
    assert not result.get("isError")
    assert [f.data for f in read_frames(out)] == [FRAME] * 3


@pytest.mark.parametrize("name", ["pcap", "pcapng"])
def test_capture_octets_are_never_returned_as_text(name, trace):
    result = call_tool(Pktcap, "pktcap.convert", {"input": str(trace), "format": name})
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "--output" in text and name in text


def test_standard_input_is_refused_naming_the_option(trace):
    result = call_tool(Pktcap, "pktcap.convert", {"input": "-"})
    assert result["isError"] is True
    assert "--input" in result["content"][0]["text"]


def test_a_bad_filter_is_an_error_result_not_a_crash(trace):
    result = call_tool(
        Pktcap, "pktcap.convert", {"input": str(trace), "filter": "colour=red"}
    )
    assert result["isError"] is True and "colour" in result["content"][0]["text"]


def test_the_server_over_a_pipe_lists_convert_and_converts(trace):
    env = dict(os.environ, PKTCAP_MCP="stdio")
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
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "pktcap.convert",
                "arguments": {"input": str(trace), "limit": 1},
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
    assert [t["name"] for t in replies[2]["result"]["tools"]] == [
        "pktcap.convert",
        "pktcap.plugins",
    ]
    text = replies[3]["result"]["content"][0]["text"]
    assert json.loads(text)["linktype"] == 1


# -- how a command tells that it is a tool call -------------------------------------
#
# Loading.served() answers true when standard output is a stream with no
# `buffer`. That is what duho 0.7.2 does to run a tool (a StringIO in place of
# standard output) and not something it documents. These two tests hold the
# answer in each kind of call, and the property it is read from, against the
# installed duho; both are replaced by duho's own call when a release publishes
# one and the floor of the `cli` extra moves to it.


@pytest.fixture
def probed(monkeypatch):
    """What `plugins` saw when it ran: whether it was served, and whether the
    standard output it was given had a `buffer`."""
    from pktcap.cli import Plugins

    seen = []
    original = Plugins.__call__

    def probe(self):
        seen.append((self.served(), getattr(sys.stdout, "buffer", None) is not None))
        return original(self)

    monkeypatch.setattr(Plugins, "__call__", probe)
    return seen


def test_served_is_true_in_a_tool_call_and_false_on_the_command_line(probed):
    from pktcap.cli import main

    result = call_tool(Pktcap, "pktcap.plugins", {})
    assert not result.get("isError")
    assert probed == [(True, False)]
    assert main(["plugins"]) == 0
    assert probed[1] == (False, True)


def test_duho_runs_a_tool_with_standard_output_that_has_no_buffer(probed):
    # Fails the day duho gives a tool a standard output with a `buffer`, or a
    # command line one without: `served()` would then answer wrongly.
    call_tool(Pktcap, "pktcap.plugins", {})
    _, had_buffer = probed[0]
    assert had_buffer is False
    from duho import main as run

    run(Pktcap, ["plugins"])
    assert probed[1][1] is True


# -- a duho that publishes running_mode() ----------------------------------------------


@pytest.mark.parametrize(
    "mode, buffered, served",
    [("mcp", True, True), ("cli", False, False), ("mcp", False, True)],
)
def test_served_follows_running_mode_and_ignores_standard_output(
    mode, buffered, served, monkeypatch
):
    import io

    from pktcap.cli import Plugins

    monkeypatch.setattr("pktcap.cli._common._running_mode", lambda: mode, raising=False)
    stream = io.TextIOWrapper(io.BytesIO()) if buffered else io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    assert Plugins.served(object()) is served
