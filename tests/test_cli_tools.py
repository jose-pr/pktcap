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


def test_the_tools_served_are_convert_alone():
    assert [tool["name"] for tool in describe_tools(Pktcap)] == ["pktcap.convert"]
    for name in ("pktcap.capture", "pktcap.replay"):
        with pytest.raises(UnknownToolError):
            call_tool(Pktcap, name, {})


def test_every_field_of_the_tool_says_what_it_is_and_what_omitting_it_means():
    (tool,) = describe_tools(Pktcap)
    properties = tool["inputSchema"]["properties"]
    assert tool["inputSchema"]["required"] == ["input"]
    own = set(properties) - {"loglevels", "verbose", "quiet", "--"}
    assert own == {
        "filter",
        "output",
        "format",
        "per_record",
        "max_files",
        "datagrams",
        "input",
        "limit",
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
    assert [t["name"] for t in replies[2]["result"]["tools"]] == ["pktcap.convert"]
    text = replies[3]["result"]["content"][0]["text"]
    assert json.loads(text)["linktype"] == 1
