"""The README is in the standard shape and its examples run.

Every Python block of "Quick start" is executed, in order, in one namespace
and in an empty directory, so a renamed function or a changed result fails
here and not in a reader's terminal. Nothing leaves the host: the one example
that sends does so to a loopback socket it binds itself.
"""

import json
import pathlib
import re
import socket

import pktcap

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"
TEXT = README.read_text(encoding="utf-8")

SECTIONS = [
    "Features",
    "Installation",
    "Quick start",
    "API overview",
    "Differences from tshark",
    "Development",
    "License",
]


def _section(heading):
    start = TEXT.index("\n## %s\n" % heading)
    end = TEXT.find("\n## ", start + 1)
    return TEXT[start : end if end != -1 else None]


def test_the_sections_are_the_standard_ones_in_the_standard_order():
    assert re.findall(r"^## (.+)$", TEXT, re.MULTILINE) == SECTIONS


def test_the_badge_row_is_the_standard_five_in_order():
    badges = re.findall(r"^\[!\[([^\]]+)\]", TEXT, re.MULTILINE)
    assert badges == ["Version", "Python versions", "License: MIT", "Docs", "CI"]
    assert TEXT.startswith("# pktcap\n\n[![Version]")


def test_every_link_is_absolute():
    links = re.findall(r"\]\(([^)]+)\)", TEXT)
    assert links and all(link.startswith("https://") for link in links)


def test_the_overview_names_exactly_the_public_names():
    named = set(re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", _section("API overview")))
    assert named - {"pktcap"} == set(pktcap.__all__)


def test_the_quick_start_examples_run(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    blocks = re.findall(r"```python\n(.*?)```", _section("Quick start"), re.DOTALL)
    assert len(blocks) == 5
    namespace = {"__name__": "readme_example"}
    try:
        for block in blocks:
            exec(compile(block, "README.md", "exec"), namespace)
    finally:
        for value in namespace.values():
            if isinstance(value, socket.socket):
                value.close()
    out = capsys.readouterr().out
    assert "192.0.2.5 50000 -> 192.0.2.1 69 b'\\x00\\x01boot.efi" in out
    assert "TFTPLayer(opcode=1, filename='boot.efi')" in out
    assert "DissectStats(frames=3, malformed=0, failed=0, unsupported=0" in out
    assert "1700000000.05 ('192.0.2.1', 40000) ('192.0.2.5', 50000) 8" in out
    assert '[record]\ntime = 1700000000.0\nsource = "192.0.2.5:50000"' in out
    assert "ReplayResult(sent=3, partial=0)" in out
    assert out.splitlines()[-1] == "3 frames handed to a callable"
    # The filter kept the one frame the registered dissector read.
    (line,) = (tmp_path / "requests.jsonl").read_text(encoding="ascii").splitlines()
    record = json.loads(line)
    assert [layer["layer"] for layer in record["layers"]] == ["ipv4", "udp", "tftp"]
    assert record["layers"][-1] == {
        "layer": "tftp",
        "opcode": 1,
        "filename": "boot.efi",
    }
    # The copy holds the frames of the original, octet for octet.
    assert [f.data for f in pktcap.read_frames(tmp_path / "copy.pcapng")] == [
        f.data for f in pktcap.read_frames(tmp_path / "trace.pcap")
    ]


def test_the_installation_table_names_the_declared_extras():
    try:
        import tomllib
    except ImportError:  # before Python 3.11
        import tomli as tomllib
    manifest = tomllib.loads((README.parent / "pyproject.toml").read_text("utf-8"))
    extras = set(manifest["project"]["optional-dependencies"]) - {"dev", "docs"}
    rows = set(re.findall(r"^\| `([a-z]+)` \|", _section("Installation"), re.MULTILINE))
    assert rows == extras == {"yaml", "toml"}
