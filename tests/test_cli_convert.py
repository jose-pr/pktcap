"""``pktcap convert``: real argument vectors through the real parser.

Frames in a capture are built octet by octet (``captures.py``) and what a
command wrote is read back with a reader this command did not use: the
standard ``json`` module, or the library's own capture reader.
"""

import json
import subprocess
import sys

import pytest

pytest.importorskip("duho")

import captures as build  # noqa: E402
from pktcap import read_frames  # noqa: E402
from pktcap.cli import main  # noqa: E402

DHCP = build.ethernet(
    build.ipv4("10.0.0.5", "255.255.255.255", build.udp(68, 67, b"discover"))
)
REPLY = build.ethernet(build.ipv4("10.0.0.1", "10.0.0.5", build.udp(67, 68, b"offer")))
DNS = build.ethernet(build.ipv4("10.0.0.5", "10.0.0.2", build.udp(5353, 53, b"query")))
WEB = build.ethernet(
    build.ipv4("10.0.0.5", "10.0.0.2", build.tcp(40000, 80, b"GET"), protocol=6)
)
ARP = b"\x02" * 12 + b"\x08\x06" + bytes(28)
FRAMES = [DHCP, REPLY, DNS, WEB, ARP]


@pytest.fixture
def trace(tmp_path):
    path = tmp_path / "trace.pcap"
    path.write_bytes(build.pcap(FRAMES))
    return path


def _lines(text):
    return [json.loads(line) for line in text.splitlines()]


def _layers(record):
    return [layer["layer"] for layer in record["layers"]]


def test_json_is_one_object_per_frame_on_stdout_and_the_summary_on_stderr(
    trace, capsys
):
    assert main(["convert", "-i", str(trace), "--format", "json"]) == 0
    out, err = capsys.readouterr()
    records = _lines(out)
    assert [_layers(r) for r in records] == [
        ["ethernet", "ipv4", "udp"],
        ["ethernet", "ipv4", "udp"],
        ["ethernet", "ipv4", "udp"],
        ["ethernet", "ipv4", "tcp"],
        ["ethernet"],
    ]
    assert err.strip() == "5 frames read, 5 written"


def test_the_default_format_of_standard_output_is_json(trace, capsys):
    assert main(["convert", "-i", str(trace), "--limit", "1"]) == 0
    assert len(_lines(capsys.readouterr().out)) == 1


def test_a_capture_written_and_converted_back_holds_the_frames_octet_for_octet(
    trace, tmp_path
):
    ng = tmp_path / "out.pcapng"
    back = tmp_path / "back.pcap"
    assert main(["convert", "-i", str(trace), "-o", str(ng)]) == 0
    assert main(["convert", "-i", str(ng), "-o", str(back)]) == 0
    assert [f.data for f in read_frames(back)] == FRAMES
    assert [f.time for f in read_frames(back)] == [f.time for f in read_frames(trace)]
    assert [f.linktype for f in read_frames(ng)] == [1] * 5


def test_a_filter_writes_only_the_frames_it_selects(trace, tmp_path, capsys):
    out = tmp_path / "dhcp.pcap"
    assert (
        main(
            ["convert", "-i", str(trace), "-o", str(out), "-f", "proto=udp and port=67"]
        )
        == 0
    )
    assert [f.data for f in read_frames(out)] == [DHCP, REPLY]
    assert capsys.readouterr().err.strip() == "5 frames read, 2 written, 3 skipped"


def test_datagrams_writes_the_udp_view_and_passes_over_the_rest(trace, capsys):
    assert main(["convert", "-i", str(trace), "--datagrams"]) == 0
    out, err = capsys.readouterr()
    records = _lines(out)
    assert [r["destination"] for r in records] == [
        "255.255.255.255:67",
        "10.0.0.5:68",
        "10.0.0.2:53",
    ]
    assert records[0]["payload"] == b"discover".hex()
    assert err.strip() == "5 frames read, 3 written, 2 skipped"


def test_datagrams_into_a_capture_are_written_under_synthesised_headers(
    trace, tmp_path
):
    out = tmp_path / "udp.pcap"
    assert main(["convert", "-i", str(trace), "-o", str(out), "--datagrams"]) == 0
    frames = list(read_frames(out))
    assert len(frames) == 3 and {f.linktype for f in frames} == {101}


def test_limit_stops_after_that_many_written(trace, capsys):
    assert main(["convert", "-i", str(trace), "--limit", "2"]) == 0
    out, err = capsys.readouterr()
    assert len(_lines(out)) == 2 and err.strip() == "2 frames read, 2 written"
    assert main(["convert", "-i", str(trace), "--limit", "-1"]) == 2


def test_a_capture_cut_mid_record_writes_the_whole_records_and_is_status_2(
    tmp_path, capsys
):
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(build.pcap(FRAMES)[:-10])
    out = tmp_path / "out.jsonl"
    assert main(["convert", "-i", str(cut), "-o", str(out)]) == 2
    err = capsys.readouterr().err
    assert str(cut) in err and err.startswith("pktcap: error: ")
    assert err.count("\n") == 1 and "4 written" in err
    assert len(_lines(out.read_text("ascii"))) == 4


def test_what_is_not_a_capture_is_status_2_naming_the_file(tmp_path, capsys):
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture file at all")
    assert main(["convert", "-i", str(junk)]) == 2
    assert str(junk) in capsys.readouterr().err


def test_a_file_that_cannot_be_opened_is_status_1(tmp_path, capsys):
    assert main(["convert", "-i", str(tmp_path / "missing.pcap")]) == 1
    assert "pktcap: error: " in capsys.readouterr().err


def test_a_format_of_one_record_per_file_needs_per_record(trace, capsys):
    assert main(["convert", "-i", str(trace), "--format", "toml"]) == 2
    err = capsys.readouterr().err
    assert "per_record" in err and "toml" in err


def test_toml_per_record_writes_one_file_each(trace, tmp_path):
    pattern = str(tmp_path / "rec" / "{index:03d}.toml")
    assert main(["convert", "-i", str(trace), "-o", pattern, "--per-record"]) == 0
    assert sorted(p.name for p in (tmp_path / "rec").iterdir()) == [
        "%03d.toml" % n for n in range(5)
    ]


def test_the_file_budget_turns_records_away_and_the_status_says_so(
    trace, tmp_path, capsys
):
    pattern = str(tmp_path / "rec" / "{index}.json")
    status = main(
        ["convert", "-i", str(trace), "-o", pattern, "--per-record", "--max-files", "2"]
    )
    assert status == 1
    assert len(list((tmp_path / "rec").iterdir())) == 2
    assert "3 refused" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv, words",
    [
        (["-o", "out.unknown"], "format"),
        (["--per-record"], "pattern"),
        (["-f", "colour=red"], "colour"),
        (["-o", "{index}.json", "--per-record", "--max-files", "0"], "max_files"),
    ],
    ids=["unknown-ending", "per-record-to-stdout", "bad-filter", "no-files-allowed"],
)
def test_a_combination_that_cannot_work_is_status_2_before_anything_is_read(
    argv, words, trace, tmp_path, capsys, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    assert main(["convert", "-i", str(trace)] + argv) == 2
    assert words in capsys.readouterr().err
    assert [p.name for p in tmp_path.iterdir()] == ["trace.pcap"]


def test_a_missing_extra_is_status_1_with_the_one_line(trace, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "tomli_w", None)
    pattern = "{index}.toml"
    assert main(["convert", "-i", str(trace), "-o", pattern, "--per-record"]) == 1
    err = capsys.readouterr().err
    assert err.strip() == (
        "pktcap: error: TOML output needs the 'toml' extra: pip install \"pktcap[toml]\""
    )


def test_capture_octets_are_not_written_to_a_terminal(trace, monkeypatch, capsys):
    class Terminal:
        buffer = None

        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdout", Terminal())
    assert main(["convert", "-i", str(trace), "--format", "pcap"]) == 2
    err = capsys.readouterr().err
    assert "--output" in err and "terminal" in err


def test_a_frame_of_a_link_type_nothing_dissects_is_counted_and_still_written(
    tmp_path, capsys
):
    odd = tmp_path / "odd.pcap"
    odd.write_bytes(build.pcap([b"\x01\x02\x03"], linktype=147))
    assert main(["convert", "-i", str(odd)]) == 0
    out, err = capsys.readouterr()
    (record,) = _lines(out)
    assert record["linktype"] == 147 and record["layers"] == []
    assert "1 of an unsupported link type (147)" in err


def test_a_malformed_frame_is_counted_in_the_summary(tmp_path, capsys):
    short = tmp_path / "short.pcap"
    short.write_bytes(build.pcap([DHCP[:20]]))
    assert main(["convert", "-i", str(short)]) == 0
    assert "1 malformed" in capsys.readouterr().err


def test_quiet_drops_the_summary_and_keeps_the_data(trace, capsys):
    assert main(["convert", "-q", "-i", str(trace)]) == 0
    out, err = capsys.readouterr()
    assert len(_lines(out)) == 5 and err == ""


# -- standard input and output as real streams -----------------------------


def _run(*args, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "pktcap", *args],
        input=stdin,
        capture_output=True,
        timeout=120,
    )


@pytest.mark.parametrize("name", ["pcap", "pcapng"])
def test_capture_octets_on_standard_output_are_those_of_the_file(name, trace, tmp_path):
    """Nothing else is on stdout, and no newline is translated on Windows."""
    expected = tmp_path / ("expected." + name)
    assert main(["convert", "-i", str(trace), "-o", str(expected)]) == 0
    done = _run("convert", "-i", str(trace), "-o", "-", "--format", name)
    assert done.returncode == 0, done.stderr
    assert done.stdout == expected.read_bytes()
    assert done.stderr.decode().strip() == "5 frames read, 5 written"


def test_a_capture_from_a_pipe_is_read_and_records_go_to_a_pipe(trace):
    done = _run("convert", "-i", "-", stdin=trace.read_bytes())
    assert done.returncode == 0, done.stderr
    assert len(_lines(done.stdout.decode("ascii"))) == 5
    assert b"\r" not in done.stdout


def test_an_empty_pipe_is_an_empty_capture():
    done = _run("convert", "-i", "-", stdin=b"")
    assert done.returncode == 0 and done.stdout == b""
    assert done.stderr.decode().strip() == "0 frames read, 0 written"
