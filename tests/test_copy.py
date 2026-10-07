"""`copy_frames`: a source of dissected frames into a writer the caller owns."""

import io
import json

import pytest

import captures as build
from pktcap import (
    CapturedFrame,
    CaptureWriter,
    CopyResult,
    FrameDissector,
    compile_capture_filter,
    copy_frames,
    frame_filter,
    read_dissected,
    read_frames,
)

UDP_FRAME = build.ethernet(
    build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"first"))
)
TCP_FRAME = build.ethernet(
    build.ipv4("10.0.0.5", "10.0.0.1", build.tcp(40000, 80, b"GET"), protocol=6)
)
ARP_FRAME = b"\x02" * 12 + b"\x08\x06" + bytes(28)
SECOND_UDP = build.ethernet(
    build.ipv4("10.0.0.6", "10.0.0.1", build.udp(50001, 67, b"second"))
)
CAPTURE = build.pcap([UDP_FRAME, TCP_FRAME, ARP_FRAME, SECOND_UDP])


def _frames(*raw):
    dissector = FrameDissector()
    return [
        dissector.dissect(CapturedFrame(float(i), 1, data))
        for i, data in enumerate(raw)
    ]


def _json_lines(path):
    return [json.loads(line) for line in path.read_text("ascii").splitlines()]


def test_every_frame_of_a_capture_becomes_one_record(tmp_path):
    source = tmp_path / "in.pcap"
    source.write_bytes(build.pcap([UDP_FRAME, TCP_FRAME, ARP_FRAME]))
    out = tmp_path / "out.json"
    with CaptureWriter(out) as writer:
        result = copy_frames(read_dissected(source), writer)
    assert result == CopyResult(read=3, written=3, skipped=0, refused=0)
    records = _json_lines(out)
    assert [[layer["layer"] for layer in r["layers"]] for r in records] == [
        ["ethernet", "ipv4", "udp"],
        ["ethernet", "ipv4", "tcp"],
        ["ethernet"],
    ]


def test_the_datagram_view_writes_one_record_per_udp_datagram(tmp_path):
    out = tmp_path / "out.json"
    with CaptureWriter(out) as writer:
        result = copy_frames(
            _frames(UDP_FRAME, TCP_FRAME, ARP_FRAME), writer, datagrams=True
        )
    assert result == CopyResult(read=3, written=1, skipped=2, refused=0)
    (record,) = _json_lines(out)
    assert record["source"] == "10.0.0.5:50000" and record["payload"] == b"first".hex()


def test_select_decides_which_frames_are_written_and_the_rest_are_skipped(tmp_path):
    out = tmp_path / "out.json"
    with CaptureWriter(out) as writer:
        result = copy_frames(
            _frames(UDP_FRAME, TCP_FRAME, SECOND_UDP),
            writer,
            select=compile_capture_filter("proto=udp and dport=67", frame_filter),
        )
    assert result == CopyResult(read=3, written=1, skipped=2, refused=0)
    assert len(_json_lines(out)) == 1


def test_a_limit_stops_reading_and_the_source_is_not_read_past_it(tmp_path):
    taken = []

    def source():
        for index, data in enumerate(_frames(UDP_FRAME, TCP_FRAME, ARP_FRAME)):
            if index == 2:
                raise AssertionError("the third frame was read")
            taken.append(index)
            yield data

    with CaptureWriter(tmp_path / "out.json") as writer:
        result = copy_frames(source(), writer, limit=2)
    assert result == CopyResult(read=2, written=2, skipped=0, refused=0)
    assert taken == [0, 1]


def test_a_limit_counts_what_is_written_not_what_is_read(tmp_path):
    with CaptureWriter(tmp_path / "out.json") as writer:
        result = copy_frames(
            _frames(ARP_FRAME, UDP_FRAME, TCP_FRAME, SECOND_UDP),
            writer,
            datagrams=True,
            limit=1,
        )
    assert result == CopyResult(read=2, written=1, skipped=1, refused=0)


def test_a_limit_of_zero_reads_nothing(tmp_path):
    def source():
        raise AssertionError("read")
        yield  # pragma: no cover

    with CaptureWriter(tmp_path / "out.json") as writer:
        assert copy_frames(source(), writer, limit=0) == CopyResult(0, 0, 0, 0)
    assert not (tmp_path / "out.json").exists()


def test_the_writer_stays_the_callers_and_a_second_call_adds_to_it():
    stream = io.BytesIO()
    writer = CaptureWriter(stream, "json")
    first = copy_frames(_frames(UDP_FRAME), writer)
    second = copy_frames(_frames(TCP_FRAME, ARP_FRAME), writer)
    assert (first.written, second.written, writer.written) == (1, 2, 3)
    writer.write(_frames(UDP_FRAME)[0])  # still open
    assert len(stream.getvalue().splitlines()) == 4
    writer.close()


def test_a_capture_format_holds_the_frames_as_captured(tmp_path):
    out = tmp_path / "out.pcapng"
    with CaptureWriter(out) as writer:
        copy_frames(read_dissected(io.BytesIO(CAPTURE)), writer)
    assert [f.data for f in read_frames(out)] == [
        UDP_FRAME,
        TCP_FRAME,
        ARP_FRAME,
        SECOND_UDP,
    ]


def test_records_the_file_budget_turns_away_are_counted_as_refused(tmp_path):
    pattern = str(tmp_path / "out" / "{index}.json")
    with CaptureWriter(pattern, per_record=True, max_files=2) as writer:
        result = copy_frames(
            _frames(UDP_FRAME, TCP_FRAME, ARP_FRAME, SECOND_UDP), writer
        )
    assert result == CopyResult(read=4, written=2, skipped=0, refused=2)
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["0.json", "1.json"]


def test_the_refusals_counted_are_this_calls_alone(tmp_path):
    pattern = str(tmp_path / "{index}.json")
    with CaptureWriter(pattern, per_record=True, max_files=1) as writer:
        first = copy_frames(_frames(UDP_FRAME, TCP_FRAME), writer)
        second = copy_frames(_frames(ARP_FRAME), writer)
    assert (first.refused, second.refused, writer.refused) == (1, 1, 2)


def test_a_frame_cut_short_is_still_a_frame(tmp_path):
    cut = _frames(UDP_FRAME[:20])
    with CaptureWriter(tmp_path / "out.json") as writer:
        assert copy_frames(cut, writer).written == 1


def test_what_is_wrong_is_refused_before_anything_is_read(tmp_path):
    def source():
        raise AssertionError("read")
        yield  # pragma: no cover

    with CaptureWriter(tmp_path / "out.json") as writer:
        with pytest.raises(TypeError, match="CaptureWriter"):
            copy_frames(source(), io.BytesIO())  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="callable"):
            copy_frames(source(), writer, select=5)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="int"):
            copy_frames(source(), writer, limit=1.5)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="int"):
            copy_frames(source(), writer, limit=True)
        with pytest.raises(ValueError, match="below zero"):
            copy_frames(source(), writer, limit=-1)
    assert not (tmp_path / "out.json").exists()


@pytest.mark.parametrize("item", [UDP_FRAME, CapturedFrame(0.0, 1, UDP_FRAME), None])
def test_an_item_that_is_not_a_dissected_frame_is_a_type_error(item, tmp_path):
    with CaptureWriter(tmp_path / "out.json") as writer:
        with pytest.raises(TypeError, match="DissectedFrame"):
            copy_frames([item], writer)  # type: ignore[list-item]
    assert writer.written == 0


def test_a_failing_writer_ends_the_copy_with_its_own_error(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_bytes(b"")
    with CaptureWriter(str(blocked / "out.json")) as writer:
        with pytest.raises(OSError):
            copy_frames(_frames(UDP_FRAME), writer)
