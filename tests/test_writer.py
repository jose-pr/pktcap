"""`PcapWriter` and `PcapngWriter`: what they write reads back, a frame
round-trips as it was captured, and nothing is touched early."""

import gc
import io
import os
import struct
import warnings

import pytest

import captures as build
from pktcap import (
    CapturedDatagram,
    CapturedFrame,
    FrameDissector,
    PcapngWriter,
    PcapWriter,
    read_datagrams,
    read_frames,
)

V4 = (("10.0.0.5", 50000), ("10.0.0.1", 69))
V6 = (("2001:db8::5", 50000), ("2001:db8::1", 69))
WRITERS = [PcapWriter, PcapngWriter]


def _written(*datagrams, writer=PcapWriter):
    stream = io.BytesIO()
    with writer(stream) as out:
        for time, source, destination, payload in datagrams:
            out.write(time, source, destination, payload)
    return stream.getvalue()


def _sum16(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


# -- the round trip -------------------------------------------------------


@pytest.mark.parametrize("ends", [V4, V6], ids=["ipv4", "ipv6"])
@pytest.mark.parametrize("size", [0, 1, 2, 511, 512, 1472, 9000])
def test_what_is_written_reads_back_octet_for_octet(ends, size):
    payload = os.urandom(size)
    data = _written((1_700_000_000.25, ends[0], ends[1], payload))
    assert list(read_datagrams(io.BytesIO(data))) == [
        CapturedDatagram(1_700_000_000.25, ends[0], ends[1], payload)
    ]


def test_the_largest_payload_of_each_family_fits_and_one_more_does_not():
    for ends, most in ((V4, 65507), (V6, 65527)):
        data = _written((0, ends[0], ends[1], bytes(most)))
        (datagram,) = read_datagrams(io.BytesIO(data))
        assert len(datagram.payload) == most
        stream = io.BytesIO()
        with pytest.raises(ValueError, match="does not fit"):
            PcapWriter(stream).write(0, ends[0], ends[1], bytes(most + 1))
        assert stream.getvalue() == b""


def test_a_mapped_address_is_written_as_ipv4():
    data = _written((5, ("::ffff:10.0.0.5", 1), ("::FFFF:a00:1", 2), b"x"))
    (frame,) = read_frames(io.BytesIO(data))
    assert frame.linktype == 101 and frame.data[0] >> 4 == 4
    (datagram,) = read_datagrams(io.BytesIO(data))
    assert (datagram.source, datagram.destination) == (("10.0.0.5", 1), ("10.0.0.1", 2))


def test_one_end_of_each_family_is_written_as_ipv6():
    data = _written((5, ("10.0.0.5", 1), ("2001:db8::1", 2), b"x"))
    (datagram,) = read_datagrams(io.BytesIO(data))
    assert datagram.source == ("::ffff:10.0.0.5", 1)
    assert datagram.destination == ("2001:db8::1", 2)


def test_a_socket_address_with_a_zone_and_four_items_is_accepted():
    source = ("fe80::1%eth0", 546, 0, 3)
    data = _written((5, source, ("ff02::1:2%3", 547), b"solicit"))
    (datagram,) = read_datagrams(io.BytesIO(data))
    assert (datagram.source, datagram.destination) == (
        ("fe80::1", 546),
        ("ff02::1:2", 547),
    )


def test_a_captured_datagram_is_written_as_it_stands():
    datagram = CapturedDatagram(7.5, V4[0], V4[1], b"payload")
    stream = io.BytesIO()
    with PcapWriter(stream) as writer:
        writer.write_datagram(datagram)
    assert list(read_datagrams(io.BytesIO(stream.getvalue()))) == [datagram]


def test_times_are_kept_to_the_microsecond():
    data = _written(
        (1.0000004, *V4, b"a"), (1.9999996, *V4, b"b"), (4294967295.9999995, *V4, b"c")
    )
    times = [d.time for d in read_datagrams(io.BytesIO(data))]
    assert times == pytest.approx([1.0, 2.0, 4294967295.999999], abs=1e-6)


# -- what tcpdump and Wireshark check -------------------------------------


def test_the_file_header_is_little_endian_microsecond_raw_pcap():
    data = _written((0, *V4, b"x"))
    magic, major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(
        "<IHHiIII", data[:24]
    )
    assert (magic, major, minor, linktype) == (0xA1B2C3D4, 2, 4, 101)
    assert snaplen >= 65575  # the longest packet this writer produces


@pytest.mark.parametrize("payload", [b"", b"x", b"odd", os.urandom(1400)])
def test_the_ipv4_and_udp_checksums_are_valid(payload):
    (frame,) = read_frames(io.BytesIO(_written((0, *V4, payload))))
    header, udp = frame.data[:20], frame.data[20:]
    assert _sum16(header) == 0xFFFF
    pseudo = header[12:20] + struct.pack("!BBH", 0, 17, len(udp))
    assert _sum16(pseudo + udp) == 0xFFFF
    assert struct.unpack_from("!H", udp, 6)[0] != 0  # zero would mean "none"
    assert struct.unpack_from("!H", header, 2)[0] == len(frame.data)


@pytest.mark.parametrize("payload", [b"", b"x", os.urandom(1400)])
def test_the_ipv6_udp_checksum_is_valid(payload):
    (frame,) = read_frames(io.BytesIO(_written((0, *V6, payload))))
    udp = frame.data[40:]
    pseudo = frame.data[8:40] + struct.pack("!I3xB", len(udp), 17)
    assert _sum16(pseudo + udp) == 0xFFFF
    assert struct.unpack_from("!H", frame.data, 4)[0] == len(udp)


def test_ipv4_identifiers_differ_from_one_datagram_to_the_next():
    """Two datagrams sharing an identifier would be read as fragments of one
    by a tool that reassembles."""
    data = _written(*[(0, *V4, b"x")] * 3)
    idents = [
        struct.unpack_from("!H", f.data, 4)[0] for f in read_frames(io.BytesIO(data))
    ]
    assert len(set(idents)) == 3


# -- nothing is touched early ---------------------------------------------


def test_a_writer_that_never_writes_creates_no_file(tmp_path):
    path = tmp_path / "trace.pcap"
    writer = PcapWriter(path)
    assert not path.exists()
    writer.close()
    assert not path.exists()
    with PcapWriter(path):
        pass
    assert not path.exists()


def test_an_existing_file_is_untouched_until_the_first_write(tmp_path):
    path = tmp_path / "trace.pcap"
    path.write_bytes(b"an earlier capture")
    writer = PcapWriter(str(path))
    assert path.read_bytes() == b"an earlier capture"
    with pytest.raises(ValueError):
        writer.write(0, ("not-an-address", 1), V4[1], b"x")
    assert path.read_bytes() == b"an earlier capture"
    writer.write(0, *V4, b"x")
    writer.close()
    assert len(list(read_datagrams(path))) == 1


def test_each_record_is_on_disk_when_write_returns(tmp_path):
    path = tmp_path / "live.pcap"
    with PcapWriter(path) as writer:
        writer.write(1, *V4, b"first")
        assert [d.payload for d in read_datagrams(path)] == [b"first"]
        writer.write(2, *V4, b"second")
        assert [d.payload for d in read_datagrams(path)] == [b"first", b"second"]


def test_a_stream_gets_nothing_before_the_first_write_and_stays_open():
    stream = io.BytesIO()
    writer = PcapWriter(stream)
    assert stream.getvalue() == b""
    writer.write(0, *V4, b"x")
    writer.close()
    writer.close()
    assert not stream.closed and len(stream.getvalue()) == 24 + 16 + 20 + 8 + 1


def test_a_path_the_writer_opened_is_closed_by_it(tmp_path):
    path = tmp_path / "trace.pcap"
    writer = PcapWriter(path)
    writer.write(0, *V4, b"x")
    writer.close()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        del writer
        gc.collect()  # a file left open warns when it is collected
    assert [str(w.message) for w in caught if w.category is ResourceWarning] == []


def test_a_closed_writer_refuses_to_write():
    writer = PcapWriter(io.BytesIO())
    writer.close()
    with pytest.raises(ValueError, match="closed"):
        writer.write(0, *V4, b"x")


@pytest.mark.parametrize("writer", [PcapWriter, PcapngWriter])
def test_a_closed_writer_refuses_a_frame_too(writer):
    stream = io.BytesIO()
    out = writer(stream)
    out.close()
    with pytest.raises(ValueError, match="closed"):
        out.write_frame(CapturedFrame(0.0, 1, b"frame"))
    assert stream.getvalue() == b""


# -- a caller's mistake writes nothing ------------------------------------


@pytest.mark.parametrize(
    "arguments, error",
    [
        ((0, ("localhost", 1), V4[1], b"x"), ValueError),
        ((0, ("10.0.0.5", 65536), V4[1], b"x"), ValueError),
        ((0, ("10.0.0.5", -1), V4[1], b"x"), ValueError),
        ((0, ("10.0.0.5", "69"), V4[1], b"x"), TypeError),
        ((0, ("10.0.0.5", True), V4[1], b"x"), TypeError),
        ((0, "10.0.0.5:69", V4[1], b"x"), TypeError),
        ((0, V4[0], (b"\x0a\x00\x00\x01", 69), b"x"), TypeError),
        ((-1, *V4, b"x"), ValueError),
        ((2**32, *V4, b"x"), ValueError),
        ((float("nan"), *V4, b"x"), ValueError),
        ((float("inf"), *V4, b"x"), ValueError),
        (("now", *V4, b"x"), TypeError),
        ((0, *V4, "text"), TypeError),
    ],
)
def test_a_bad_argument_is_refused_and_nothing_is_written(arguments, error):
    stream = io.BytesIO()
    with pytest.raises(error):
        PcapWriter(stream).write(*arguments)
    assert stream.getvalue() == b""


@pytest.mark.parametrize("target", [None, 5, b"bytes"])
def test_a_target_that_is_neither_path_nor_stream_is_refused(target):
    with pytest.raises(TypeError, match="path or a binary stream"):
        PcapWriter(target)


@pytest.mark.parametrize("writer", WRITERS)
def test_a_reader_of_the_output_counts_nothing_as_malformed(writer):
    data = _written(
        (1, *V4, b"a"), (2, *V6, b"b"), (3, *V4, bytes(65507)), writer=writer
    )
    dissector = FrameDissector()
    assert len(list(read_datagrams(io.BytesIO(data), dissector=dissector))) == 3
    stats = dissector.stats
    assert (stats.malformed, stats.failed, stats.unsupported) == (0, 0, 0)


# -- pcapng ---------------------------------------------------------------


@pytest.mark.parametrize("ends", [V4, V6], ids=["ipv4", "ipv6"])
def test_pcapng_datagrams_read_back_octet_for_octet(ends):
    payload = os.urandom(700)
    data = _written((1_700_000_000.25, ends[0], ends[1], payload), writer=PcapngWriter)
    assert data[:4] == b"\x0a\x0d\x0d\x0a"
    assert list(read_datagrams(io.BytesIO(data))) == [
        CapturedDatagram(1_700_000_000.25, ends[0], ends[1], payload)
    ]


@pytest.mark.parametrize("writer", WRITERS)
def test_both_writers_open_late_flush_each_record_and_close_what_they_opened(
    writer, tmp_path
):
    path = tmp_path / "trace.cap"
    out = writer(path)
    assert not path.exists()
    out.write(1, *V4, b"first")
    assert [d.payload for d in read_datagrams(path)] == [b"first"]
    out.write_datagram(CapturedDatagram(2, V6[0], V6[1], b"second"))
    assert [d.payload for d in read_datagrams(path)] == [b"first", b"second"]
    out.close()
    out.close()
    with pytest.raises(ValueError, match="closed"):
        out.write(3, *V4, b"x")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        del out
        gc.collect()
    assert [w for w in caught if w.category is ResourceWarning] == []


def test_pcapng_writes_nothing_about_the_host():
    data = _written((1, *V4, b"x"), writer=PcapngWriter)
    # A section header with no option, one interface with none, one packet.
    assert len(data) == 28 + 20 + (32 + 32)


# -- frames, as captured --------------------------------------------------

UDP = build.udp(50000, 69, b"request")
FRAMES = [
    CapturedFrame(
        1_700_000_000.000001, 1, build.ethernet(build.ipv4("10.0.0.5", "10.0.0.1", UDP))
    ),
    CapturedFrame(1_700_000_000.5, 1, b"\x02" * 12 + b"\x08\x06" + bytes(28)),
    CapturedFrame(1_700_000_001.25, 1, b"odd"),
]
MIXED = FRAMES + [
    CapturedFrame(
        1_700_000_002.0, 113, build.linux_sll(build.ipv4("10.0.0.5", "10.0.0.1", UDP))
    ),
    CapturedFrame(1_700_000_003.0, 105, b"a link type nothing here dissects"),
    CapturedFrame(1_700_000_004.0, 1, b""),
]


def _frames_written(frames, writer):
    stream = io.BytesIO()
    with writer(stream) as out:
        for frame in frames:
            out.write_frame(frame)
    return stream.getvalue()


def _same(read, written):
    assert [(f.linktype, f.data) for f in read] == [
        (f.linktype, f.data) for f in written
    ]
    assert [f.time for f in read] == pytest.approx([f.time for f in written], abs=1e-6)


@pytest.mark.parametrize("writer", WRITERS)
def test_a_frame_is_written_back_as_it_was_captured(writer):
    _same(list(read_frames(io.BytesIO(_frames_written(FRAMES, writer)))), FRAMES)


def test_pcapng_holds_frames_of_any_mix_of_link_types():
    read = list(read_frames(io.BytesIO(_frames_written(MIXED, PcapngWriter))))
    _same(read, MIXED)
    # One interface for each link type, in the order they were first written.
    assert [f.interface for f in read] == [0, 0, 0, 1, 2, 0]


def test_a_pcap_file_has_the_link_type_of_its_first_write_and_refuses_another():
    stream = io.BytesIO()
    writer = PcapWriter(stream)
    writer.write_frame(FRAMES[0])
    before = stream.getvalue()
    with pytest.raises(ValueError, match="link type 1 and cannot take 113"):
        writer.write_frame(MIXED[3])
    with pytest.raises(ValueError, match="link type 1 and cannot take 101"):
        writer.write(1, *V4, b"a datagram is raw IP")
    assert stream.getvalue() == before
    assert struct.unpack_from("<I", before, 20)[0] == 1


def test_a_write_that_was_refused_does_not_fix_the_link_type_of_a_pcap_file():
    stream = io.BytesIO()
    writer = PcapWriter(stream)
    with pytest.raises(ValueError, match="time"):
        writer.write_frame(CapturedFrame(-1.0, 113, b"refused"))
    assert stream.getvalue() == b""
    writer.write_frame(FRAMES[0])
    assert struct.unpack_from("<I", stream.getvalue(), 20)[0] == 1


def test_a_capture_of_several_link_types_round_trips_through_pcapng():
    """Read any capture, write it back: the frames are the same frames."""
    original = (
        build.section()
        + build.interface(build.ETHERNET)
        + build.interface(build.LINUX_SLL, tsresol=9)
        + build.interface(105)
        + build.packet(FRAMES[0].data, iface=0, stamp=1_700_000_000_250_000)
        + build.packet(MIXED[3].data, iface=1, stamp=1_700_000_000_500_000_000)
        + build.packet(b"unknown", iface=2, stamp=1_700_000_000_750_000)
        + build.block(4, b"a name resolution block, skipped")
        + build.packet(FRAMES[1].data, iface=0, stamp=1_700_000_001_000_000)
    )
    first = list(read_frames(io.BytesIO(original)))
    assert [f.linktype for f in first] == [1, 113, 105, 1]
    again = list(read_frames(io.BytesIO(_frames_written(first, PcapngWriter))))
    _same(again, first)
    assert [f.interface for f in again] == [f.interface for f in first]


@pytest.mark.parametrize("writer", WRITERS)
def test_a_filtered_capture_keeps_the_frames_that_passed_octet_for_octet(writer):
    kept = [frame for frame in FRAMES if len(frame.data) > 10]
    read = list(read_frames(io.BytesIO(_frames_written(kept, writer))))
    assert [f.data for f in read] == [f.data for f in kept]


@pytest.mark.parametrize("writer", WRITERS)
@pytest.mark.parametrize(
    "frame, error",
    [
        (CapturedFrame(-1.0, 1, b"x"), ValueError),
        (CapturedFrame(float("nan"), 1, b"x"), ValueError),
        (CapturedFrame(0.0, 70000, b"x"), ValueError),
        (CapturedFrame(0.0, -1, b"x"), ValueError),
        (CapturedFrame(0.0, "1", b"x"), TypeError),
        (CapturedFrame(0.0, 1, bytes(262145)), ValueError),
        (CapturedFrame(0.0, 1, "text"), TypeError),
    ],
)
def test_a_frame_that_cannot_be_written_is_refused_and_nothing_is_written(
    writer, frame, error
):
    stream = io.BytesIO()
    with pytest.raises(error):
        writer(stream).write_frame(frame)
    assert stream.getvalue() == b""


def test_the_largest_frame_a_reader_accepts_is_written():
    frame = CapturedFrame(0.0, 1, bytes(262144))
    for writer in WRITERS:
        (read,) = read_frames(io.BytesIO(_frames_written([frame], writer)))
        assert len(read.data) == 262144
