"""`PcapWriter`: what it writes reads back, and it touches nothing early."""

import gc
import io
import os
import struct
import warnings

import pytest

from pktcap import (
    CapturedDatagram,
    FrameDecoder,
    PcapWriter,
    read_datagrams,
    read_frames,
)

V4 = (("10.0.0.5", 50000), ("10.0.0.1", 69))
V6 = (("2001:db8::5", 50000), ("2001:db8::1", 69))


def _written(*datagrams):
    stream = io.BytesIO()
    with PcapWriter(stream) as writer:
        for time, source, destination, payload in datagrams:
            writer.write(time, source, destination, payload)
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


def test_a_reader_of_the_output_counts_nothing_as_malformed():
    data = _written((1, *V4, b"a"), (2, *V6, b"b"), (3, *V4, bytes(65507)))
    decoder = FrameDecoder()
    assert len(list(read_datagrams(io.BytesIO(data), decoder=decoder))) == 3
    stats = decoder.stats
    assert (stats.malformed, stats.ignored, stats.unsupported) == (0, 0, 0)
