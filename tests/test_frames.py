"""From frames to UDP datagrams: link layers, IPv4, IPv6, and what is counted."""

import io
import logging
import random
import struct
import time

import pytest

import captures as build
from pktcap import (
    LINKTYPES,
    CapturedDatagram,
    CapturedFrame,
    DecodeStats,
    FrameDecoder,
    read_datagrams,
)

V4 = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"request"))
V6 = build.ipv6("2001:db8::5", "2001:db8::1", build.udp(50000, 69, b"request"))
WANT_V4 = CapturedDatagram(1.5, ("10.0.0.5", 50000), ("10.0.0.1", 69), b"request")
WANT_V6 = CapturedDatagram(1.5, ("2001:db8::5", 50000), ("2001:db8::1", 69), b"request")


def _decode(linktype, data, **options):
    decoder = FrameDecoder(**options)
    return decoder.decode(CapturedFrame(1.5, linktype, data)), decoder.stats


# -- link layers ----------------------------------------------------------


@pytest.mark.parametrize(
    "linktype, frame",
    [
        (1, build.ethernet(V4)),
        (1, build.ethernet(V4, vlans=1)),
        (1, build.ethernet(V4, vlans=2)),
        (12, V4),
        (14, V4),
        (101, V4),
        (228, V4),
        (113, build.linux_sll(V4)),
        (276, build.linux_sll2(V4)),
        (0, struct.pack("<I", 2) + V4),
        (0, struct.pack(">I", 2) + V4),
        (108, struct.pack(">I", 2) + V4),
    ],
)
def test_ipv4_udp_is_found_under_every_link_type(linktype, frame):
    datagrams, stats = _decode(linktype, frame)
    assert datagrams == [WANT_V4]
    assert (stats.frames, stats.datagrams) == (1, 1)


@pytest.mark.parametrize(
    "linktype, frame",
    [
        (1, build.ethernet(V6, v6=True)),
        (101, V6),
        (229, V6),
        (113, build.linux_sll(V6, v6=True)),
        (276, build.linux_sll2(V6, v6=True)),
        (0, struct.pack("<I", 30) + V6),
        (0, struct.pack("<I", 10) + V6),
        (108, struct.pack(">I", 24) + V6),
    ],
)
def test_ipv6_udp_is_found_under_every_link_type(linktype, frame):
    assert _decode(linktype, frame)[0] == [WANT_V6]


def test_every_listed_link_type_is_decoded_and_the_table_cannot_be_changed():
    assert set(LINKTYPES) == {0, 1, 12, 14, 101, 108, 113, 228, 229, 276}
    with pytest.raises(TypeError):
        LINKTYPES[105] = "IEEE802_11"


# -- what is counted, never raised ----------------------------------------


@pytest.mark.parametrize(
    "linktype, frame",
    [
        (1, b"\x02" * 12 + b"\x08\x06" + bytes(28)),  # ARP
        (1, build.ethernet(build.ipv4("10.0.0.5", "10.0.0.1", bytes(20), protocol=6))),
        (101, build.ipv6("::1", "::1", bytes(20), next_header=6)),
        (101, build.ipv6("::1", "::1", bytes(8), next_header=58)),
        (0, struct.pack("<I", 7) + V4),
        (113, struct.pack("!HHH8sH", 0, 1, 6, b"", 0x0806) + bytes(28)),
    ],
)
def test_a_frame_that_is_not_udp_over_ip_is_counted_as_ignored(linktype, frame):
    datagrams, stats = _decode(linktype, frame)
    assert datagrams == []
    assert (stats.ignored, stats.malformed, stats.unsupported) == (1, 0, 0)


@pytest.mark.parametrize(
    "linktype, frame",
    [
        (1, b""),
        (1, b"\x02" * 13),
        (1, build.ethernet(b"")),
        (1, build.ethernet(V4[:19])),
        (1, build.ethernet(V4[:24])),  # the UDP header is cut
        (101, b"\x44" + V4[1:]),  # header length 4 words, under the minimum
        (101, b"\x4f" + V4[1:]),  # header length past the frame
        (101, build.ipv4("10.0.0.5", "10.0.0.1", build.udp(1, 2, b"x"), total=12)),
        (101, b"\x05" + V4[1:]),  # version 0
        (101, V6[:39]),
        (101, build.ipv6("::1", "::1", build.udp(1, 2, b"x")[:6])),
        (101, build.ipv4("10.0.0.5", "10.0.0.1", build.udp(1, 2, b"x", length=5))),
        (113, bytes(15)),
        (276, bytes(19)),
        (0, bytes(3)),
    ],
)
def test_a_frame_cut_short_or_inconsistent_is_counted_as_malformed(linktype, frame):
    datagrams, stats = _decode(linktype, frame)
    assert datagrams == []
    assert (stats.malformed, stats.ignored) == (1, 0)


def test_an_unknown_link_type_is_counted_and_logged_once(caplog):
    decoder = FrameDecoder()
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        for _ in range(3):
            assert decoder.decode(CapturedFrame(0.0, 105, V4)) == []
    assert decoder.stats.unsupported == 3 and decoder.stats.datagrams == 0
    assert [r.getMessage() for r in caplog.records] == [
        "link type 105 is not understood; its frames are counted and skipped"
    ]


def test_a_capture_cannot_make_the_decoder_log_without_end(caplog):
    decoder = FrameDecoder()
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        for linktype in range(1000, 1500):
            decoder.decode(CapturedFrame(0.0, linktype, V4))
    assert decoder.stats.unsupported == 500
    assert len(caplog.records) == 8


def test_stats_is_a_snapshot_with_a_name_for_each_counter():
    decoder = FrameDecoder()
    before = decoder.stats
    decoder.decode(CapturedFrame(0.0, 101, V4))
    assert before == DecodeStats(0, 0, 0, 0, 0, 0, 0, 0)
    assert decoder.stats._asdict() == {
        "frames": 1,
        "datagrams": 1,
        "ignored": 0,
        "malformed": 0,
        "unsupported": 0,
        "fragments": 0,
        "dropped": 0,
        "pending": 0,
    }


# -- lengths --------------------------------------------------------------


def test_trailing_octets_after_the_ip_length_are_not_payload():
    padded = build.ethernet(V4) + bytes(18)  # Ethernet pads a short frame
    assert _decode(1, padded)[0] == [WANT_V4]


def test_a_zero_ip_length_means_the_rest_of_the_frame():
    packet = build.ipv4(
        "10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"request"), total=0
    )
    offloaded = packet[:2] + b"\0\0" + packet[4:]
    assert _decode(101, offloaded)[0] == [WANT_V4]


def test_a_datagram_cut_by_the_snap_length_is_marked_truncated():
    v4 = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"p" * 200))
    v6 = build.ipv6("::1", "::2", build.udp(1, 2, b"p" * 200))
    for packet, kept in ((v4[:96], 96 - 28), (v6[:96], 96 - 48)):
        (datagram,), stats = _decode(101, packet)
        assert datagram.truncated and not datagram.fragmented
        assert datagram.payload == b"p" * kept
        assert stats.malformed == 0
    (whole,), _stats = _decode(101, v4)
    assert not whole.truncated and len(whole.payload) == 200


def test_ipv4_options_are_skipped():
    packet = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"request"), ihl=7)
    assert _decode(101, packet)[0] == [WANT_V4]


def test_ipv6_extension_headers_are_walked():
    body = build.ipv6_extension(
        build.ipv6_extension(build.udp(50000, 69, b"request"), next_header=17),
        next_header=60,
    )
    packet = build.ipv6("2001:db8::5", "2001:db8::1", body, next_header=0)
    assert _decode(101, packet)[0] == [WANT_V6]


def test_a_mapped_address_reads_the_same_on_every_python():
    packet = build.ipv6("::ffff:10.0.0.5", "::ffff:10.0.0.1", build.udp(1, 2, b"x"))
    (datagram,), _stats = _decode(101, packet)
    assert datagram.source == ("::ffff:10.0.0.5", 1)
    assert datagram.destination == ("::ffff:10.0.0.1", 2)


# -- what a hostile frame can cost ----------------------------------------


def test_more_extension_headers_than_any_stack_sends_is_malformed():
    def chained(count):
        body = build.udp(1, 2, b"x")
        for index in range(count):
            body = build.ipv6_extension(body, next_header=17 if index == 0 else 60)
        return build.ipv6("::1", "::2", body, next_header=60)

    assert len(_decode(101, chained(63))[0]) == 1
    datagrams, stats = _decode(101, chained(64))
    assert datagrams == [] and stats.malformed == 1


def test_a_frame_of_nothing_but_extension_headers_is_given_up_at_the_ceiling():
    """A 256 KiB frame of 32,000 chained headers costs what 64 headers cost: a
    frame half the size takes no less time, within the noise of a timer."""
    header = bytes([60, 0, 0, 0, 0, 0, 0, 0])

    def cost(count):
        packet = build.ipv6("::1", "::2", header * count, next_header=60, length=0)
        frame = CapturedFrame(0.0, 101, packet)
        decoder = FrameDecoder()
        best = float("inf")
        for _ in range(5):
            started = time.perf_counter()
            for _ in range(200):
                decoder.decode(frame)
            best = min(best, time.perf_counter() - started)
        assert decoder.stats.malformed == 1000
        return best

    assert cost(32000) < 8 * cost(1000) + 0.01


def test_more_vlan_tags_than_any_network_carries_is_malformed():
    assert _decode(1, build.ethernet(V4, vlans=8))[0] == [WANT_V4]
    datagrams, stats = _decode(1, build.ethernet(V4, vlans=9))
    assert datagrams == [] and stats.malformed == 1


@pytest.mark.parametrize("linktype", sorted(LINKTYPES))
def test_a_mutated_frame_never_raises(linktype):
    """Seeded fuzz: whatever a frame holds, `decode` returns a list."""
    random.seed(20261005 + linktype)
    first = build.udp(7, 9, b"f" * 64)
    seeds = [
        build.ethernet(V4, vlans=1),
        build.ethernet(V6, v6=True),
        build.linux_sll(V4),
        build.linux_sll2(V6, v6=True),
        struct.pack("<I", 2) + V4,
        V4,
        V6,
        build.ipv4("10.0.0.5", "10.0.0.1", first[:32], more=True),
        build.ipv4("10.0.0.5", "10.0.0.1", first[32:], offset=32),
        build.ipv6(
            "::1", "::2", build.ipv6_fragment(first[:32], more=True), next_header=44
        ),
        build.ipv6(
            "::1", "::2", build.ipv6_fragment(first[32:], offset=32), next_header=44
        ),
    ]
    decoder = FrameDecoder(max_reassemblies=16)
    produced = 0
    for index in range(5000):
        data = bytearray(random.choice(seeds))
        for _ in range(random.randint(0, 3)):
            position = random.randrange(len(data))
            if random.random() < 0.7:
                data[position] = random.randrange(256)
            else:
                data = data[:position] or bytearray(1)
        result = decoder.decode(CapturedFrame(index * 0.001, linktype, bytes(data)))
        assert isinstance(result, list)
        produced += len(result)
    stats = decoder.stats
    assert stats.frames == 5000 and stats.pending <= 16
    assert produced == stats.datagrams


# -- the one-call form ----------------------------------------------------


def test_read_datagrams_reads_and_decodes_in_one_call():
    frames = [build.ethernet(V4), b"\x02" * 12 + b"\x08\x06" + bytes(28)]
    data = build.pcapng(frames)
    (datagram,) = list(read_datagrams(io.BytesIO(data)))
    assert datagram == WANT_V4._replace(time=datagram.time)
    assert datagram.time == pytest.approx(1_000_000)


def test_a_decoder_passed_in_keeps_the_counts():
    decoder = FrameDecoder()
    data = build.pcap([build.ethernet(V4)], linktype=105) + build.pcap_record(b"x")
    assert list(read_datagrams(io.BytesIO(data), decoder=decoder)) == []
    assert decoder.stats.unsupported == 2 and decoder.stats.frames == 2


def test_read_datagrams_checks_its_arguments_at_the_call():
    with pytest.raises(TypeError):
        read_datagrams(None)
    with pytest.raises(TypeError, match="FrameDecoder"):
        read_datagrams(io.BytesIO(b""), decoder=object())
    with pytest.raises(ValueError):
        read_datagrams(io.BytesIO(b""), max_frame_size=0)


@pytest.mark.parametrize(
    "options, error",
    [
        ({"max_reassemblies": 0}, ValueError),
        ({"max_reassemblies": 1.5}, TypeError),
        ({"max_reassemblies": True}, TypeError),
        ({"reassembly_timeout": 0}, ValueError),
        ({"reassembly_timeout": float("nan")}, ValueError),
    ],
)
def test_a_decoder_refuses_a_limit_that_is_not_positive(options, error):
    with pytest.raises(error):
        FrameDecoder(**options)
