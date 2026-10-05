"""IP fragment reassembly: what it puts together, and its bounds."""

import io
import os
import random
import time
import tracemalloc

import pytest

import captures as build
from pktcap import CapturedFrame, FrameDecoder, read_datagrams

SRC, DST = "10.0.0.1", "10.0.0.5"


def _v4_fragments(datagram, size, *, ident=9):
    """The IPv4 packets ``datagram`` (UDP header and payload) fragments into."""
    pieces = [datagram[i : i + size] for i in range(0, len(datagram), size)]
    return [
        build.ipv4(
            SRC, DST, piece, ident=ident, offset=i * size, more=i < len(pieces) - 1
        )
        for i, piece in enumerate(pieces)
    ]


def _v6_fragments(datagram, size, *, ident=77):
    pieces = [datagram[i : i + size] for i in range(0, len(datagram), size)]
    return [
        build.ipv6(
            "2001:db8::1",
            "2001:db8::5",
            build.ipv6_fragment(
                piece, offset=i * size, more=i < len(pieces) - 1, ident=ident
            ),
            next_header=44,
        )
        for i, piece in enumerate(pieces)
    ]


def _feed(decoder, packets, *, start=0.0, step=0.001):
    out = []
    for index, packet in enumerate(packets):
        out += decoder.decode(CapturedFrame(start + index * step, 101, packet))
    return out


PAYLOAD = os.urandom(3000)
DATAGRAM = build.udp(50000, 50001, PAYLOAD)


# -- what it puts together ------------------------------------------------


@pytest.mark.parametrize("fragments", [_v4_fragments, _v6_fragments])
@pytest.mark.parametrize("order", ["in order", "reversed", "shuffled"])
def test_fragments_in_any_order_give_one_datagram(fragments, order):
    packets = fragments(DATAGRAM, 1480 if fragments is _v4_fragments else 1232)
    if order == "reversed":
        packets.reverse()
    elif order == "shuffled":
        random.Random(7).shuffle(packets)
    decoder = FrameDecoder()
    (datagram,) = _feed(decoder, packets)
    assert datagram.payload == PAYLOAD
    assert (datagram.source[1], datagram.destination[1]) == (50000, 50001)
    assert not datagram.fragmented and not datagram.truncated
    stats = decoder.stats
    assert (stats.fragments, stats.datagrams, stats.dropped, stats.pending) == (
        len(packets),
        1,
        0,
        0,
    )


def test_the_datagram_carries_the_time_of_the_fragment_that_completed_it():
    decoder = FrameDecoder()
    (datagram,) = _feed(decoder, _v4_fragments(DATAGRAM, 1480), start=100.0, step=0.5)
    assert datagram.time == 101.0


def test_a_capture_with_a_vlan_tag_and_fragments_out_of_order_is_read():
    first, second, third = _v4_fragments(DATAGRAM, 1480)
    request = build.ipv4(DST, SRC, build.udp(50000, 69, b"request"))
    frames = [
        build.ethernet(request),
        build.ethernet(first, vlans=1),
        build.ethernet(third),
        build.ethernet(second),
        b"\x02" * 12 + b"\x08\x06" + bytes(28),  # ARP
    ]
    datagrams = list(read_datagrams(io.BytesIO(build.pcapng(frames))))
    assert [d.source for d in datagrams] == [(DST, 50000), (SRC, 50000)]
    assert datagrams[1].payload == PAYLOAD
    assert datagrams[0].time == pytest.approx(1_000_000)


def test_a_nanosecond_cooked_capture_with_ipv6_fragments_is_read():
    datagram = build.udp(1000, 69, b"write request for a file")
    frames = [build.linux_sll(p, v6=True) for p in _v6_fragments(datagram, 16)]
    data = build.pcapng(frames, linktype=113, nanoseconds=True)
    (read,) = list(read_datagrams(io.BytesIO(data)))
    assert read.source == ("2001:db8::1", 1000)
    assert read.payload == b"write request for a file"
    assert read.time == pytest.approx(1_000_000 + len(frames) - 1)


def test_headers_after_the_fragment_header_are_walked_once_reassembled():
    """The fragmentable part may itself start with a destination-options
    header; it is read from the reassembled octets, not from each fragment."""
    inner = build.ipv6_extension(build.udp(7, 9, b"q" * 100), next_header=17)
    packets = [
        build.ipv6(
            "::1",
            "::2",
            build.ipv6_fragment(inner[:56], more=True, next_header=60),
            next_header=44,
        ),
        build.ipv6(
            "::1",
            "::2",
            build.ipv6_fragment(inner[56:], offset=56, next_header=60),
            next_header=44,
        ),
    ]
    (datagram,) = _feed(FrameDecoder(), packets)
    assert datagram.payload == b"q" * 100


def test_an_atomic_fragment_is_a_whole_datagram():
    packet = build.ipv6(
        "::1", "::2", build.ipv6_fragment(build.udp(7, 9, b"whole")), next_header=44
    )
    decoder = FrameDecoder()
    (datagram,) = _feed(decoder, [packet])
    assert datagram.payload == b"whole" and decoder.stats.fragments == 0


def test_fragments_of_something_that_is_not_udp_are_not_kept():
    tcp = [build.ipv4(SRC, DST, bytes(64), more=True, protocol=6)]
    icmp6 = [
        build.ipv6(
            "::1",
            "::2",
            build.ipv6_fragment(bytes(64), more=True, next_header=58),
            next_header=44,
        )
    ]
    decoder = FrameDecoder()
    assert _feed(decoder, tcp + icmp6) == []
    assert (decoder.stats.ignored, decoder.stats.pending) == (2, 0)


def test_two_datagrams_interleaved_are_told_apart_by_identifier():
    other = build.udp(1, 2, b"z" * 3000)
    a, b = _v4_fragments(DATAGRAM, 1480, ident=1), _v4_fragments(other, 1480, ident=2)
    mixed = [packet for pair in zip(a, b) for packet in pair]
    payloads = {d.payload for d in _feed(FrameDecoder(), mixed)}
    assert payloads == {PAYLOAD, b"z" * 3000}


# -- reassembly off -------------------------------------------------------


@pytest.mark.parametrize("fragments", [_v4_fragments, _v6_fragments])
def test_without_reassembly_the_first_fragment_is_marked_and_no_state_is_kept(
    fragments,
):
    packets = fragments(DATAGRAM, 1480 if fragments is _v4_fragments else 1232)
    decoder = FrameDecoder(reassemble=False)
    (datagram,) = _feed(decoder, list(reversed(packets)))
    assert datagram.fragmented and not datagram.truncated
    assert PAYLOAD.startswith(datagram.payload) and 0 < len(datagram.payload) < 3000
    stats = decoder.stats
    assert (stats.fragments, stats.datagrams, stats.pending, stats.dropped) == (
        len(packets),
        1,
        0,
        0,
    )


# -- what contradicts itself ----------------------------------------------


def test_an_overlapping_fragment_discards_its_datagram():
    first, second, third = _v4_fragments(DATAGRAM, 1480)
    overlap = build.ipv4(SRC, DST, bytes(64), ident=9, offset=1472, more=True)
    decoder = FrameDecoder()
    assert _feed(decoder, [first, overlap, second, third]) == []
    assert decoder.stats.dropped == 1
    # The rest of the damaged datagram can never complete on its own.
    assert decoder.stats.pending == 1 and decoder.stats.datagrams == 0


def test_an_overlapping_ipv6_fragment_discards_its_datagram():
    first, second, third = _v6_fragments(DATAGRAM, 1232)
    overlap = build.ipv6(
        "2001:db8::1",
        "2001:db8::5",
        build.ipv6_fragment(bytes(64), offset=1224, more=True),
        next_header=44,
    )
    decoder = FrameDecoder()
    assert _feed(decoder, [first, overlap, second, third]) == []
    assert decoder.stats.dropped == 1


def test_a_fragment_overlapping_the_one_after_it_discards_the_datagram():
    """The piece held starts later than the one arriving, which runs into it."""
    first, second, third = _v4_fragments(DATAGRAM, 1480)
    long_first = build.ipv4(SRC, DST, DATAGRAM[:1488], ident=9, offset=0, more=True)
    decoder = FrameDecoder()
    assert _feed(decoder, [second, long_first, third]) == []
    assert decoder.stats.dropped == 1


def test_a_fragment_shorter_than_its_own_header_is_malformed_not_placed():
    packet = build.ipv4(SRC, DST, bytes(64), ident=9, more=True, total=12)
    decoder = FrameDecoder()
    assert _feed(decoder, [packet]) == []
    stats = decoder.stats
    assert (stats.malformed, stats.dropped, stats.pending) == (1, 0, 0)


def test_the_same_fragment_seen_twice_is_not_an_overlap():
    """A capture taken on a bridge or on every interface shows a frame more
    than once."""
    first, second, third = _v4_fragments(DATAGRAM, 1480)
    decoder = FrameDecoder()
    (datagram,) = _feed(decoder, [first, first, second, second, third])
    assert datagram.payload == PAYLOAD and decoder.stats.dropped == 0


def test_the_same_offset_with_other_octets_is_an_overlap():
    first, second, third = _v4_fragments(DATAGRAM, 1480)
    forged = build.ipv4(SRC, DST, bytes(1480), ident=9, offset=0, more=True)
    decoder = FrameDecoder()
    assert _feed(decoder, [first, forged, second, third]) == []
    assert decoder.stats.dropped == 1


@pytest.mark.parametrize(
    "packets",
    [
        # a piece past the fragment that said it was the last
        [
            build.ipv4(SRC, DST, bytes(64), ident=3, offset=1024),
            build.ipv4(SRC, DST, bytes(64), ident=3, offset=2048, more=True),
        ],
        # two different ends
        [
            build.ipv4(SRC, DST, bytes(64), ident=3, offset=1024),
            build.ipv4(SRC, DST, bytes(64), ident=3, offset=2048),
        ],
        # an end before a piece already held
        [
            build.ipv4(SRC, DST, bytes(64), ident=3, offset=2048, more=True),
            build.ipv4(SRC, DST, bytes(64), ident=3, offset=1024),
        ],
        # a fragment that would pass the longest IP datagram
        [build.ipv4(SRC, DST, bytes(1024), ident=3, offset=65528, more=True)],
        # a fragment that carries nothing
        [build.ipv4(SRC, DST, b"", ident=3, offset=64, more=True)],
    ],
    ids=["past the end", "two ends", "end before a piece", "over 65,535", "empty"],
)
def test_a_fragment_that_contradicts_its_datagram_discards_it(packets):
    decoder = FrameDecoder()
    assert _feed(decoder, packets) == []
    assert decoder.stats.dropped == 1 and decoder.stats.pending == 0


def test_a_fragment_cut_by_the_snap_length_is_malformed_not_placed():
    first, second, third = _v4_fragments(DATAGRAM, 1480)
    decoder = FrameDecoder()
    assert _feed(decoder, [first[:96], second, third]) == []
    assert decoder.stats.malformed == 1 and decoder.stats.pending == 1


# -- the bounds -----------------------------------------------------------


def test_reassemblies_in_flight_are_bounded_and_the_oldest_goes_first():
    decoder = FrameDecoder()
    for ident in range(10_000):
        packet = build.ipv4(SRC, DST, bytes(8), ident=ident % 65536, more=True)
        decoder.decode(CapturedFrame(ident * 0.0001, 101, packet))
    stats = decoder.stats
    assert stats.pending == 256
    assert stats.dropped == 10_000 - 256
    # The newest are the ones still held: completing one works.
    last = build.ipv4(SRC, DST, bytes(8), ident=9_999, offset=8)
    assert len(decoder.decode(CapturedFrame(1.0, 101, last))) == 1


def test_the_bound_is_the_callers_to_set():
    decoder = FrameDecoder(max_reassemblies=2)
    for ident in range(5):
        decoder.decode(
            CapturedFrame(
                0.0, 101, build.ipv4(SRC, DST, bytes(8), ident=ident, more=True)
            )
        )
    assert (decoder.stats.pending, decoder.stats.dropped) == (2, 3)


def test_a_reassembly_does_not_outlive_its_timeout():
    """IP identifiers are reused: a fragment 31 s later belongs to another
    datagram and must not complete the first."""
    first, second, third = _v4_fragments(DATAGRAM, 1480)
    decoder = FrameDecoder()
    assert _feed(decoder, [first, second]) == []
    assert decoder.decode(CapturedFrame(31.0, 101, third)) == []
    assert (decoder.stats.dropped, decoder.stats.pending) == (1, 1)
    patient = FrameDecoder(reassembly_timeout=60.0)
    _feed(patient, [first, second])
    assert len(patient.decode(CapturedFrame(31.0, 101, third))) == 1


def test_one_datagram_may_not_arrive_in_fragments_without_end():
    """65,528 octets in 8-octet fragments is 8,191 pieces; a real datagram
    over an MTU of 576 is 119. Past 1,024 the datagram is given up."""
    decoder = FrameDecoder()
    for index in range(1024):
        packet = build.ipv4(
            SRC, DST, bytes(8), ident=6, offset=8 + index * 8, more=True
        )
        decoder.decode(CapturedFrame(0.0, 101, packet))
    assert (decoder.stats.dropped, decoder.stats.pending) == (0, 1)
    decoder = FrameDecoder()
    for index in range(1025):
        packet = build.ipv4(
            SRC, DST, bytes(8), ident=5, offset=8 + index * 8, more=True
        )
        decoder.decode(CapturedFrame(0.0, 101, packet))
    assert (decoder.stats.dropped, decoder.stats.pending) == (1, 0)


def _hole_capture(count):
    """The last fragment first, then ``count`` 8-octet fragments in order with
    a hole before the last: the shape that made every fragment re-sort and
    re-copy all the others."""
    packets = [build.ipv4(SRC, DST, bytes(8), ident=5, offset=(count + 2) * 8)]
    packets += [
        build.ipv4(SRC, DST, bytes(8), ident=5, offset=index * 8, more=True)
        for index in range(count)
    ]
    return [CapturedFrame(0.0, 101, packet) for packet in packets]


def test_the_work_per_fragment_does_not_grow_with_the_fragments_held():
    def cost(count):
        frames = _hole_capture(count)
        best = float("inf")
        for _ in range(9):
            decoder = FrameDecoder()
            started = time.perf_counter()
            for frame in frames:
                decoder.decode(frame)
            best = min(best, time.perf_counter() - started)
        assert decoder.stats.pending == 1 and decoder.stats.fragments == count + 1
        return best

    # Eight times the fragments is 8 times the work when each costs the same
    # (8.2 measured), and far more when each one re-sorts and re-joins the
    # rest: a ratio is the same on a slow machine as on a fast one.
    assert cost(1000) < 16 * cost(125)


def test_eight_thousand_fragments_of_one_datagram_are_cheap_and_counted():
    decoder = FrameDecoder()
    started = time.perf_counter()
    for frame in _hole_capture(8000):
        assert decoder.decode(frame) == []
    elapsed = time.perf_counter() - started
    stats = decoder.stats
    assert stats.fragments == 8001 and stats.dropped >= 3 and stats.pending == 1
    assert elapsed < 2.0  # 3.7 s where every fragment re-sorted the rest


def test_the_memory_a_full_table_can_hold_is_bounded():
    """Every reassembly as full as it may be, in the smallest fragments."""
    decoder = FrameDecoder(max_reassemblies=8)
    piece = bytes(8)
    tracemalloc.start()
    try:
        for ident in range(8):
            for index in range(1024):
                packet = build.ipv4(
                    SRC, DST, piece, ident=ident, offset=8 + index * 8, more=True
                )
                decoder.decode(CapturedFrame(0.0, 101, packet))
        current, _peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert decoder.stats.pending == 8
    assert current < 8 * 256 * 1024  # under 256 KiB for each reassembly
