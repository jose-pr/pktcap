"""TCP stream reassembly: each direction's octets in order, within bounds.

Every test builds TCP segments with the builders in ``captures.py``, has a real
``FrameDissector`` read them, and compares what the reassembler hands out with
the octets the test cut the segments from.
"""

import io
import pathlib
import random
import re

import pytest

import captures as build
import pktcap
from pktcap import (
    CapturedFrame,
    FrameDissector,
    TCPReassembler,
    TCPStreamData,
    TCPStreamStats,
    CaptureFormatError,
    read_tcp_streams,
)

A = ("10.0.0.1", 5000)
B = ("10.0.0.2", 80)
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
MASK = 0xFFFFFFFF


class Wire:
    """A reassembler fed frames the way a capture file would feed it."""

    def __init__(self, **options):
        self.dissector = FrameDissector()
        self.reassembler = TCPReassembler(**options)
        self.items = []
        self.clock = 1000.0

    def frame(self, sequence, data=b"", flags=PSH, *, src=A, dst=B, ack=0, time=None):
        if time is None:
            self.clock += 0.001
            time = self.clock
        raw = build.tcp_frame(
            src[0],
            dst[0],
            src[1],
            dst[1],
            sequence & MASK,
            data,
            flags=flags,
            acknowledgment=ack & MASK,
        )
        return self.dissector.dissect(CapturedFrame(time, build.ETHERNET, raw))

    def send(self, *args, **kwargs):
        got = self.reassembler.add(self.frame(*args, **kwargs))
        self.items.extend(got)
        return got

    def flush(self):
        got = self.reassembler.flush()
        self.items.extend(got)
        return got

    @property
    def stats(self):
        return self.reassembler.stats

    def octets(self, source=A, stream=None):
        return b"".join(
            i.data
            for i in self.items
            if i.source == source and stream in (None, i.stream)
        )


def view(items):
    """``(data, offset, missing, stream, end)`` of each item."""
    return [(i.data, i.offset, i.missing, i.stream, i.end) for i in items]


def consistent(items):
    """Each direction's items follow one another: an offset is where the last
    one ended plus the octets given up before it, and nothing follows an end."""
    position, ended = {}, set()
    for item in items:
        key = (item.stream, item.source)
        assert key not in ended
        assert item.data or item.end
        assert item.offset == position.get(key, 0) + item.missing, item
        position[key] = item.offset + len(item.data)
        if item.end:
            ended.add(key)


def handshake(wire, a=999, b=4999):
    wire.send(a, flags=SYN)
    wire.send(b, flags=SYN | ACK, src=B, dst=A, ack=a + 1)


# -- the values --------------------------------------------------------------


def test_the_values_are_named_tuples_with_the_documented_defaults():
    item = TCPStreamData(1.0, A, B, b"x", 0)
    assert item.missing == 0 and item.stream == 0 and item.end is False
    assert TCPStreamStats._fields == (
        "segments",
        "streams",
        "delivered",
        "retransmitted",
        "out_of_order",
        "missing",
        "conflicts",
        "ignored",
        "evicted",
        "pending",
        "held",
    )
    assert TCPReassembler().stats == TCPStreamStats(*[0] * 11)


# -- order -------------------------------------------------------------------


def test_segments_in_order_are_handed_out_as_they_come():
    wire = Wire()
    assert view(wire.send(1000, b"hello")) == [(b"hello", 0, 0, 0, False)]
    assert view(wire.send(1005, b" world")) == [(b" world", 5, 0, 0, False)]
    assert wire.items[0].source == A and wire.items[0].destination == B
    assert wire.items[0].time == pytest.approx(1000.001)
    assert wire.flush() == ()
    stats = wire.stats
    assert (stats.segments, stats.streams, stats.delivered) == (2, 1, 11)
    assert (stats.pending, stats.held, stats.missing) == (0, 0, 0)


def test_both_directions_share_a_stream_number_and_keep_their_own_offsets():
    wire = Wire()
    wire.send(1000, b"GET /")
    wire.send(7000, b"200 OK", src=B, dst=A)
    wire.send(1005, b" x")
    assert [(i.source, i.offset, i.stream) for i in wire.items] == [
        (A, 0, 0),
        (B, 0, 0),
        (A, 5, 0),
    ]
    other = ("10.0.0.9", 6000)
    wire.send(1, b"z", src=other, dst=B)
    assert wire.items[-1].stream == 1


def test_the_same_addresses_in_either_order_are_one_connection():
    wire = Wire()
    wire.send(1, b"a", src=A, dst=B)
    wire.send(1, b"b", src=B, dst=A)
    assert {i.stream for i in wire.items} == {0}
    assert wire.stats.streams == 1


def test_a_segment_seen_twice_is_a_retransmission_and_dropped_unread():
    wire = Wire()
    wire.send(1000, b"hello")
    assert wire.send(1000, b"hello") == ()
    # A copy that disagrees with what was handed out is dropped as well:
    # the delivered octets are final.
    assert wire.send(1000, b"HELLO") == ()
    assert wire.octets() == b"hello"
    assert wire.stats.retransmitted == 10 and wire.stats.conflicts == 0


def test_a_segment_straddling_the_delivered_point_gives_only_its_new_part():
    wire = Wire()
    wire.send(1000, b"hello")
    assert view(wire.send(1003, b"lo world")) == [(b" world", 5, 0, 0, False)]
    assert wire.stats.retransmitted == 2


def test_two_pieces_out_of_order_arrive_as_one_run_when_the_first_is_late():
    wire = Wire()
    handshake(wire)
    assert wire.send(1005, b"world") == ()
    assert wire.stats.held == 5 and wire.stats.out_of_order == 1
    assert view(wire.send(1000, b"hello")) == [(b"helloworld", 0, 0, 0, False)]
    assert wire.stats.held == 0


@pytest.mark.parametrize("order", [(2, 1, 0), (1, 2, 0), (0, 2, 1), (2, 0, 1)])
def test_three_pieces_in_any_order_give_the_stream_in_order(order):
    truth = b"aaaabbbbcccc"
    cuts = [(0, truth[:4]), (4, truth[4:8]), (8, truth[8:])]
    wire = Wire()
    handshake(wire)
    for index in order:
        wire.send(1000 + cuts[index][0], cuts[index][1])
    assert wire.octets() == truth
    consistent(wire.items)
    assert wire.stats.held == 0 and wire.stats.missing == 0


def test_a_piece_that_fills_the_hole_releases_the_pieces_beyond_it():
    wire = Wire()
    handshake(wire)
    wire.send(1000, b"aa")
    wire.send(1006, b"cc")
    wire.send(1010, b"ee")
    got = wire.send(1002, b"bbbb")
    assert view(got) == [(b"bbbbcc", 2, 0, 0, False)]
    assert wire.stats.held == 2
    assert view(wire.send(1008, b"dd")) == [(b"ddee", 8, 0, 0, False)]
    assert wire.octets() == b"aabbbbccddee"


def test_octets_are_counted_from_zero_and_do_not_wrap_with_the_sequence_number():
    truth = bytes(range(100))
    wire = Wire()
    first = 0xFFFFFFF0
    handshake(wire, a=first - 1)
    for start in (30, 0, 20, 10, 60, 50, 40, 90, 80, 70):
        wire.send(first + start, truth[start : start + 10])
    assert wire.octets() == truth
    consistent(wire.items)
    assert [i.offset for i in wire.items] == sorted(i.offset for i in wire.items)
    assert max(i.offset for i in wire.items) < 100
    wire.send(first + 100, b"tail")
    assert wire.items[-1].offset == 100


def test_a_sequence_number_just_behind_the_next_octet_across_the_wrap_is_old():
    wire = Wire()
    wire.send(0xFFFFFFFE, b"abcd")  # covers the wrap
    assert wire.send(2, b"ef")[0].offset == 4
    assert wire.send(0xFFFFFFFE, b"abcdef") == ()
    assert wire.octets() == b"abcdef"


# -- overlap -----------------------------------------------------------------


def test_an_overlap_that_agrees_is_counted_as_copies_and_changes_nothing():
    wire = Wire()
    handshake(wire)
    wire.send(1010, b"0123456789")
    wire.send(1015, b"56789abcde")
    assert wire.stats.retransmitted == 5 and wire.stats.conflicts == 0
    wire.send(1000, b"X" * 10)
    assert wire.octets() == b"X" * 10 + b"0123456789abcde"
    consistent(wire.items)


def test_of_two_copies_not_yet_delivered_the_first_captured_wins():
    wire = Wire()
    handshake(wire)
    wire.send(1010, b"0123456789")
    wire.send(1015, b"56??9abcde")  # two octets disagree with the first copy
    assert wire.stats.conflicts == 2 and wire.stats.retransmitted == 5
    wire.send(1000, b"Y" * 10)
    assert wire.octets() == b"Y" * 10 + b"0123456789abcde"


def test_a_segment_covering_several_held_pieces_fills_only_the_gaps():
    wire = Wire()
    handshake(wire)
    wire.send(1002, b"BB")
    wire.send(1006, b"DD")
    wire.send(1000, b"aaCCCCeeee"[:10])
    # [0,2) delivered in order; the first copies of BB and DD win; the rest
    # of the segment fills the gaps around them.
    assert wire.octets() == b"aaBBCCDDee"
    assert wire.stats.conflicts == 4 and wire.stats.retransmitted == 4


# -- where a direction starts ------------------------------------------------


def test_offset_zero_is_the_octet_after_a_syn():
    wire = Wire()
    assert wire.send(999, flags=SYN) == ()
    assert view(wire.send(1000, b"hello")) == [(b"hello", 0, 0, 0, False)]


def test_a_syn_that_carries_data_delivers_it_at_offset_zero():
    wire = Wire()
    assert view(wire.send(999, b"abc", flags=SYN)) == [(b"abc", 0, 0, 0, False)]
    assert view(wire.send(1003, b"def")) == [(b"def", 3, 0, 0, False)]


def test_a_retransmitted_syn_changes_nothing():
    wire = Wire()
    wire.send(999, flags=SYN)
    wire.send(1000, b"hello")
    assert wire.send(999, flags=SYN) == ()
    assert wire.send(999, b"hello", flags=SYN) == ()
    assert wire.send(1005, b"!")[0].offset == 5
    assert wire.stats.streams == 1 and wire.stats.ignored == 0


def test_without_a_syn_the_first_octet_seen_is_offset_zero():
    wire = Wire()
    assert view(wire.send(5000, b"middle")) == [(b"middle", 0, 0, 0, False)]
    assert wire.send(4990, b"early") == ()  # before the start: not delivered
    assert wire.stats.ignored == 1 and wire.stats.retransmitted == 0
    assert wire.octets() == b"middle"


def test_a_segment_that_straddles_the_start_gives_its_octets_from_the_start():
    wire = Wire()
    wire.send(1000, b"abcde")
    wire.send(997, b"xyzabc")  # xyz lies before offset 0, abc was delivered
    assert wire.octets() == b"abcde"
    assert wire.stats.ignored == 1 and wire.stats.retransmitted == 3


def test_a_syn_seen_after_the_data_it_precedes_is_the_connections_own():
    wire = Wire()
    wire.send(1000, b"abc")
    assert wire.send(999, flags=SYN) == ()
    assert wire.stats.streams == 1
    assert wire.send(1003, b"d")[0].offset == 3


# -- the end -----------------------------------------------------------------


def test_a_fin_with_data_ends_the_direction_in_the_same_item():
    wire = Wire()
    wire.send(1000, b"abc")
    assert view(wire.send(1003, b"def", flags=FIN | ACK)) == [(b"def", 3, 0, 0, True)]
    consistent(wire.items)


def test_a_fin_alone_is_an_empty_item_that_ends_the_direction():
    wire = Wire()
    wire.send(1000, b"abc")
    assert view(wire.send(1003, flags=FIN)) == [(b"", 3, 0, 0, True)]
    assert wire.send(1003, flags=FIN) == ()  # a retransmitted FIN
    assert wire.stats.ignored == 0


def test_a_fin_behind_the_delivered_octets_is_ignored():
    wire = Wire()
    wire.send(1000, b"abcdef")
    assert wire.send(1002, flags=FIN) == ()
    assert wire.stats.ignored == 1
    assert view(wire.send(1006, b"g")) == [(b"g", 6, 0, 0, False)]


def test_a_second_fin_somewhere_else_is_ignored_and_counted():
    wire = Wire()
    wire.send(1000, b"abc", flags=FIN)
    assert wire.send(1010, flags=FIN) == ()
    assert wire.stats.ignored == 1 and wire.octets() == b"abc"


def test_octets_beyond_a_fin_are_dropped_and_counted():
    wire = Wire()
    wire.send(1000, b"abc", flags=FIN)
    assert wire.send(1003, b"more") == ()
    assert wire.send(1000, b"abc") == ()
    assert wire.stats.ignored == 1 and wire.stats.retransmitted == 3
    assert wire.octets() == b"abc"
    held = Wire()
    handshake(held)
    held.send(1020, b"zz")
    held.send(1010, b"tail", flags=FIN)  # the FIN lands at 14: zz is beyond it
    assert held.stats.ignored == 1 and held.stats.held == 4
    held.flush()
    assert view(held.items) == [(b"tail", 10, 10, 0, True)]


def test_a_fin_behind_a_hole_ends_the_direction_when_the_hole_is_given_up():
    wire = Wire()
    handshake(wire)
    assert wire.send(1010, b"tail", flags=FIN) == ()
    assert view(wire.flush()) == [(b"tail", 10, 10, 0, True)]
    assert wire.stats.missing == 10


def test_a_fin_with_a_hole_and_nothing_held_ends_with_the_octets_missing():
    wire = Wire()
    handshake(wire)
    wire.send(1000, b"ab")
    wire.send(1010, flags=FIN)
    assert view(wire.flush()) == [(b"", 10, 8, 0, True)]


def test_a_hole_between_the_last_held_octets_and_the_fin_is_reported_before_the_end():
    """Held octets, then a hole, then the FIN: the end is an item of its own
    carrying that hole. Marked on the held octets' item, the end sat twenty
    octets early and those twenty were counted and never reported."""
    wire = Wire()
    handshake(wire)
    wire.send(1000, b"ab")
    wire.send(1010, b"held")
    wire.send(1034, flags=FIN)
    assert view(wire.flush()) == [(b"held", 10, 8, 0, False), (b"", 34, 20, 0, True)]
    assert wire.stats.missing == 28 == sum(i.missing for i in wire.items)


@pytest.mark.parametrize("seed", range(40))
def test_every_octet_given_up_is_reported_in_an_item(seed):
    """With no connection forgotten, the octets the counters call missing are
    exactly the ones the items report, whatever ends the streams."""
    rng = random.Random(seed)
    wire = Wire()
    flags = [PSH, PSH | ACK, ACK, SYN, SYN | ACK, FIN, FIN | ACK, RST]
    weights = [30, 30, 20, 1, 1, 4, 4, 1]
    after = {}
    for _ in range(300):
        src, dst = (A, B) if rng.random() < 0.5 else (B, A)
        base = after.setdefault((src, dst), rng.randrange(1 << 32))
        number = base + rng.choice(
            [0, 0, 0, rng.randrange(0, 300), -rng.randrange(0, 40)]
        )
        data = bytes(rng.choice(b"ab") for _ in range(rng.choice([0, 1, 5, 40])))
        after[(src, dst)] = number + len(data)
        wire.send(
            number,
            data,
            rng.choices(flags, weights)[0],
            src=src,
            dst=dst,
            ack=after.get((dst, src), 0) + rng.choice([0, 0, -20, 50, 100000]),
        )
    wire.flush()
    consistent(wire.items)
    stats = wire.stats
    assert stats.evicted == 0
    assert stats.missing == sum(i.missing for i in wire.items)
    assert stats.delivered == sum(len(i.data) for i in wire.items)


def test_an_end_is_not_marked_by_the_end_of_the_capture_alone():
    wire = Wire()
    wire.send(1000, b"abc")
    wire.send(1010, b"held")
    assert view(wire.flush()) == [(b"held", 10, 7, 0, False)]


def test_a_reset_in_sequence_ends_both_directions_and_delivers_what_is_held():
    wire = Wire()
    handshake(wire)
    wire.send(1000, b"req")
    wire.send(5000, b"resp", src=B, dst=A)
    wire.send(1010, b"late")
    got = wire.send(1003, flags=RST)
    assert view(got) == [(b"late", 10, 7, 0, True), (b"", 4, 0, 0, True)]
    assert (got[0].source, got[1].source) == (A, B)
    assert wire.stats.pending == 0
    # The connection's next segments start a new stream.
    assert wire.send(2000, b"again")[0].stream == 1
    consistent(wire.items)


def test_a_reset_behind_the_delivered_octets_is_ignored():
    wire = Wire()
    wire.send(1000, b"abcdef")
    assert wire.send(1002, flags=RST) == ()
    assert wire.stats.ignored == 1 and wire.stats.pending == 1
    assert wire.send(1006, b"g")[0].stream == 0


def test_a_reset_for_a_connection_never_seen_starts_nothing():
    wire = Wire()
    assert wire.send(1000, flags=RST) == ()
    assert wire.stats.streams == 0 and wire.stats.pending == 0


def test_a_syn_that_is_not_the_connections_own_starts_a_new_stream():
    wire = Wire()
    wire.send(999, b"one", flags=SYN)
    got = wire.send(5000, flags=SYN)
    assert view(got) == [(b"", 3, 0, 0, True)]
    assert view(wire.send(5001, b"two")) == [(b"two", 0, 0, 1, False)]
    assert wire.stats.streams == 2 and wire.stats.pending == 1


def test_a_syn_after_octets_were_seen_the_other_way_starts_a_new_stream():
    wire = Wire()
    wire.send(5000, b"x", src=B, dst=A)  # a capture that began mid-stream
    got = wire.send(999, flags=SYN)
    assert view(got) == [(b"", 1, 0, 0, True)]
    assert wire.send(1000, b"y")[0].stream == 1 and wire.stats.streams == 2


def test_a_syn_after_a_finished_connection_starts_a_new_stream_without_a_second_end():
    wire = Wire()
    wire.send(999, b"x", flags=SYN | FIN)
    assert [i.end for i in wire.items] == [True]
    assert wire.send(7000, flags=SYN) == ()
    assert wire.send(7001, b"y")[0].stream == 1


def test_a_syn_ack_that_contradicts_the_connection_is_ignored():
    wire = Wire()
    wire.send(999, flags=SYN)
    assert wire.send(7777, flags=SYN | ACK, src=B, dst=A, ack=1234) == ()
    assert wire.stats.ignored >= 1
    # It started nothing: the real answer is the connection's own.
    wire.send(4999, flags=SYN | ACK, src=B, dst=A, ack=1000)
    assert view(wire.send(5000, b"hi", src=B, dst=A)) == [(b"hi", 0, 0, 0, False)]
    assert wire.stats.streams == 1


def test_a_bare_acknowledgment_with_no_connection_starts_nothing():
    wire = Wire()
    assert wire.send(1000, flags=ACK, ack=500) == ()
    assert wire.stats.segments == 1 and wire.stats.streams == 0


# -- not TCP, not whole ------------------------------------------------------


def test_a_frame_that_is_not_tcp_gives_nothing():
    wire = Wire()
    udp = build.ethernet(build.ipv4("10.0.0.1", "10.0.0.2", build.udp(1, 2, b"x")))
    frame = wire.dissector.dissect(CapturedFrame(1.0, build.ETHERNET, udp))
    assert wire.reassembler.add(frame) == ()
    assert wire.stats == TCPStreamStats(*[0] * 11)


def test_a_segment_in_an_ip_fragment_that_was_not_reassembled_is_ignored():
    loose = FrameDissector(reassemble=False)
    segment = build.tcp(5000, 80, b"x" * 16, flags=PSH, sequence=1)
    packet = build.ipv4(A[0], B[0], segment[:24], protocol=6, ident=3, more=True)
    frame = loose.dissect(CapturedFrame(1.0, build.ETHERNET, build.ethernet(packet)))
    assert frame.layers[-1].__class__.__name__ == "TCPLayer"
    reassembler = TCPReassembler()
    assert reassembler.add(frame) == ()
    assert reassembler.stats.ignored == 1 and reassembler.stats.segments == 1
    assert reassembler.stats.streams == 0


def test_a_segment_in_fragments_is_read_from_the_frame_that_completes_it():
    segment = build.tcp(5000, 80, b"split across two frames", sequence=1, flags=PSH)
    first = build.ipv4(A[0], B[0], segment[:24], protocol=6, ident=3, more=True)
    last = build.ipv4(A[0], B[0], segment[24:], protocol=6, ident=3, offset=24)
    wire = Wire()
    for index, packet in enumerate((first, last)):
        frame = wire.dissector.dissect(
            CapturedFrame(float(index + 1), build.ETHERNET, build.ethernet(packet))
        )
        wire.items.extend(wire.reassembler.add(frame))
    assert view(wire.items) == [(b"split across two frames", 0, 0, 0, False)]
    assert wire.items[0].time == 2.0


def test_ipv6_is_reassembled_like_ipv4():
    src, dst = ("2001:db8::1", 40000), ("2001:db8::2", 443)
    wire = Wire()
    wire.send(1, flags=SYN, src=src, dst=dst)
    wire.send(7, b"world", src=src, dst=dst)
    got = wire.send(2, b"hello", src=src, dst=dst)
    assert view(got) == [(b"helloworld", 0, 0, 0, False)]
    assert wire.octets(src) == b"helloworld"
    assert wire.items[0].source == src and wire.items[0].destination == dst


def test_a_mapped_ipv6_address_is_a_different_host_from_the_ipv4_one():
    wire = Wire()
    mapped = ("::ffff:10.0.0.1", 5000)
    wire.send(1, b"a", src=A, dst=B)
    wire.send(1, b"b", src=mapped, dst=("::ffff:10.0.0.2", 80))
    assert wire.stats.streams == 2


# -- the whole of it ---------------------------------------------------------


def _cut(truth, rng):
    """``(offset, data)`` pieces covering ``truth``, in order."""
    cuts, position = [], 0
    while position < len(truth):
        size = rng.randint(1, 40)
        cuts.append((position, truth[position : position + size]))
        position += size
    return cuts


@pytest.mark.parametrize("seed", range(60))
def test_any_order_and_any_repetition_of_a_streams_segments_gives_the_same_octets(seed):
    rng = random.Random(seed)
    truth = bytes(rng.randrange(256) for _ in range(rng.randint(1, 600)))
    first = rng.choice([0, 1, 0xFFFFFF00, 0xFFFFFFFE, rng.randrange(1 << 32)])
    segments = _cut(truth, rng)
    # The same octets cut again at other places, and some segments twice.
    segments += _cut(truth, rng)
    segments += [rng.choice(segments) for _ in range(rng.randint(0, 20))]
    rng.shuffle(segments)
    wire = Wire()
    wire.send(first - 1, flags=SYN)
    for offset, data in segments:
        wire.send(first + offset, data)
    wire.flush()
    assert wire.octets() == truth
    consistent(wire.items)
    assert all(i.missing == 0 for i in wire.items)
    stats = wire.stats
    assert (stats.conflicts, stats.missing, stats.held) == (0, 0, 0)
    assert stats.delivered == len(truth)


# -- an acknowledgment proves receipt -----------------------------------------


def _hole_at_ten(wire):
    """A direction A with two octets delivered and ``tail`` held at 10."""
    handshake(wire)
    wire.send(1000, b"ab")
    wire.send(1010, b"tail")


def test_an_acknowledgment_past_a_hole_delivers_what_is_held_before_the_frames_own_octets():
    wire = Wire()
    _hole_at_ten(wire)
    assert wire.stats.held == 4
    got = wire.send(5000, b"reply", src=B, dst=A, flags=PSH | ACK, ack=1014)
    assert view(got) == [(b"tail", 10, 8, 0, False), (b"reply", 0, 0, 0, False)]
    assert (got[0].source, got[1].source) == (A, B)
    assert wire.stats.missing == 8 and wire.stats.held == 0
    consistent(wire.items)


def test_an_acknowledgment_inside_a_hole_gives_up_only_the_part_before_it():
    wire = Wire()
    _hole_at_ten(wire)
    assert wire.send(5000, src=B, dst=A, flags=ACK, ack=1006) == ()
    assert wire.stats.missing == 4 and wire.stats.held == 4
    # The rest of the hole is still waited for: the octets it holds come out
    # when they are filled, with the four given up reported before them.
    assert view(wire.send(1006, b"cdef")) == [(b"cdeftail", 6, 4, 0, False)]
    consistent(wire.items)
    assert wire.stats.missing == 4


def test_an_acknowledgment_up_to_the_start_of_a_held_run_releases_it():
    wire = Wire()
    _hole_at_ten(wire)
    assert view(wire.send(5000, src=B, dst=A, flags=ACK, ack=1010)) == [
        (b"tail", 10, 8, 0, False)
    ]


def test_an_acknowledgment_beyond_everything_seen_changes_nothing_and_is_counted():
    wire = Wire()
    _hole_at_ten(wire)
    before = wire.stats
    assert wire.send(5000, src=B, dst=A, flags=ACK, ack=1015) == ()
    assert wire.send(5000, src=B, dst=A, flags=ACK, ack=1000 + (1 << 30)) == ()
    after = wire.stats
    assert after.ignored == before.ignored + 2
    assert (after.held, after.missing) == (before.held, before.missing)
    # Believing it would make every later octet a retransmission.
    assert view(wire.send(1002, b"cdefghij")) == [(b"cdefghijtail", 2, 0, 0, False)]
    assert wire.stats.retransmitted == 0


def test_an_acknowledgment_that_covers_nothing_new_is_not_counted():
    wire = Wire()
    _hole_at_ten(wire)
    wire.send(5000, src=B, dst=A, flags=ACK, ack=1002)  # exactly the next octet
    wire.send(5000, src=B, dst=A, flags=ACK, ack=1000)  # behind it
    wire.send(5000, src=B, dst=A, flags=ACK, ack=900)
    assert wire.stats.ignored == 0 and wire.stats.missing == 0


def test_an_acknowledgment_of_a_direction_never_seen_is_not_read_against_anything():
    wire = Wire()
    wire.send(1000, b"data", flags=PSH | ACK, ack=777)
    assert wire.stats.ignored == 0 and wire.stats.streams == 1


def test_an_acknowledgment_of_a_fin_behind_a_hole_ends_the_direction():
    wire = Wire()
    handshake(wire)
    wire.send(1000, b"ab")
    wire.send(1010, flags=FIN)
    got = wire.send(5000, src=B, dst=A, flags=ACK, ack=1011)
    assert view(got) == [(b"", 10, 8, 0, True)]


def test_an_acknowledgment_wraps_with_the_sequence_number():
    wire = Wire()
    first = 0xFFFFFFFC
    wire.send(first - 1, flags=SYN)
    wire.send(first, b"ab")
    wire.send(first + 10, b"tail")  # 2**32 - 4 + 10 wraps to 6
    got = wire.send(5000, src=B, dst=A, flags=ACK, ack=first + 14)
    assert view(got) == [(b"tail", 10, 8, 0, False)]


# -- the table of connections --------------------------------------------------


def test_five_thousand_connections_leave_the_most_the_table_holds():
    wire = Wire()
    for index in range(5000):
        wire.send(1, b"x", src=("10.1.%d.%d" % (index // 250, index % 250), 9), dst=B)
    stats = wire.stats
    assert stats.pending == 1024 and stats.streams == 5000
    assert stats.evicted == 5000 - 1024 and stats.delivered == 5000


def test_the_connection_forgotten_is_the_least_recently_active():
    wire = Wire(max_streams=3)
    peers = [("10.0.1.%d" % n, 7) for n in range(5)]
    for peer in peers[:3]:
        wire.send(1, b"a", src=peer, dst=B)
    wire.send(2, b"b", src=peers[0], dst=B)  # the first is the most recent
    wire.send(1, b"c", src=peers[3], dst=B)  # one more: peers[1] is forgotten
    assert wire.stats.evicted == 1
    assert view(wire.send(3, b"d", src=peers[0], dst=B)) == [(b"d", 2, 0, 0, False)]
    got = wire.send(2, b"e", src=peers[1], dst=B)
    assert view(got) == [(b"e", 0, 0, 4, False)]  # a stream of its own, new


def test_a_forgotten_connection_drops_what_it_held_and_the_budget_with_it():
    wire = Wire(max_streams=1)
    handshake(wire)
    wire.send(1010, b"held")
    assert wire.stats.held == 4
    wire.send(1, b"z", src=("10.0.9.9", 1), dst=B)
    assert wire.stats.held == 0 and wire.stats.evicted == 1
    wire.flush()
    assert b"held" not in wire.octets(A)


def test_a_connection_silent_past_the_timeout_restarts_as_a_new_stream():
    wire = Wire(idle_timeout=10.0)
    wire.send(1000, b"a", time=100.0)
    assert wire.send(1001, b"b", time=105.0)[0].stream == 0
    got = wire.send(1002, b"c", time=200.0)
    assert view(got) == [(b"c", 0, 0, 1, False)]
    assert wire.stats.evicted == 1 and wire.stats.streams == 2


def test_the_idle_timeout_is_checked_when_the_addresses_are_next_seen():
    wire = Wire(idle_timeout=10.0)
    wire.send(1000, b"a", time=100.0)
    wire.send(1, b"z", src=("10.0.9.9", 1), dst=B, time=500.0)
    assert wire.stats.pending == 2 and wire.stats.evicted == 0


def test_a_time_of_zero_neither_expires_a_connection_nor_keeps_it_alive():
    wire = Wire(idle_timeout=10.0)
    wire.send(1000, b"a", time=100.0)
    # A pcapng simple packet block has no time: it says nothing about silence.
    assert wire.send(1001, b"b", time=0.0)[0].stream == 0
    # Nor does it keep the connection alive: 500 is measured from 100.
    assert wire.send(1002, b"c", time=500.0)[0].stream == 1
    # Nor did it refresh the connection: 109 is measured from 100, not from 0.
    wire = Wire(idle_timeout=10.0)
    wire.send(1000, b"a", time=100.0)
    wire.send(1001, b"b", time=0.0)
    assert wire.send(1002, b"c", time=109.0)[0].stream == 0
    first = Wire(idle_timeout=10.0)
    first.send(1000, b"a", time=0.0)
    assert first.send(1001, b"b", time=1.7e9)[0].stream == 0


def test_a_time_that_jumps_either_way_past_the_timeout_counts_as_silence():
    # A file controls the clock, so a jump backwards cannot be told from a
    # long gap; a small step back, as in a merged capture, is not one.
    wire = Wire(idle_timeout=10.0)
    wire.send(1000, b"a", time=100.0)
    assert wire.send(1001, b"b", time=95.0)[0].stream == 0
    assert wire.send(1002, b"c", time=40.0)[0].stream == 1


# -- the budget of held octets --------------------------------------------------


def _hold(wire, port, size=300, *, hole=10):
    peer = ("10.0.7.%d" % port, 4000 + port)
    wire.send(1, flags=SYN, src=peer, dst=B)
    return peer, wire.send(2 + hole, b"x" * size, src=peer, dst=B)


def test_octets_held_over_all_connections_never_pass_max_buffered():
    wire = Wire(max_buffered=1000)
    peers = []
    for port in range(2):
        peers.append(_hold(wire, port)[0])
    assert wire.stats.held == 600  # 2 x (300 + 64) = 728, within 1000
    peer, got = _hold(wire, 2)
    # The third would make 1,092: the direction that has waited longest,
    # the first, gives up its hole and delivers.
    assert view(got) == [(b"x" * 300, 10, 10, 0, False)]
    assert got[0].source == peers[0]
    assert wire.stats.held == 600 and wire.stats.missing == 10


def test_each_held_piece_is_charged_its_length_plus_sixty_four():
    wire = Wire(max_buffered=1000)
    handshake(wire)
    for index in range(1, 200):
        wire.send(1000 + 2 * index, b"x")
        # 65 per piece: more than 15 pieces cannot be held.
        assert wire.stats.held * 65 <= 1000
    assert wire.stats.missing > 0


def test_the_direction_that_has_waited_longest_is_the_one_that_gives_up():
    wire = Wire(max_buffered=1000)
    old, _ = _hold(wire, 0, 200)
    _hold(wire, 1, 200)
    # A third that overflows the budget: the first to wait gives up, not the
    # biggest and not the one that overflowed it.
    _, got = _hold(wire, 2, 500)
    assert [item.source for item in got] == [old]
    assert wire.stats.held == 700 and wire.stats.pending == 3


def test_a_piece_larger_than_the_budget_is_delivered_at_once_behind_a_hole():
    wire = Wire(max_buffered=100)
    handshake(wire)
    wire.send(1000, b"ab")
    got = wire.send(1010, b"B" * 200)
    assert view(got) == [(b"B" * 200, 10, 8, 0, False)]
    assert wire.stats.held == 0 and wire.stats.missing == 8


def test_a_piece_larger_than_the_budget_costs_no_other_direction_its_wait():
    wire = Wire(max_buffered=300)
    other, _ = _hold(wire, 0, 50)
    peer, got = _hold(wire, 1, 400)
    assert [item.source for item in got] == [peer]
    assert wire.stats.held == 50 and wire.stats.missing == 10


def test_a_large_piece_that_starts_inside_a_run_delivered_before_it_adds_only_its_new_part():
    wire = Wire(max_buffered=100)
    handshake(wire)
    wire.send(1004, b"abcdefghij")
    got = wire.send(1010, b"G" * 200)
    assert view(got) == [
        (b"abcdefghij", 4, 4, 0, False),
        (b"G" * 196, 14, 0, 0, False),
    ]
    assert wire.stats.retransmitted == 4


def test_holes_before_a_piece_larger_than_the_budget_are_given_up_in_order():
    wire = Wire(max_buffered=100)
    handshake(wire)
    wire.send(1000, b"ab")
    wire.send(1004, b"cd")
    got = wire.send(1010, b"B" * 200)
    assert view(got) == [(b"cd", 4, 2, 0, False), (b"B" * 200, 10, 4, 0, False)]
    consistent(wire.items)


def test_a_piece_larger_than_the_budget_that_overlaps_a_held_one_keeps_the_first_copy():
    wire = Wire(max_buffered=100)
    handshake(wire)
    wire.send(1004, b"cdef")
    got = wire.send(1002, b"AB" + b"CDEF" + b"g" * 200)
    assert b"".join(i.data for i in got) == b"AB" + b"cdef" + b"g" * 200
    assert wire.stats.conflicts == 4


def test_no_more_than_a_thousand_and_twenty_four_pieces_are_held_in_one_direction():
    wire = Wire()
    handshake(wire)
    most = 0
    for index in range(1, 10001):
        wire.send(1000 + 2 * index, b"x")
        most = max(most, wire.stats.held)
        assert wire.stats.held <= 1024
    assert most == 1024
    # The wait is lost and the octets are not: every one comes out.
    wire.flush()
    assert len(wire.octets()) == 10000
    consistent(wire.items)
    assert wire.stats.delivered == 10000 and wire.stats.held == 0


def test_the_work_per_segment_does_not_grow_with_the_pieces_held():
    import time as clock

    def cost(count):
        wire = Wire()
        frames = [wire.frame(1000 + 2 * i, b"x") for i in range(1, count + 1)]
        best = float("inf")
        for _ in range(9):
            reassembler = TCPReassembler()
            reassembler.add(wire.frame(999, flags=SYN))
            started = clock.perf_counter()
            for frame in frames:
                reassembler.add(frame)
            best = min(best, clock.perf_counter() - started)
        assert reassembler.stats.held == count
        return best

    # Eight times the pieces is 8 times the work when each costs the same
    # (8.2 measured), and far more when each one re-sorts or re-joins the rest:
    # a ratio is the same on a slow machine as on a fast one.
    assert cost(1000) < 16 * cost(125)


@pytest.mark.parametrize("seed", range(6))
def test_mutated_segments_never_raise_and_never_pass_the_bounds(seed):
    rng = random.Random(seed)
    wire = Wire(max_streams=2, max_buffered=1024, idle_timeout=500.0)
    hosts = [("10.0.%d.%d" % (n, n), 1000 + n) for n in range(3)]
    flags = [PSH, PSH | ACK, ACK, SYN, SYN | ACK, FIN, FIN | ACK, RST]
    weights = [30, 30, 20, 2, 2, 3, 3, 1]
    after = {}  # the sequence number each direction would continue at
    for _ in range(4000):
        src, dst = rng.sample(hosts, 2)
        base = after.setdefault((src, dst), rng.randrange(1 << 32))
        roll = rng.random()
        if roll < 0.03:
            number = rng.randrange(1 << 32)
        elif roll < 0.5:
            number = base + rng.randrange(0, 400)
        else:
            number = base - rng.randrange(0, 60)
        data = bytes(rng.choice(b"ab") for _ in range(rng.choice([0, 1, 5, 40, 200])))
        after[(src, dst)] = number + len(data)
        wire.send(
            number,
            data,
            rng.choices(flags, weights)[0],
            src=src,
            dst=dst,
            ack=rng.choice([number, base + rng.randrange(900), rng.randrange(1 << 32)]),
            time=rng.choice([None, None, None, 0.0, wire.clock + rng.uniform(-80, 80)]),
        )
        stats = wire.stats
        assert stats.held <= 1024 and stats.pending <= 2
    wire.flush()
    stats = wire.stats
    assert stats.held == 0 and stats.pending == 0
    consistent(wire.items)
    assert stats.delivered == sum(len(i.data) for i in wire.items)
    # Octets of a forgotten connection are given up and never reported.
    assert stats.missing >= sum(i.missing for i in wire.items)
    # The run met every rule, not only the quiet ones.
    for counter in (
        "out_of_order",
        "retransmitted",
        "conflicts",
        "ignored",
        "evicted",
        "missing",
    ):
        assert getattr(stats, counter) > 0, counter
    assert any(i.end for i in wire.items) and any(i.missing for i in wire.items)


def test_the_urgent_pointer_is_ignored_and_its_octet_delivered_in_place():
    raw = build.tcp_frame(
        A[0], B[0], A[1], B[1], 1000, b"abc!def", flags=PSH | 0x20, urgent=4
    )
    wire = Wire()
    frame = wire.dissector.dissect(CapturedFrame(1.0, build.ETHERNET, raw))
    assert view(wire.reassembler.add(frame)) == [(b"abc!def", 0, 0, 0, False)]


def test_two_vlans_with_the_same_addresses_are_one_connection():
    wire = Wire()
    for vlans, sequence, data in ((1, 1000, b"one "), (2, 1004, b"two")):
        segment = build.tcp(A[1], B[1], data, sequence=sequence, flags=PSH)
        ip = build.ipv4(A[0], B[0], segment, protocol=6)
        raw = build.ethernet(ip, vlans=vlans)
        frame = wire.dissector.dissect(CapturedFrame(1.0, build.ETHERNET, raw))
        wire.items.extend(wire.reassembler.add(frame))
    assert wire.octets() == b"one two" and wire.stats.streams == 1


def test_flush_gives_the_connections_in_order_of_their_stream_number():
    wire = Wire()
    first, second = ("10.0.1.1", 1), ("10.0.1.2", 2)
    for peer in (first, second):
        wire.send(1, flags=SYN, src=peer, dst=B)
    wire.send(10, b"b", src=second, dst=B)
    wire.send(10, b"a", src=first, dst=B)  # the most recently active
    assert [i.stream for i in wire.flush()] == [0, 1]


# -- a capture in one call -----------------------------------------------------


def _segment(sequence, data=b"", flags=PSH, *, src=A, dst=B, ack=0):
    return build.tcp_frame(
        src[0], dst[0], src[1], dst[1], sequence, data, flags=flags, acknowledgment=ack
    )


def _exchange():
    """A handshake, a request cut in two and sent out of order, a reply, and
    a FIN from each side."""
    return [
        _segment(999, flags=SYN),
        _segment(4999, flags=SYN | ACK, src=B, dst=A, ack=1000),
        _segment(1000, flags=ACK, ack=5000),
        _segment(1005, b"world"),
        _segment(1000, b"hello"),
        _segment(5000, b"reply", flags=PSH | ACK, src=B, dst=A, ack=1010),
        _segment(1010, flags=FIN | ACK, ack=5005),
        _segment(5005, flags=FIN | ACK, src=B, dst=A, ack=1011),
    ]


def test_the_items_of_an_exchange_come_in_capture_order():
    capture = build.pcap(_exchange())
    items = list(read_tcp_streams(io.BytesIO(capture)))
    assert [(i.source, i.data, i.offset, i.end) for i in items] == [
        (A, b"helloworld", 0, False),
        (B, b"reply", 0, False),
        (A, b"", 10, True),
        (B, b"", 5, True),
    ]
    assert [i.time for i in items] == [
        1_000_004.0,
        1_000_005.0,
        1_000_006.0,
        1_000_007.0,
    ]
    consistent(items)


def test_a_pcap_and_a_pcapng_of_one_exchange_give_the_same_items():
    frames = _exchange()
    from_pcap = list(read_tcp_streams(io.BytesIO(build.pcap(frames))))
    from_pcapng = list(read_tcp_streams(io.BytesIO(build.pcapng(frames))))
    assert from_pcap == from_pcapng and len(from_pcap) == 4


def test_a_path_is_read_like_a_stream(tmp_path):
    path = tmp_path / "exchange.pcap"
    path.write_bytes(build.pcap(_exchange()))
    assert list(read_tcp_streams(str(path))) == list(read_tcp_streams(path))
    assert len(list(read_tcp_streams(path))) == 4


def test_a_capture_that_ends_inside_a_hole_yields_the_held_octets_last():
    frames = [
        _segment(999, flags=SYN),
        _segment(1000, b"ab"),
        _segment(1010, b"tail"),
    ]
    items = list(read_tcp_streams(io.BytesIO(build.pcap(frames))))
    assert view(items) == [(b"ab", 0, 0, 0, False), (b"tail", 10, 8, 0, False)]


def test_a_capture_with_no_tcp_and_an_empty_one_yield_nothing():
    udp = build.ethernet(build.ipv4(A[0], B[0], build.udp(1, 2, b"x")))
    assert list(read_tcp_streams(io.BytesIO(build.pcap([udp])))) == []
    assert list(read_tcp_streams(io.BytesIO(build.pcap([])))) == []


def test_a_damaged_container_raises_after_the_items_before_the_damage():
    frames = [
        _segment(999, flags=SYN),
        _segment(1000, b"ab"),
        _segment(1010, b"tail"),
        _segment(1014, b"more"),
    ]
    data = build.pcap(frames)
    items = []
    with pytest.raises(CaptureFormatError):
        for item in read_tcp_streams(io.BytesIO(data[:-10])):
            items.append(item)
    # What the frames before the damage held comes out before the error.
    assert view(items) == [(b"ab", 0, 0, 0, False), (b"tail", 10, 8, 0, False)]
    with pytest.raises(CaptureFormatError):
        list(read_tcp_streams(io.BytesIO(b"not a capture at all")))


class _Counting(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.reads = 0

    def read(self, size=-1):
        self.reads += 1
        return super().read(size)


def test_nothing_is_read_before_the_first_item_and_a_caller_that_stops_leaves_the_rest():
    frames = [_segment(999, flags=SYN)] + [
        _segment(1000 + index, b"x") for index in range(3000)
    ]
    data = build.pcap(frames)
    stream = _Counting(data)
    items = read_tcp_streams(stream)
    assert stream.reads == 0
    first = next(items)
    assert first.data == b"x" and stream.reads > 0
    assert stream.tell() < len(data) // 4
    items.close()


def test_a_reassembler_and_a_dissector_of_the_wrong_type_are_refused_before_a_read():
    stream = _Counting(build.pcap(_exchange()))
    for options in ({"reassembler": object()}, {"dissector": object()}):
        with pytest.raises(TypeError):
            read_tcp_streams(stream, **options)
        assert stream.reads == 0
    with pytest.raises(TypeError):
        read_tcp_streams(stream, TCPReassembler())  # options are keyword-only


def test_the_reassembler_and_the_dissector_given_hold_the_counters():
    reassembler = TCPReassembler(max_streams=2)
    dissector = FrameDissector()
    frames = _exchange()
    items = list(
        read_tcp_streams(
            io.BytesIO(build.pcap(frames)), reassembler=reassembler, dissector=dissector
        )
    )
    assert len(items) == 4
    assert dissector.stats.frames == len(frames)
    assert reassembler.stats.segments == len(frames) and reassembler.stats.streams == 1
    assert reassembler.stats.delivered == len(b"helloworld") + len(b"reply")


_HEADER = pathlib.Path(pktcap.__file__).parent / "_streams" / "AGENTS.md"


def test_the_examples_of_the_streams_header_run(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    client, server = ("192.0.2.5", 50000), ("192.0.2.1", 80)
    with pktcap.PcapWriter("trace.pcap") as writer:
        for index, (sequence, data, flags) in enumerate(
            [
                (999, b"", SYN),
                (1005, b"world", PSH),
                (1000, b"hello", PSH),
                (1010, b"", FIN),
            ]
        ):
            raw = build.tcp_frame(
                client[0], server[0], client[1], server[1], sequence, data, flags=flags
            )
            writer.write_frame(CapturedFrame(1.0 + index, build.ETHERNET, raw))
    blocks = re.findall(
        r"```python\n(.*?)```", _HEADER.read_text(encoding="utf-8"), re.DOTALL
    )
    assert len(blocks) == 2
    namespace = {"__name__": "header_example"}
    for block in blocks:
        exec(compile(block, "AGENTS.md", "exec"), namespace)
    assert capsys.readouterr().out.splitlines() == [
        "0 192.0.2.5:50000 0 0 b'helloworld' False",
        "0 192.0.2.5:50000 10 0 b'' True",
        "b'helloworld'",
        "0",
    ]


# -- arguments ---------------------------------------------------------------


def test_add_takes_a_dissected_frame_and_nothing_else():
    reassembler = TCPReassembler()
    for wrong in (None, b"\x00" * 60, CapturedFrame(1.0, 1, b"")):
        with pytest.raises(TypeError):
            reassembler.add(wrong)


@pytest.mark.parametrize("option", ["max_streams", "max_buffered", "idle_timeout"])
@pytest.mark.parametrize("value", [0, -1])
def test_a_limit_that_is_not_positive_is_refused(option, value):
    with pytest.raises(ValueError):
        TCPReassembler(**{option: value})


def test_a_timeout_that_is_not_a_number_of_seconds_is_refused():
    with pytest.raises(ValueError):
        TCPReassembler(idle_timeout=float("nan"))


@pytest.mark.parametrize(
    "option, value",
    [
        ("max_streams", "8"),
        ("max_streams", 2.5),
        ("max_streams", True),
        ("max_buffered", None),
        ("idle_timeout", "5"),
        ("idle_timeout", True),
    ],
)
def test_an_option_of_the_wrong_type_is_a_type_error(option, value):
    with pytest.raises(TypeError):
        TCPReassembler(**{option: value})


def test_options_are_keyword_only():
    with pytest.raises(TypeError):
        TCPReassembler(10)  # type: ignore[misc]
