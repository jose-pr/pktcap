"""TCP stream reassembly: each direction's octets in order, within bounds.

Every test builds TCP segments with the builders in ``captures.py``, has a real
``FrameDissector`` read them, and compares what the reassembler hands out with
the octets the test cut the segments from.
"""

import random

import pytest

import captures as build
from pktcap import (
    CapturedFrame,
    FrameDissector,
    TCPReassembler,
    TCPStreamData,
    TCPStreamStats,
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


def test_a_syn_after_a_finished_connection_starts_a_new_stream_without_a_second_end():
    wire = Wire()
    wire.send(999, b"x", flags=SYN | FIN)
    assert [i.end for i in wire.items] == [True]
    assert wire.send(7000, flags=SYN) == ()
    assert wire.send(7001, b"y")[0].stream == 1


def test_a_syn_ack_that_contradicts_the_connection_is_ignored():
    wire = Wire()
    wire.send(999, flags=SYN)
    assert wire.send(4999, flags=SYN | ACK, src=B, dst=A, ack=1234) == ()
    assert wire.stats.ignored == 1
    wire.send(4999, flags=SYN | ACK, src=B, dst=A, ack=1000)
    assert wire.send(5000, b"hi", src=B, dst=A)[0].offset == 0
    assert wire.stats.streams == 1 and wire.stats.ignored == 1


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
