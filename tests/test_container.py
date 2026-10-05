"""Reading the pcap and pcapng containers, and what a hostile one can cost."""

import io
import random
import struct
import tracemalloc

import pytest

import captures as build
from pktcap import CapturedFrame, CaptureFormatError, PktcapError, read_frames

FRAMES = [b"first frame", b"second", b"x" * 300]
GIB = 1 << 30


def _frames(data, **options):
    return list(read_frames(io.BytesIO(data), **options))


# -- what is read ---------------------------------------------------------


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nanoseconds", [False, True])
@pytest.mark.parametrize("container", [build.pcap, build.pcapng])
def test_every_frame_comes_back_with_its_time_and_link_type(
    container, endian, nanoseconds
):
    data = container(FRAMES, linktype=113, endian=endian, nanoseconds=nanoseconds)
    frames = _frames(data)
    assert [f.data for f in frames] == FRAMES
    assert [f.linktype for f in frames] == [113, 113, 113]
    assert [f.time for f in frames] == pytest.approx([1_000_000, 1_000_001, 1_000_002])
    assert all(isinstance(f, CapturedFrame) for f in frames)


def test_a_fraction_is_scaled_by_the_magic_number():
    micro = build.pcap([]) + build.pcap_record(b"a", seconds=5, fraction=250_000)
    nano = build.pcap([], nanoseconds=True) + build.pcap_record(
        b"a", seconds=5, fraction=250_000_000
    )
    assert _frames(micro)[0].time == pytest.approx(5.25)
    assert _frames(nano)[0].time == pytest.approx(5.25)


def test_a_pcap_link_type_ignores_the_frame_check_sequence_bits():
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0x10000001)
    assert _frames(data + build.pcap_record(b"a"))[0].linktype == 1


def test_a_path_and_a_stream_read_the_same(tmp_path):
    path = tmp_path / "one.pcap"
    path.write_bytes(build.pcap(FRAMES))
    assert list(read_frames(path)) == list(read_frames(str(path)))
    assert [f.data for f in read_frames(path)] == FRAMES


def test_an_empty_input_is_an_empty_capture():
    assert _frames(b"") == []


@pytest.mark.parametrize("container", [build.pcap, build.pcapng])
def test_a_stream_that_cannot_seek_and_reads_short_is_read(container):
    pipe = build.Pipe(container(FRAMES))
    assert not hasattr(pipe, "seek")
    assert [f.data for f in read_frames(pipe)] == FRAMES


def test_frames_are_yielded_as_they_are_read_and_damage_raises_after_them():
    data = build.pcap(FRAMES) + build.pcap_record(b"cut", captured=100)
    reader = read_frames(io.BytesIO(data))
    assert [next(reader).data for _ in FRAMES] == FRAMES
    with pytest.raises(CaptureFormatError, match="ends inside a packet record"):
        next(reader)


def test_pcapng_interfaces_each_carry_their_link_type_resolution_and_offset():
    data = (
        build.section()
        + build.interface(1)
        + build.interface(113, tsresol=9)
        + build.interface(101, tsresol=0x80 | 10, tsoffset=1000)
        + build.packet(b"a", iface=0, stamp=2_500_000)
        + build.packet(b"b", iface=1, stamp=2_500_000_000)
        + build.packet(b"c", iface=2, stamp=2560)
    )
    frames = _frames(data)
    assert [(f.linktype, f.data) for f in frames] == [
        (1, b"a"),
        (113, b"b"),
        (101, b"c"),
    ]
    assert [f.time for f in frames] == pytest.approx([2.5, 2.5, 1002.5])


def test_a_new_section_forgets_the_interfaces_and_may_change_byte_order():
    data = (
        build.section()
        + build.interface(1)
        + build.packet(b"little")
        + build.section(endian=">")
        + build.interface(101, endian=">")
        + build.packet(b"big", endian=">")
    )
    assert [(f.linktype, f.data) for f in _frames(data)] == [
        (1, b"little"),
        (101, b"big"),
    ]


def test_the_two_other_packet_blocks_are_read():
    simple = build.block(3, struct.pack("<I", 5) + b"hello")
    obsolete = build.block(2, struct.pack("<HHIIII", 0, 0, 0, 3_000_000, 3, 3) + b"old")
    frames = _frames(build.section() + build.interface(1) + simple + obsolete)
    assert [(f.time, f.data) for f in frames] == [(0.0, b"hello"), (3.0, b"old")]


def test_a_block_that_is_not_needed_is_skipped_without_being_held():
    """A name-resolution or secrets block may be megabytes; it is read in
    pieces and discarded, so it costs time and never memory."""
    big = build.block(4, b"n" * (3 << 20))
    pipe = build.Pipe(
        build.section() + build.interface(1) + big + build.packet(b"after"), 1 << 20
    )
    assert [f.data for f in read_frames(pipe)] == [b"after"]
    assert pipe.largest_request <= 65536


# -- what is refused ------------------------------------------------------


def test_the_error_is_one_type_and_says_where():
    with pytest.raises(CaptureFormatError) as caught:
        _frames(b"hello world")
    assert isinstance(caught.value, PktcapError)
    assert isinstance(caught.value, ValueError)
    assert caught.value.offset == 0
    assert "not a pcap or pcapng capture" in str(caught.value)
    assert "hello" not in str(caught.value)


@pytest.mark.parametrize(
    "data, problem",
    [
        (build.pcap([])[:10], "ends inside the file header"),
        (build.pcap([]) + b"\x01\x02\x03", "ends inside a packet record header"),
        (build.pcap([]) + build.pcap_record(b"", captured=4), "ends inside a packet"),
        (build.section()[:14], "ends inside a block"),
        (build.section() + build.interface()[:6], "ends inside a block header"),
        (build.section() + build.block(1, b"", length=8), "impossible length"),
        (build.section() + build.block(1, b"", length=14), "impossible length"),
        (build.section(length=16), "impossible length"),
        (build.section() + build.block(1, b"abcd"), "interface description is cut"),
        (build.section() + build.interface() + build.block(6, b"abcd"), "cut short"),
        (build.section() + build.interface() + build.block(3, b""), "cut short"),
        (
            build.section() + build.interface() + build.packet(b"abcd", captured=64),
            "longer than the block",
        ),
        (build.section() + build.packet(b"abcd"), "interface its section does not"),
        (
            build.section() + build.interface() + build.packet(b"abcd", iface=1),
            "interface its section does not",
        ),
        (
            build.section() + build.interface() + build.block(3, b"abcd", trailer=99),
            "lengths disagree",
        ),
        (build.section() + build.block(9, b"abcd", trailer=99), "lengths disagree"),
        (b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\0" * 20, "byte-order magic"),
    ],
)
def test_a_damaged_capture_is_a_format_error(data, problem):
    with pytest.raises(CaptureFormatError, match=problem):
        _frames(data)


def test_a_text_stream_is_a_type_error_not_a_format_error():
    with pytest.raises(TypeError, match="binary stream"):
        list(read_frames(io.StringIO("abcd")))


@pytest.mark.parametrize("source", [None, 5, b"\xd4\xc3\xb2\xa1"])
def test_a_source_that_is_neither_path_nor_stream_is_refused_at_the_call(source):
    with pytest.raises(TypeError, match="path or a binary stream"):
        read_frames(source)


@pytest.mark.parametrize(
    "size, error",
    [(0, ValueError), (-1, ValueError), (1.5, TypeError), (True, TypeError)],
)
def test_a_bad_frame_limit_is_refused_at_the_call(size, error):
    with pytest.raises(error):
        read_frames(io.BytesIO(b""), max_frame_size=size)


# -- what a hostile capture can cost --------------------------------------

#: Captures that state a 1 GiB length and hold almost nothing.
HOSTILE = {
    "pcap record": build.pcap([]) + build.pcap_record(b"\0" * 8, captured=GIB),
    "pcapng packet block": build.section()
    + build.interface()
    + struct.pack("<II", 6, GIB)
    + b"\0" * 32,
    "pcapng section header": b"\x0a\x0d\x0d\x0a"
    + struct.pack("<II", GIB, 0x1A2B3C4D)
    + b"\0" * 8,
    "pcapng interface block": build.section() + struct.pack("<II", 1, GIB) + b"\0" * 8,
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_a_claimed_length_is_refused_before_it_is_read(name):
    """The reader never asks its stream for more than a ceiling allows."""
    pipe = build.Pipe(HOSTILE[name], chunk=1 << 16)
    with pytest.raises(CaptureFormatError, match="over the limit"):
        list(read_frames(pipe))
    assert pipe.largest_request <= 1 << 20


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_a_small_file_claiming_a_gibibyte_allocates_almost_nothing(name, tmp_path):
    path = tmp_path / "hostile.pcap"
    path.write_bytes(HOSTILE[name])
    assert path.stat().st_size < 128
    tracemalloc.start()
    try:
        with pytest.raises(CaptureFormatError):
            list(read_frames(path))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 1 << 20, "%d octets allocated for a %d-octet file" % (
        peak,
        path.stat().st_size,
    )


def test_a_skipped_block_claiming_a_gibibyte_ends_as_a_truncation():
    data = build.section() + struct.pack("<II", 4, GIB) + b"\0" * 64
    pipe = build.Pipe(data, chunk=1 << 20)
    with pytest.raises(CaptureFormatError, match="ends inside a block"):
        list(read_frames(pipe))
    assert pipe.largest_request <= 65536


def test_the_frame_limit_is_the_callers_to_move():
    data = build.pcap([b"x" * 2000])
    with pytest.raises(CaptureFormatError, match="2000 octets, over the limit of 1500"):
        _frames(data, max_frame_size=1500)
    assert len(_frames(data, max_frame_size=2000)[0].data) == 2000
    packet_block = build.pcapng([b"x" * 2000])
    with pytest.raises(CaptureFormatError, match="over the limit of 1500"):
        _frames(packet_block, max_frame_size=1500)


def test_a_section_may_not_describe_interfaces_without_end():
    data = build.section() + build.interface() * 4097
    with pytest.raises(CaptureFormatError, match="more than 4096 interfaces"):
        _frames(data)
    assert _frames(build.section() + build.interface() * 4096) == []


@pytest.mark.parametrize("container", [build.pcap, build.pcapng])
def test_a_mutated_capture_is_read_or_refused_and_nothing_else(container):
    """Seeded fuzz: any damage is a `CaptureFormatError`, never a
    `struct.error`, an `IndexError` or a silent hang."""
    random.seed(20261005)
    good = bytearray(container([b"abcdefgh" * 4, b"ij" * 9, b"k" * 40], linktype=1))
    refused = 0
    for _ in range(5000):
        data = bytearray(good)
        for _ in range(random.randint(1, 4)):
            choice = random.random()
            position = random.randrange(len(data))
            if choice < 0.5:
                data[position] = random.randrange(256)
            elif choice < 0.75:
                del data[position : position + random.randint(1, 8)]
            else:
                data = data[:position]
            if not data:
                break
        try:
            for frame in read_frames(io.BytesIO(bytes(data))):
                assert len(frame.data) <= 262144
        except CaptureFormatError:
            refused += 1
    assert refused > 500  # the mutations do damage the capture


def test_a_block_of_any_kind_and_any_size_is_read_or_refused():
    """Seeded fuzz of whole blocks: each has a kind, a body length and a body
    drawn at random, with its two lengths agreeing, so the damage reaches the
    code that reads inside a block."""
    random.seed(20261005)
    kinds = [1, 2, 3, 6, 6, 6, 4, 0x0A0D0D0A, 99]
    refused = read = 0
    for _ in range(5000):
        data = build.section() + build.interface()
        for _ in range(random.randint(1, 4)):
            body = bytes(random.randrange(256) for _ in range(random.randint(0, 40)))
            if random.random() < 0.3:
                body = bytes(8) + body  # a plausible interface id and timestamp
            data += build.block(random.choice(kinds), body)
        try:
            read += len(list(read_frames(io.BytesIO(data))))
        except CaptureFormatError:
            refused += 1
    assert refused > 500 and read > 100  # both outcomes are reached
