"""Writing TCP: single segments, and whole connections that read back exactly."""

import io
import random
import struct

import pytest

from pktcap import (
    PcapngWriter,
    PcapWriter,
    TCPFlowWriter,
    TCPLayer,
    read_dissected,
    read_frames,
    read_tcp_streams,
)

V4 = (("10.0.0.5", 50000), ("10.0.0.1", 443))
V6 = (("fd00::5", 50000), ("fd00::1", 443))
MIXED = (("10.0.0.5", 50000), ("fd00::1", 443))


def _ones_sum(data):
    """The 16-bit one's-complement sum, written here independently of pktcap."""
    if len(data) % 2:
        data += b"\0"
    total = 0
    for (word,) in struct.iter_unpack("!H", data):
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _checksums_hold(packet):
    """True when the IP header (IPv4) and TCP checksums of ``packet`` verify."""
    if packet[0] >> 4 == 4:
        header_length = (packet[0] & 0x0F) * 4
        if _ones_sum(packet[:header_length]) != 0xFFFF:
            return False
        src, dst, tcp = packet[12:16], packet[16:20], packet[header_length:]
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    else:
        src, dst, tcp = packet[8:24], packet[24:40], packet[40:]
        pseudo = src + dst + struct.pack("!I3xB", len(tcp), 6)
    return _ones_sum(pseudo + tcp) == 0xFFFF


def _streams(buffer):
    """Each direction's octets and whether it ended: {(stream, source): [data, end]}."""
    buffer.seek(0)
    got = {}
    for item in read_tcp_streams(buffer):
        assert item.missing == 0
        entry = got.setdefault((item.stream, item.source), [b"", False])
        entry[0] += item.data
        entry[1] = entry[1] or item.end
    return got


@pytest.mark.parametrize("ends", [V4, V6, MIXED], ids=["v4", "v6", "mixed"])
@pytest.mark.parametrize("mss", [1, 536, 1460, 9000])
@pytest.mark.parametrize("seed", range(4))
def test_a_written_connection_reads_back_exactly(ends, mss, seed):
    rng = random.Random(seed)
    client, server = ends
    buffer = io.BytesIO()
    sent = {"client": b"", "server": b""}
    with PcapWriter(buffer) as writer:
        flow = TCPFlowWriter(
            writer,
            client,
            server,
            mss=mss,
            # Near the top of the sequence space, so the numbers wrap.
            client_isn=(1 << 32) - rng.randrange(1, 3000),
            server_isn=rng.randrange(1 << 32),
        )
        flow.open(1.0)
        for step in range(12 if mss > 1 else 4):
            sender = rng.choice(["client", "server"])
            data = bytes(
                rng.randrange(256)
                for _ in range(rng.randrange(0, 4000 if mss > 1 else 50))
            )
            flow.send(2.0 + step, sender, data)
            sent[sender] += data
        flow.close(20.0, "client")
        flow.close(21.0, "server")
        buffer.seek(0)
        frames = list(read_frames(buffer))
    assert all(_checksums_hold(frame.data) for frame in frames)
    got = _streams(io.BytesIO(buffer.getvalue()))
    client_key = (0, (client[0], client[1]))
    server_key = (0, (server[0], server[1]))
    # A mixed pair travels as IPv6; the IPv4 end reads back v4-mapped.
    if ends is MIXED:
        client_key = (0, ("::ffff:" + client[0], client[1]))
    assert got[client_key] == [sent["client"], True]
    assert got[server_key] == [sent["server"], True]


def test_segments_carry_the_fields_asked_for():
    buffer = io.BytesIO()
    with PcapWriter(buffer) as writer:
        writer.write_tcp(5.0, *V4, b"hello", seq=100, ack=200, flags="PA", window=512)
    raw = buffer.getvalue()
    (frame,) = list(read_dissected(io.BytesIO(raw)))
    tcp = frame.layer(TCPLayer)
    assert (tcp.source_port, tcp.destination_port) == (50000, 443)
    assert (tcp.sequence, tcp.acknowledgment, tcp.flags, tcp.window) == (
        100,
        200,
        0x18,
        512,
    )
    assert frame.payload == b"hello"
    assert _checksums_hold(list(read_frames(io.BytesIO(raw)))[0].data)


def test_flags_may_be_letters_or_an_int():
    buffer = io.BytesIO()
    with PcapngWriter(buffer) as writer:
        writer.write_tcp(1.0, *V6, seq=1, flags="sa")
        writer.write_tcp(1.0, *V6, seq=1, flags=0x12)
    packets = [f.data for f in read_frames(io.BytesIO(buffer.getvalue()))]
    # IPv6 has no identification field, so the two packets are identical.
    assert packets[0] == packets[1]


@pytest.mark.parametrize(
    "kwargs, error",
    [
        ({"seq": -1}, ValueError),
        ({"seq": 1 << 32}, ValueError),
        ({"seq": 1, "ack": 1 << 32}, ValueError),
        ({"seq": 1, "flags": "X"}, ValueError),
        ({"seq": 1, "flags": 300}, ValueError),
        ({"seq": 1, "window": 70000}, ValueError),
        ({"seq": "1"}, TypeError),
        ({"seq": 1, "flags": 1.5}, TypeError),
    ],
)
def test_bad_segment_arguments_write_nothing(kwargs, error):
    buffer = io.BytesIO()
    writer = PcapWriter(buffer)
    with pytest.raises(error):
        writer.write_tcp(1.0, *V4, **kwargs)
    assert buffer.getvalue() == b""


def test_a_payload_too_large_for_one_packet_is_refused():
    with pytest.raises(ValueError, match="does not fit"):
        PcapWriter(io.BytesIO()).write_tcp(1.0, *V4, bytes(65496), seq=1)
    PcapWriter(io.BytesIO()).write_tcp(1.0, *V4, bytes(65495), seq=1)


def test_the_flow_refuses_what_a_connection_cannot_do():
    flow = TCPFlowWriter(PcapWriter(io.BytesIO()), *V4, client_isn=1, server_isn=2)
    with pytest.raises(ValueError, match="open"):
        flow.send(1.0, "client", b"x")
    flow.open(1.0)
    with pytest.raises(ValueError, match="already open"):
        flow.open(1.0)
    with pytest.raises(ValueError, match="sender"):
        flow.send(1.0, "middle", b"x")
    flow.close(2.0, "client")
    with pytest.raises(ValueError, match="ended"):
        flow.send(3.0, "client", b"x")
    flow.send(3.0, "server", b"still open")


def test_a_reset_ends_both_directions():
    buffer = io.BytesIO()
    with PcapWriter(buffer) as writer:
        flow = TCPFlowWriter(writer, *V4, client_isn=10, server_isn=20)
        flow.open(1.0)
        flow.send(2.0, "client", b"abc")
        flow.reset(3.0, "server")
        with pytest.raises(ValueError, match="ended"):
            flow.send(4.0, "server", b"x")
    got = _streams(io.BytesIO(buffer.getvalue()))
    assert got[(0, V4[0])][0] == b"abc"


@pytest.mark.parametrize(
    "kwargs, error",
    [
        ({"mss": 0}, ValueError),
        ({"mss": 65496}, ValueError),
        ({"client_isn": -1}, ValueError),
        ({"mss": "1"}, TypeError),
    ],
)
def test_bad_flow_arguments(kwargs, error):
    with pytest.raises(error):
        TCPFlowWriter(PcapWriter(io.BytesIO()), *V4, **kwargs)
    with pytest.raises(TypeError):
        TCPFlowWriter(object(), *V4)
