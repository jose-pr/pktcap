"""Live capture: its decoding path with the socket replaced, and the real
socket where the host allows it.

Opening ``AF_PACKET`` needs Linux and ``CAP_NET_RAW``, so every test but the
last replaces ``pktcap._live._open_socket`` (the one private name this suite
patches) with a socket that hands back what a cooked packet socket does:
``(packet, (interface, protocol, packet type, device type, address))``.
"""

import socket
import time

import pytest
from netimps import get_interfaces

import captures as build
from pktcap import (
    CapturedDatagram,
    CapturedFrame,
    FrameDecoder,
    LiveCapture,
    LiveCaptureError,
    PktcapError,
    has_live_capture,
    sniff,
)

V4 = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"request"))
V6 = build.ipv6("2001:db8::5", "2001:db8::1", build.udp(50000, 69, b"request"))
HOST, OUTGOING = 0, 4
ETHER, LOOPBACK = 1, 772


def _read(packet, protocol, kind=HOST, device=ETHER, name="eth0"):
    return packet, (name, protocol, kind, device, b"\x02" * 6)


class FakePacketSocket:
    """What `recvfrom` on a cooked packet socket returns, from a list."""

    def __init__(self, reads):
        self.reads = list(reads)
        self.closed = False
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def recvfrom(self, size):
        assert size >= 65535
        if not self.reads:
            raise socket.timeout("timed out")
        return self.reads.pop(0)

    def fileno(self):
        return 99

    def close(self):
        self.closed = True


@pytest.fixture
def packet_socket(monkeypatch):
    """Replace the privileged socket; returns a function that queues reads."""
    state = {"opened": [], "socket": None}

    def install(*reads):
        state["socket"] = FakePacketSocket(reads)
        return state["socket"]

    def open_socket(name):
        state["opened"].append(name)
        return state["socket"] or install()

    monkeypatch.setattr("pktcap._live._open_socket", open_socket)
    install.opened = state["opened"]
    return install


# -- the platform ---------------------------------------------------------


def test_the_probe_says_whether_the_platform_has_packet_sockets():
    assert has_live_capture() is hasattr(socket, "AF_PACKET")


def test_a_platform_without_packet_sockets_says_what_to_do_instead(monkeypatch):
    monkeypatch.setattr("pktcap._live._AF_PACKET", None)
    assert has_live_capture() is False
    with pytest.raises(LiveCaptureError, match="pipe a capture tool") as caught:
        LiveCapture().open()
    assert isinstance(caught.value, PktcapError) and isinstance(caught.value, OSError)
    with pytest.raises(LiveCaptureError):
        next(sniff())


# -- the lifecycle --------------------------------------------------------


def test_constructing_opens_nothing_and_open_is_idempotent(packet_socket):
    capture = LiveCapture()
    assert packet_socket.opened == []
    capture.open()
    capture.open()
    assert packet_socket.opened == [None]
    capture.close()
    capture.close()


def test_with_opens_and_closes_the_socket(packet_socket):
    fake = packet_socket()
    with LiveCapture() as capture:
        assert capture.fileno() == 99 and not fake.closed
    assert fake.closed


def test_a_closed_capture_stays_closed(packet_socket):
    capture = LiveCapture()
    capture.open()
    capture.close()
    with pytest.raises(ValueError, match="closed"):
        capture.open()
    for call in (capture.read, capture.fileno):
        with pytest.raises(ValueError, match="not open"):
            call()


def test_reading_before_opening_is_refused(packet_socket):
    with pytest.raises(ValueError, match="not open"):
        LiveCapture().read()


@pytest.mark.parametrize(
    "timeout, error",
    [(0, ValueError), (-1, ValueError), ("1", TypeError), (True, TypeError)],
)
def test_a_timeout_that_is_not_positive_is_refused(timeout, error):
    with pytest.raises(error):
        LiveCapture(timeout=timeout)


# -- what a read is worth -------------------------------------------------


def test_ip_packets_come_back_as_frames_of_their_family(packet_socket):
    packet_socket(_read(V4, 0x0800), _read(V6, 0x86DD))
    before = time.time()
    with LiveCapture() as capture:
        first, second = capture.read(), capture.read()
    assert (first.linktype, first.data) == (228, V4)
    assert (second.linktype, second.data) == (229, V6)
    assert isinstance(first, CapturedFrame) and before <= first.time <= time.time()


def test_what_is_not_ip_is_passed_over(packet_socket):
    arp = bytes(28)
    packet_socket(_read(arp, 0x0806), _read(arp, 0x88CC), _read(V4, 0x0800))
    with LiveCapture() as capture:
        assert capture.read().data == V4


def test_loopback_gives_each_packet_once(packet_socket):
    """A loopback device shows a packet leaving and arriving; a real one shows
    what this host sent only once."""
    packet_socket(
        _read(V4, 0x0800, OUTGOING, LOOPBACK, "lo"),
        _read(V4, 0x0800, HOST, LOOPBACK, "lo"),
        _read(V6, 0x86DD, OUTGOING, ETHER),
    )
    with LiveCapture() as capture:
        frames = [capture.read(), capture.read(), capture.read()]
    assert [f.linktype if f else None for f in frames] == [228, 229, None]


def test_loopback_is_told_by_the_device_type_not_the_name(packet_socket):
    packet_socket(
        _read(V4, 0x0800, OUTGOING, LOOPBACK, "renamed0"),
        _read(V4, 0x0800, OUTGOING, ETHER, "lo"),
    )
    with LiveCapture() as capture:
        assert capture.read() is not None and capture.read() is None


def test_a_quiet_interface_gives_none_after_the_timeout(packet_socket):
    fake = packet_socket()
    with LiveCapture(timeout=0.25) as capture:
        assert capture.read() is None
    assert fake.timeouts and 0 < fake.timeouts[0] <= 0.25


def test_iterating_yields_frames_until_the_capture_is_closed(packet_socket):
    packet_socket(_read(V4, 0x0800), _read(V6, 0x86DD), _read(V4, 0x0800))
    capture = LiveCapture(timeout=0.05)
    capture.open()
    seen = []
    for frame in capture:
        seen.append(frame.linktype)
        if len(seen) == 2:
            capture.close()
    assert seen == [228, 229]


# -- naming the interface -------------------------------------------------


def test_the_interface_may_be_an_object_a_name_or_an_address(packet_socket):
    chosen = next((i for i in get_interfaces() if i.is_loopback), None)
    if chosen is None:
        pytest.skip("this host reports no loopback interface to name")
    queries = [chosen, chosen.name]
    if any(str(address.ip) == "127.0.0.1" for address in chosen.ips):
        queries.append("127.0.0.1")
    for query in queries:
        with LiveCapture(query):
            pass
    assert packet_socket.opened == [chosen.name] * len(queries)


def test_an_interface_that_does_not_exist_is_refused_before_any_socket(packet_socket):
    with pytest.raises(ValueError, match="no interface matches"):
        LiveCapture("no-such-interface-0").open()
    assert packet_socket.opened == []


# -- the one-call form ----------------------------------------------------


def test_sniff_yields_the_datagrams_and_closes_the_socket(packet_socket):
    fake = packet_socket(_read(V4, 0x0800), _read(bytes(28), 0x0806), _read(V6, 0x86DD))
    calls = []

    def stop():
        calls.append(None)
        return len(calls) > 4

    datagrams = list(sniff(stop=stop))
    assert [(d.source, d.payload) for d in datagrams] == [
        (("10.0.0.5", 50000), b"request"),
        (("2001:db8::5", 50000), b"request"),
    ]
    assert all(isinstance(d, CapturedDatagram) for d in datagrams)
    assert fake.closed


def test_sniff_opens_at_the_first_datagram_and_closes_when_abandoned(packet_socket):
    fake = packet_socket(_read(V4, 0x0800), _read(V4, 0x0800))
    stream = sniff()
    assert packet_socket.opened == []
    assert next(stream).payload == b"request"
    assert packet_socket.opened == [None] and not fake.closed
    stream.close()
    assert fake.closed


def test_sniff_reassembles_and_a_decoder_passed_in_keeps_the_counts(packet_socket):
    datagram = build.udp(7, 9, b"f" * 64)
    packet_socket(
        _read(build.ipv4("10.0.0.5", "10.0.0.1", datagram[:32], more=True), 0x0800),
        _read(build.ipv4("10.0.0.5", "10.0.0.1", datagram[32:], offset=32), 0x0800),
    )
    decoder = FrameDecoder()
    stops = iter([False, False, True])
    (whole,) = list(sniff(stop=lambda: next(stops), decoder=decoder))
    assert whole.payload == b"f" * 64 and decoder.stats.fragments == 2


def test_sniff_checks_its_arguments_at_the_call(packet_socket):
    with pytest.raises(TypeError, match="callable"):
        sniff(stop=5)
    with pytest.raises(TypeError, match="FrameDecoder"):
        sniff(decoder=object())
    assert packet_socket.opened == []


# -- the real socket ------------------------------------------------------


def test_the_real_socket_captures_a_loopback_datagram_once():
    """Nothing is replaced here. One datagram sent to loopback is captured
    exactly once, with its payload and both its ports."""
    if not has_live_capture():
        pytest.skip("this platform has no AF_PACKET: live capture is Linux only")
    loopback = next((i for i in get_interfaces() if i.is_loopback), None)
    if loopback is None:
        pytest.skip("this host reports no loopback interface")
    capture = LiveCapture(loopback, timeout=0.2)
    try:
        capture.open()
    except PermissionError:
        pytest.skip("opening AF_PACKET needs CAP_NET_RAW: run as root to cover it")
    payload = b"pktcap live capture test %d" % time.time_ns()
    decoder = FrameDecoder()
    seen = []
    with capture, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        sent_to = receiver.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(payload, receiver.getsockname())
            sent_from = sender.getsockname()[1]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            frame = capture.read()
            if frame is None:
                if seen:
                    break
                continue
            seen += [d for d in decoder.decode(frame) if d.payload == payload]
    assert len(seen) == 1
    assert seen[0].source == ("127.0.0.1", sent_from)
    assert seen[0].destination == ("127.0.0.1", sent_to)
