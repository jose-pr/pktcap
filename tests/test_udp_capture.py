"""``UDPCapture``, ``sniff_udp`` and ``asniff_udp``: datagrams arriving at
sockets the caller bound, read as frames.

Every socket is on loopback, bound to port 0, and the port is read back. A
datagram is waited for with a bound of seconds, never a fixed sleep.
"""

import asyncio
import errno
import gc
import selectors
import socket
import subprocess
import sys
import textwrap
import threading
import time
from typing import NamedTuple

import pytest
from netimps import UDPEndpoint, bind, get_interface, set_buffer_size

import pktcap
from pktcap import (
    CapturedFrame,
    DissectedFrame,
    DissectorRegistry,
    FrameDissector,
    IPv4Layer,
    IPv6Layer,
    UDPCapture,
    UDPLayer,
    asniff_udp,
    sniff_udp,
)

WAIT = 5.0


def _has_ipv6_loopback():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        return False
    return True


def listener(host="127.0.0.1"):
    return UDPEndpoint(bind(host, 0))


def port_of(endpoint):
    return endpoint.socket.getsockname()[1]


def send(payload, endpoint, host="127.0.0.1"):
    """Send ``payload`` to ``endpoint`` from a socket of the test's own; the
    sender's address is returned."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sender:
        sender.bind((host, 0))
        sender.sendto(payload, (host, port_of(endpoint)))
        return sender.getsockname()[:2]


def wait_readable(*endpoints):
    """Block until every endpoint holds a datagram, for at most WAIT seconds."""
    with selectors.DefaultSelector() as selector:
        for endpoint in endpoints:
            selector.register(endpoint.socket, selectors.EVENT_READ)
        pending = len(endpoints)
        deadline = time.monotonic() + WAIT
        seen = set()
        while len(seen) < pending and time.monotonic() < deadline:
            for key, _ in selector.select(0.1):
                seen.add(key.fd)
    assert len(seen) == pending, "a datagram did not arrive on loopback"


def read_one(capture):
    """The next frame, waiting up to WAIT seconds for one."""
    deadline = time.monotonic() + WAIT
    while time.monotonic() < deadline:
        frame = capture.read()
        if frame is not None:
            return frame
    raise AssertionError("no frame within %s seconds" % WAIT)


def closed(endpoint):
    return endpoint.socket.fileno() == -1


# -- one datagram, as a frame ------------------------------------------------


def test_a_datagram_sent_to_a_socket_is_read_as_a_frame_and_dissects():
    endpoint = listener()
    port = port_of(endpoint)
    capture = UDPCapture([endpoint])
    try:
        sender = send(b"hello", endpoint)
        frame = read_one(capture)
    finally:
        capture.close()
    assert isinstance(frame, CapturedFrame) and frame.linktype == 101
    assert abs(frame.time - time.time()) < 60
    datagram = FrameDissector().dissect(frame).datagram()
    assert datagram.payload == b"hello"
    assert datagram.source == sender
    assert datagram.destination == ("127.0.0.1", port)
    assert not datagram.truncated and not datagram.fragmented


def test_the_arrival_interface_is_the_frames_interface():
    endpoint = listener()
    if not endpoint.has_pktinfo:
        endpoint.close()
        pytest.skip("this host reports no arrival interface")
    expected = get_interface("127.0.0.1").index
    with UDPCapture([endpoint]) as capture:
        send(b"x", endpoint)
        frame = read_one(capture)
    assert frame.interface == expected != 0


def test_a_host_that_cannot_say_which_interface_leaves_it_unknown():
    endpoint = listener()
    endpoint.has_pktinfo = False
    with UDPCapture([endpoint]) as capture:
        send(b"x", endpoint)
        frame = read_one(capture)
    assert frame.interface is None


def test_the_registered_dissector_of_the_port_is_applied():
    class Demo(NamedTuple):
        first: int

    endpoint = listener()
    registry = DissectorRegistry()
    registry.register_layer(Demo, name="demo")
    registry.register(
        "udp", port_of(endpoint), lambda data: pktcap.Dissected(Demo(data[0]), data[1:])
    )
    frames = sniff_udp([endpoint], dissector=FrameDissector(registry))
    try:
        send(b"\x07rest", endpoint)
        frame = next(frames)
    finally:
        frames.close()
    assert isinstance(frame, DissectedFrame)
    assert [type(layer) for layer in frame.layers] == [IPv4Layer, UDPLayer, Demo]
    assert frame.layers[-1].first == 7 and frame.payload == b"rest"


def test_the_source_port_dissector_applies_when_the_destination_has_none():
    class Demo(NamedTuple):
        first: int

    endpoint = listener()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.bind(("127.0.0.1", 0))
        registry = DissectorRegistry()
        registry.register_layer(Demo, name="demo")
        registry.register(
            "udp",
            sender.getsockname()[1],
            lambda data: pktcap.Dissected(Demo(data[0]), data[1:]),
        )
        frames = sniff_udp([endpoint], dissector=FrameDissector(registry))
        try:
            sender.sendto(b"\x09z", ("127.0.0.1", port_of(endpoint)))
            frame = next(frames)
        finally:
            frames.close()
    assert isinstance(frame.layers[-1], Demo)


def test_a_quiet_read_gives_none_after_the_timeout():
    endpoint = listener()
    with UDPCapture([endpoint], timeout=0.2) as capture:
        started = time.monotonic()
        assert capture.read() is None
        assert 0.1 <= time.monotonic() - started < 3


@pytest.mark.skipif(not _has_ipv6_loopback(), reason="no IPv6 loopback address")
def test_an_ipv6_datagram_is_an_ipv6_frame():
    endpoint = listener("::1")
    port = port_of(endpoint)
    with UDPCapture([endpoint]) as capture:
        sender = send(b"six", endpoint, "::1")
        frame = FrameDissector().dissect(read_one(capture))
    assert frame.layer(IPv6Layer) is not None
    assert frame.datagram().source == sender
    assert frame.datagram().destination == ("::1", port)


def test_a_dual_stack_socket_reading_ipv4_gives_an_ipv4_frame():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", 0))
    except OSError:
        sock.close()
        pytest.skip("this host cannot bind a dual-stack IPv6 wildcard")
    endpoint = UDPEndpoint(sock)
    with UDPCapture([endpoint]) as capture:
        sender = send(b"mapped", endpoint)
        frame = FrameDissector().dissect(read_one(capture))
    datagram = frame.datagram()
    assert datagram.payload == b"mapped" and datagram.source == sender
    assert frame.layer(IPv4Layer) is not None


def test_a_destination_the_host_does_not_report_is_the_bound_address():
    endpoint = listener()
    endpoint.has_pktinfo = False
    port = port_of(endpoint)
    with UDPCapture([endpoint]) as capture:
        send(b"x", endpoint)
        datagram = FrameDissector().dissect(read_one(capture)).datagram()
    assert datagram.destination == ("127.0.0.1", port)


# -- the bounds ----------------------------------------------------------------


def test_a_datagram_over_max_size_is_counted_and_not_returned():
    endpoint = listener()
    with UDPCapture([endpoint], max_size=100) as capture:
        send(b"a" * 101, endpoint)
        send(b"b" * 100, endpoint)
        send(b"c" * 5000, endpoint)
        send(b"d", endpoint)
        first = read_one(capture)
        second = read_one(capture)
    payloads = [FrameDissector().dissect(f).datagram().payload for f in (first, second)]
    assert payloads == [b"b" * 100, b"d"]
    assert capture.truncated == 2


def test_the_default_max_size_takes_the_largest_datagram_a_socket_holds():
    # Measured 2026-10-09: macOS 15.7 and FreeBSD 16.0 refuse a UDP send above
    # net.inet.udp.maxdgram (9216 by default) with EMSGSIZE; Linux and Windows
    # send 65507. The test sends the largest datagram the host will send.
    endpoint = listener()
    with UDPCapture([endpoint]) as capture:
        size = 65507
        try:
            send(b"z" * size, endpoint)
        except OSError as exc:
            if exc.errno != errno.EMSGSIZE:
                raise
            size = 9216
            send(b"z" * size, endpoint)
        datagram = FrameDissector().dissect(read_one(capture)).datagram()
    assert datagram.payload == b"z" * size and capture.truncated == 0


@pytest.mark.parametrize("max_size", [0, -1, 65536])
def test_a_max_size_outside_what_a_datagram_can_be_is_refused(max_size):
    endpoint = listener()
    try:
        with pytest.raises(ValueError, match="max_size"):
            UDPCapture([endpoint], max_size=max_size)
        assert not closed(endpoint)  # not taken over: the call failed
    finally:
        endpoint.close()


@pytest.mark.parametrize("timeout", [0, -1.0, float("nan")])
def test_a_timeout_that_is_not_positive_is_refused(timeout):
    endpoint = listener()
    try:
        with pytest.raises(ValueError, match="timeout"):
            UDPCapture([endpoint], timeout=timeout)
    finally:
        endpoint.close()


@pytest.mark.parametrize("option", ["timeout", "max_size"])
@pytest.mark.parametrize("value", [True, "1", None])
def test_an_option_of_the_wrong_type_is_a_type_error(option, value):
    endpoint = listener()
    try:
        with pytest.raises(TypeError):
            UDPCapture([endpoint], **{option: value})
    finally:
        endpoint.close()


def test_the_endpoints_are_a_nonempty_list_of_endpoints():
    with pytest.raises(ValueError, match="endpoint"):
        UDPCapture([])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as plain:
        with pytest.raises(TypeError, match="UDPEndpoint"):
            UDPCapture([plain])
    with pytest.raises(TypeError):
        UDPCapture(42)


def test_there_is_a_ceiling_on_how_many_endpoints_one_capture_reads():
    def endless():
        while True:
            yield object()

    # An iterator that never ends is not read to its end, and the count is
    # refused before the first item is looked at.
    with pytest.raises(ValueError, match="at most 256"):
        UDPCapture(endless())
    with pytest.raises(ValueError, match="at most 256"):
        sniff_udp([object()] * 257)


def test_the_options_are_keyword_only():
    endpoint = listener()
    try:
        with pytest.raises(TypeError):
            UDPCapture([endpoint], 1.0)
        with pytest.raises(TypeError):
            sniff_udp([endpoint], lambda: False)
    finally:
        endpoint.close()


def test_a_stop_that_is_not_callable_and_a_dissector_that_is_not_one_are_refused_at_the_call():
    endpoint = listener()
    try:
        with pytest.raises(TypeError, match="stop"):
            sniff_udp([endpoint], stop=3)
        with pytest.raises(TypeError, match="dissector"):
            sniff_udp([endpoint], dissector=object())
        with pytest.raises(TypeError, match="dissector"):
            asniff_udp([endpoint], dissector=object())
        assert not closed(endpoint)  # refused before it was taken over
    finally:
        endpoint.close()


# -- several sockets -----------------------------------------------------------


def test_every_endpoint_is_read():
    first, second = listener(), listener()
    with UDPCapture([first, second]) as capture:
        send(b"one", first)
        send(b"two", second)
        got = {
            FrameDissector().dissect(read_one(capture)).datagram().payload
            for _ in range(2)
        }
    assert got == {b"one", b"two"}


def test_a_busy_endpoint_does_not_starve_a_quiet_one():
    busy, quiet = listener(), listener()
    with UDPCapture([busy, quiet]) as capture:
        for index in range(20):
            send(b"busy%d" % index, busy)
        send(b"quiet", quiet)
        wait_readable(busy, quiet)
        payloads = [
            FrameDissector().dissect(read_one(capture)).datagram().payload
            for _ in range(4)
        ]
    assert b"quiet" in payloads


# -- the lifecycle: every exit closes the sockets ---------------------------


def test_close_closes_every_endpoint_and_is_harmless_twice():
    endpoints = [listener(), listener()]
    capture = UDPCapture(endpoints)
    capture.close()
    capture.close()
    assert all(closed(e) for e in endpoints)
    with pytest.raises(ValueError, match="closed"):
        capture.read()


def test_the_context_manager_closes_on_an_exception():
    endpoint = listener()
    with pytest.raises(RuntimeError):
        with UDPCapture([endpoint]):
            raise RuntimeError("the consumer failed")
    assert closed(endpoint)


def test_iterating_a_capture_yields_frames_until_it_is_closed():
    endpoint = listener()
    capture = UDPCapture([endpoint], timeout=0.2)
    send(b"a", endpoint)
    frames = iter(capture)
    assert FrameDissector().dissect(next(frames)).datagram().payload == b"a"
    capture.close()
    assert list(frames) == []


def test_an_iterator_that_ends_by_stop_has_closed_its_sockets():
    endpoint = listener()
    calls = []

    def stop():
        calls.append(1)
        return len(calls) > 1

    send(b"one", endpoint)
    frames = list(sniff_udp([endpoint], stop=stop))
    assert len(frames) == 1 and closed(endpoint)


def test_stop_is_asked_within_a_second_on_a_quiet_socket():
    endpoint = listener()
    started = time.monotonic()
    assert (
        list(sniff_udp([endpoint], stop=lambda: time.monotonic() - started > 0.1)) == []
    )
    assert closed(endpoint)
    assert time.monotonic() - started < 4


def test_closing_the_iterator_closes_the_sockets_even_when_never_started():
    endpoint = listener()
    frames = sniff_udp([endpoint])
    assert not closed(endpoint)
    frames.close()
    assert closed(endpoint)
    assert list(frames) == []


def test_a_consumer_that_fails_leaves_no_socket_open_once_it_closes_the_iterator():
    endpoint = listener()
    send(b"x", endpoint)
    frames = sniff_udp([endpoint])
    with pytest.raises(RuntimeError):
        try:
            for _ in frames:
                raise RuntimeError("the consumer failed")
        finally:
            frames.close()
    assert closed(endpoint)


def test_an_iterator_that_is_dropped_closes_its_sockets():
    endpoint = listener()
    send(b"x", endpoint)
    frames = sniff_udp([endpoint])
    next(frames)
    del frames
    gc.collect()
    assert closed(endpoint)


def test_an_exception_from_stop_closes_the_sockets_and_propagates():
    endpoint = listener()

    def stop():
        raise RuntimeError("stop failed")

    frames = sniff_udp([endpoint], stop=stop)
    with pytest.raises(RuntimeError, match="stop failed"):
        next(frames)
    assert closed(endpoint)


def test_copy_frames_over_a_socket_source_writes_what_arrived():
    import io

    endpoint = listener()
    out = io.BytesIO()
    send(b"first", endpoint)
    send(b"second", endpoint)
    frames = sniff_udp([endpoint])
    try:
        with pktcap.CaptureWriter(out, "pcapng") as writer:
            result = pktcap.copy_frames(frames, writer, limit=2)
    finally:
        frames.close()
    assert result.written == 2 and closed(endpoint)
    out.seek(0)
    got = [f.datagram().payload for f in pktcap.read_dissected(out)]
    assert got == [b"first", b"second"]


# -- the asynchronous twin -------------------------------------------------------


def _tasks_left():
    return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]


def test_the_twin_gives_the_same_frames_for_the_same_datagrams():
    payloads = [b"alpha", b"", b"b" * 1200, bytes(range(256))]
    sync_endpoint, async_endpoint = listener(), listener()
    for payload in payloads:
        send(payload, sync_endpoint)
        send(payload, async_endpoint)
    frames = sniff_udp([sync_endpoint])
    try:
        wanted = [next(frames) for _ in payloads]
    finally:
        frames.close()

    async def run():
        got = []
        stream = asniff_udp([async_endpoint])
        try:
            async for frame in stream:
                got.append(frame)
                if len(got) == len(payloads):
                    break
        finally:
            await stream.aclose()
        return got, _tasks_left()

    got, left = asyncio.run(run())
    assert left == []

    def shape(frame):
        datagram = frame.datagram()
        return (
            [type(layer) for layer in frame.layers],
            datagram.payload,
            datagram.source[0],
            datagram.destination[0],
            frame.frame.linktype,
            frame.error,
        )

    assert [shape(f) for f in got] == [shape(f) for f in wanted]
    assert closed(async_endpoint)


def test_the_twin_applies_the_dissector_it_is_given():
    class Demo(NamedTuple):
        first: int

    endpoint = listener()
    registry = DissectorRegistry()
    registry.register_layer(Demo, name="demo")
    registry.register(
        "udp", port_of(endpoint), lambda data: pktcap.Dissected(Demo(data[0]), data[1:])
    )

    async def run():
        stream = asniff_udp([endpoint], dissector=FrameDissector(registry))
        try:
            send(b"\x05tail", endpoint)
            return await stream.__anext__()
        finally:
            await stream.aclose()

    frame = asyncio.run(run())
    assert isinstance(frame.layers[-1], Demo) and frame.layers[-1].first == 5


def test_stopping_early_leaves_no_task_no_socket_and_no_thread():
    endpoints = [listener(), listener()]
    threads = threading.active_count()

    async def run():
        stream = asniff_udp(endpoints)
        send(b"one", endpoints[0])
        frame = await stream.__anext__()
        await stream.aclose()
        await stream.aclose()  # harmless twice
        return frame, _tasks_left()

    frame, left = asyncio.run(run())
    assert frame.datagram().payload == b"one"
    assert left == []
    assert all(closed(e) for e in endpoints)
    assert threading.active_count() <= threads


def test_a_cancelled_consumer_leaves_no_task_and_no_socket():
    endpoints = [listener(), listener()]
    threads = threading.active_count()

    async def run():
        stream = asniff_udp(endpoints)
        waiting = asyncio.ensure_future(stream.__anext__())
        for _ in range(5):  # let it reach its wait
            await asyncio.sleep(0)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        return _tasks_left()

    assert asyncio.run(run()) == []
    assert all(closed(e) for e in endpoints)
    assert threading.active_count() <= threads


def test_a_stream_never_started_is_closed_by_aclose():
    endpoint = listener()

    async def run():
        stream = asniff_udp([endpoint])
        await stream.aclose()
        with pytest.raises(StopAsyncIteration):
            await stream.__anext__()

    asyncio.run(run())
    assert closed(endpoint)


def test_aread_gives_none_when_quiet_and_counts_what_is_too_big():
    endpoint = listener()

    async def run():
        capture = UDPCapture([endpoint], timeout=0.2, max_size=10)
        try:
            assert await capture.aread() is None
            send(b"x" * 11, endpoint)
            send(b"ok", endpoint)
            deadline = time.monotonic() + WAIT
            frame = None
            while frame is None and time.monotonic() < deadline:
                frame = await capture.aread()
            return frame, capture.truncated
        finally:
            await capture.aclose()

    frame, truncated = asyncio.run(run())
    assert FrameDissector().dissect(frame).datagram().payload == b"ok"
    assert truncated == 1 and closed(endpoint)


class FailingEndpoint(UDPEndpoint):
    """An endpoint whose receive fails, as a socket can under its reader."""

    async def arecv(self, bufsize=65535, *, resolve_interface=True):
        raise OSError("the receive failed")


def test_a_failed_receive_reaches_the_reader_and_the_sockets_still_close():
    healthy = listener()
    failing = FailingEndpoint(bind("127.0.0.1", 0))

    async def run():
        capture = UDPCapture([healthy, failing], timeout=0.5)
        try:
            with pytest.raises(OSError, match="the receive failed"):
                deadline = time.monotonic() + WAIT
                while time.monotonic() < deadline:
                    await capture.aread()
        finally:
            await capture.aclose()
        return _tasks_left()

    assert asyncio.run(run()) == []
    assert closed(healthy) and closed(failing)


def test_a_queue_that_is_full_holds_the_readers_and_loses_nothing_it_took():
    endpoint = listener()

    async def run():
        capture = UDPCapture([endpoint], timeout=0.2)
        try:
            assert await capture.aread() is None
            for index in range(200):
                send(b"%03d" % index, endpoint)
            seen = []
            deadline = time.monotonic() + WAIT
            while len(seen) < 200 and time.monotonic() < deadline:
                frame = await capture.aread()
                if frame is not None:
                    seen.append(FrameDissector().dissect(frame).datagram().payload)
            return seen
        finally:
            await capture.aclose()

    seen = asyncio.run(run())
    # The kernel may drop what its buffer cannot hold; what was read is in order.
    assert seen == sorted(seen) and len(seen) == len(set(seen)) and seen


def test_the_asynchronous_queue_stops_the_readers_so_the_kernel_drops_the_rest():
    """A consumer that is not reading holds the readers at a bound: the rest of
    what is sent is left to the kernel's buffer, which drops it. With no bound
    the readers would keep taking every datagram off the socket."""
    endpoint = listener()
    # The kernel's buffer is made small, so that it cannot hold what the
    # readers leave: macOS gives a UDP socket about 768 KiB by default
    # (measured 2026-10-09: 1480 of 2000 500-octet datagrams were kept), which
    # holds most of what this sends.
    set_buffer_size(endpoint.socket, receive=16384)
    sent = 2000

    async def run():
        capture = UDPCapture([endpoint], timeout=0.2)
        try:
            assert await capture.aread() is None  # the readers are running
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                for batch in range(sent // 20):
                    for _ in range(20):
                        sender.sendto(b"x" * 500, ("127.0.0.1", port_of(endpoint)))
                    await asyncio.sleep(0.01)
            await asyncio.sleep(0.3)
            seen = 0
            while await capture.aread() is not None:
                seen += 1
            return seen
        finally:
            await capture.aclose()

    seen = asyncio.run(run())
    assert 0 < seen < sent // 2


# -- imports -----------------------------------------------------------------------


def test_the_socket_source_imports_no_asyncio_until_the_twin_is_used():
    source = """
        import socket, sys
        import pktcap
        from netimps import UDPEndpoint, bind

        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        port = endpoint.socket.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"hello", ("127.0.0.1", port))
        frames = pktcap.sniff_udp([endpoint])
        frame = next(frames)
        frames.close()
        assert frame.datagram().payload == b"hello"
        print("asyncio" in sys.modules)
        """
    code = textwrap.dedent(source)
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "False"


# -- an endpoint limited to interfaces ------------------------------------------


def _other_interface():
    """An interface with an index that loopback traffic does not arrive on."""
    from netimps import get_interfaces

    loopback = get_interface("127.0.0.1").index
    for interface in get_interfaces():
        if interface.index and interface.index != loopback:
            return interface
    return None


def limited(interfaces, host="127.0.0.1"):
    endpoint = UDPEndpoint(bind(host, 0), interfaces=interfaces)
    if not endpoint.has_pktinfo:
        endpoint.close()
        pytest.skip("this host reports no arrival interface")
    return endpoint


def test_a_datagram_from_an_interface_the_endpoint_does_not_serve_is_counted_not_returned():
    other = _other_interface()
    if other is None:
        pytest.skip("this host has no adapter besides loopback")
    endpoint = limited([other])
    with UDPCapture([endpoint], timeout=0.5) as capture:
        send(b"not for this endpoint", endpoint)
        wait_readable(endpoint)
        assert capture.read() is None
        assert capture.not_admitted == 1 and capture.truncated == 0


def test_a_datagram_from_an_interface_the_endpoint_serves_is_returned():
    endpoint = limited([get_interface("127.0.0.1")])
    with UDPCapture([endpoint]) as capture:
        send(b"served", endpoint)
        frame = read_one(capture)
        assert capture.not_admitted == 0
    assert FrameDissector().dissect(frame).datagram().payload == b"served"


def test_one_endpoint_refusing_does_not_hide_the_datagram_of_another():
    other = _other_interface()
    if other is None:
        pytest.skip("this host has no adapter besides loopback")
    refusing, serving = limited([other]), limited([])
    with UDPCapture([refusing, serving]) as capture:
        send(b"dropped", refusing)
        send(b"kept", serving)
        wait_readable(refusing, serving)
        frame = read_one(capture)
        assert FrameDissector().dissect(frame).datagram().payload == b"kept"
        assert capture.not_admitted == 1


def test_the_asynchronous_read_drops_and_counts_what_the_endpoint_does_not_admit():
    other = _other_interface()
    if other is None:
        pytest.skip("this host has no adapter besides loopback")
    refusing, serving = limited([other]), limited([])

    async def run():
        capture = UDPCapture([refusing, serving], timeout=0.2)
        try:
            send(b"dropped", refusing)
            send(b"kept", serving)
            deadline = time.monotonic() + WAIT
            frame = None
            while frame is None and time.monotonic() < deadline:
                frame = await capture.aread()
            for _ in range(20):  # the refused one may still be in its reader's hand
                if capture.not_admitted:
                    break
                await asyncio.sleep(0.05)
            return frame, capture.not_admitted
        finally:
            await capture.aclose()

    frame, count = asyncio.run(run())
    assert FrameDissector().dissect(frame).datagram().payload == b"kept"
    assert count == 1


def test_sniff_udp_gives_no_frame_for_a_datagram_its_endpoint_does_not_admit():
    other = _other_interface()
    if other is None:
        pytest.skip("this host has no adapter besides loopback")
    refusing, serving = limited([other]), limited([])
    frames = sniff_udp([refusing, serving])
    try:
        send(b"dropped", refusing)
        send(b"kept", serving)
        wait_readable(refusing, serving)
        frame = next(frames)
        assert frame.datagram().payload == b"kept"
        assert frames.not_admitted == 1 and frames.truncated == 0
    finally:
        frames.close()
