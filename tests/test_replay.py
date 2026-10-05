"""Replay: the schedule, a callable, and one destination the caller names.

Every send goes to a loopback socket this file binds. The capture's own
addresses are off-host on purpose (192.0.2.0/24 is reserved for documentation):
a replay that used them would trip the network guard.
"""

import gc
import io
import socket
import time
import warnings

import pytest
from netimps import UDPEndpoint, bind

from pktcap import (
    CapturedDatagram,
    CaptureFormatError,
    PcapWriter,
    ReplayResult,
    replay,
    replay_schedule,
    replay_to,
)

AWAY = (("192.0.2.5", 50000), ("192.0.2.1", 69))


def _datagrams(times, payloads=None):
    return [
        CapturedDatagram(
            when, AWAY[0], AWAY[1], (payloads or {}).get(index, b"payload %d" % index)
        )
        for index, when in enumerate(times)
    ]


def _capture(datagrams):
    stream = io.BytesIO()
    with PcapWriter(stream) as writer:
        for datagram in datagrams:
            writer.write_datagram(datagram)
    return stream.getvalue()


def _delays(source, **options):
    return [delay for delay, _datagram in replay_schedule(source, **options)]


def _has_ipv6_loopback():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        return False
    return True


@pytest.fixture(params=["127.0.0.1", "::1"])
def receiver(request):
    """A UDP socket on loopback that the test owns, and its address."""
    if request.param == "::1" and not _has_ipv6_loopback():
        pytest.skip("this host has no IPv6 loopback address to bind")
    family = socket.AF_INET6 if ":" in request.param else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((request.param, 0))
        sock.settimeout(5)
        yield sock


def _received(sock, count):
    return [sock.recvfrom(65535) for _ in range(count)]


# -- the schedule ---------------------------------------------------------

TIMES = [10.0, 10.5, 110.5, 100.0]


def test_the_schedule_is_the_recorded_gaps_each_capped_and_never_negative():
    assert _delays(_datagrams(TIMES)) == [0.0, 0.5, 5.0, 0.0]


def test_speed_divides_the_waits_and_none_removes_them():
    assert _delays(_datagrams(TIMES), speed=2) == [0.0, 0.25, 5.0, 0.0]
    assert _delays(_datagrams(TIMES), speed=0.5) == [0.0, 1.0, 5.0, 0.0]
    assert _delays(_datagrams(TIMES), speed=None) == [0.0] * 4


def test_the_cap_is_the_callers_to_move():
    assert _delays(_datagrams(TIMES), max_delay=200) == [0.0, 0.5, 100.0, 0.0]
    assert _delays(_datagrams(TIMES), max_delay=0) == [0.0] * 4


def test_a_hostile_timestamp_cannot_hang_a_replay():
    """The capture controls its times: 2**40 seconds is 34,000 years."""
    hostile = _datagrams([0.0, float(2**40), float("inf"), float("nan"), 7.0, -1e300])
    assert _delays(hostile) == [0.0, 5.0, 5.0, 0.0, 0.0, 0.0]


def test_the_datagrams_come_back_in_order_and_unchanged():
    datagrams = _datagrams(TIMES)
    assert [d for _delay, d in replay_schedule(datagrams, speed=None)] == datagrams


def test_the_limit_stops_the_schedule_without_taking_one_more():
    taken = []

    def source():
        for datagram in _datagrams([0.0, 1.0, 2.0, 3.0]):
            taken.append(datagram)
            yield datagram

    assert len(_delays(source(), limit=2)) == 2
    assert len(taken) == 2
    assert _delays(_datagrams(TIMES), limit=0) == []


def test_a_capture_is_a_source_by_path_and_by_stream(tmp_path):
    data = _capture(_datagrams([1.0, 1.25, 4.0]))
    path = tmp_path / "cap.pcap"
    path.write_bytes(data)
    for source in (path, str(path), io.BytesIO(data)):
        assert _delays(source) == pytest.approx([0.0, 0.25, 2.75])


def test_the_schedule_reads_no_clock_and_waits_for_nothing():
    started = time.perf_counter()
    assert sum(_delays(_datagrams([0.0, 3.0, 6.0]))) == 6.0
    assert time.perf_counter() - started < 1.0


def test_a_damaged_capture_raises_while_the_schedule_is_read():
    data = _capture(_datagrams([1.0, 2.0]))[:-3]
    schedule = replay_schedule(io.BytesIO(data), speed=None)
    assert next(schedule)[1].payload == b"payload 0"
    with pytest.raises(CaptureFormatError):
        next(schedule)


# -- to a callable --------------------------------------------------------


def test_replay_hands_every_datagram_to_the_callable_and_counts_them():
    seen = []
    datagrams = _datagrams(TIMES)
    assert replay(datagrams, seen.append, speed=None) == 4
    assert seen == datagrams


def test_replay_gives_partial_datagrams_to_the_callable_too():
    partial = _datagrams([0.0])[0]._replace(fragmented=True)
    seen = []
    assert replay([partial], seen.append, speed=None) == 1 and seen == [partial]


def test_replay_waits_the_recorded_time():
    started = time.perf_counter()
    assert replay(_datagrams([0.0, 0.06, 0.12]), lambda d: None) == 3
    assert time.perf_counter() - started >= 0.11


def test_an_exception_from_the_callable_ends_the_replay():
    seen = []

    def deliver(datagram):
        seen.append(datagram)
        raise RuntimeError("stop here")

    with pytest.raises(RuntimeError, match="stop here"):
        replay(_datagrams(TIMES), deliver, speed=None)
    assert len(seen) == 1


# -- to a destination -----------------------------------------------------


def test_every_payload_reaches_the_destination_named_in_order(receiver):
    host, port = receiver.getsockname()[:2]
    result = replay_to(_datagrams([1.0, 1.0, 1.0, 1.0]), host, port, speed=None)
    assert result == ReplayResult(sent=4, partial=0)
    arrivals = _received(receiver, 4)
    assert [data for data, _sender in arrivals] == [b"payload %d" % n for n in range(4)]
    # One socket for the whole replay, and never the capture's own addresses.
    assert len({sender[:2] for _data, sender in arrivals}) == 1


def test_a_capture_file_is_replayed_to_the_destination_named(receiver, tmp_path):
    path = tmp_path / "cap.pcap"
    path.write_bytes(_capture(_datagrams([5.0, 5.0], {0: b"", 1: b"x" * 1400})))
    host, port = receiver.getsockname()[:2]
    assert replay_to(path, host, port, speed=None) == (2, 0)
    assert [data for data, _ in _received(receiver, 2)] == [b"", b"x" * 1400]


def test_a_partial_datagram_is_counted_and_never_sent(receiver):
    whole, fragment, cut = _datagrams([1.0, 1.0, 1.0])
    datagrams = [
        fragment._replace(fragmented=True),
        whole,
        cut._replace(truncated=True),
    ]
    host, port = receiver.getsockname()[:2]
    assert replay_to(datagrams, host, port, speed=None) == ReplayResult(1, 2)
    assert _received(receiver, 1)[0][0] == b"payload 0"
    receiver.settimeout(0.2)
    with pytest.raises((socket.timeout, TimeoutError)):
        receiver.recvfrom(65535)


def _loopback_pair():
    """Sockets on 127.0.0.1 and, where the host has it, on ::1, sharing one
    port number: ``localhost`` is either, and which is the resolver's choice."""
    for _ in range(50):
        v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        v4.bind(("127.0.0.1", 0))
        if not _has_ipv6_loopback():
            return [v4]
        v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            v6.bind(("::1", v4.getsockname()[1]))
        except OSError:  # that number is taken on the other family: try another
            v4.close()
            v6.close()
            continue
        return [v4, v6]
    pytest.skip("no port number free on both loopback addresses in 50 tries")


def test_a_host_name_is_a_destination():
    sockets = _loopback_pair()
    try:
        port = sockets[0].getsockname()[1]
        assert replay_to(_datagrams([0.0]), "localhost", port, speed=None).sent == 1
        got = []
        for sock in sockets:
            sock.settimeout(0.5)
            try:
                got.append(sock.recvfrom(100)[0])
            except (socket.timeout, TimeoutError):
                pass
        assert got == [b"payload 0"]
    finally:
        for sock in sockets:
            sock.close()


def test_an_endpoint_passed_in_is_what_sends_and_it_is_left_open(receiver):
    host, port = receiver.getsockname()[:2]
    wildcard = "::" if ":" in host else ""
    with UDPEndpoint(bind(wildcard, 0), pktinfo=False) as endpoint:
        source_port = endpoint.socket.getsockname()[1]
        result = replay_to(_datagrams([0.0]), host, port, endpoint=endpoint, speed=None)
        assert result.sent == 1
        assert _received(receiver, 1)[0][1][1] == source_port
        assert endpoint.socket.fileno() != -1  # still open


def test_the_socket_the_replay_made_is_closed_when_it_returns(receiver):
    host, port = receiver.getsockname()[:2]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        replay_to(_datagrams([0.0]), host, port, speed=None)
        with pytest.raises(RuntimeError, match="the source failed"):
            replay_to(_raising(), host, port, speed=None)
        gc.collect()
    assert [w for w in caught if w.category is ResourceWarning] == []


def _raising():
    yield _datagrams([0.0])[0]
    raise RuntimeError("the source failed")


def test_the_replay_keeps_the_recorded_pace_by_default(receiver):
    host, port = receiver.getsockname()[:2]
    started = time.perf_counter()
    assert replay_to(_datagrams([0.0, 0.06, 0.12]), host, port).sent == 3
    assert time.perf_counter() - started >= 0.11
    _received(receiver, 3)


def test_a_replay_that_would_leave_the_host_is_seen_by_the_guard():
    """The guard in conftest.py watches what `replay_to` sends through: were
    it blind to it, the tests above would prove nothing about where they sent."""
    with pytest.raises(pytest.fail.Exception, match="reached off-host"):
        replay_to(_datagrams([0.0]), "192.0.2.1", 9, speed=None)


# -- a caller's mistake ---------------------------------------------------


def test_the_destination_is_required():
    with pytest.raises(TypeError):
        replay_to(_datagrams([0.0]))
    with pytest.raises(TypeError):
        replay_to(_datagrams([0.0]), "127.0.0.1")
    for nowhere in (None, "", "  "):
        with pytest.raises(ValueError, match="dst must name the host"):
            replay_to(_datagrams([0.0]), nowhere, 9)


@pytest.mark.parametrize(
    "port, error",
    [
        (0, ValueError),
        (65536, ValueError),
        (-1, ValueError),
        ("69", TypeError),
        (True, TypeError),
    ],
)
def test_a_port_that_is_not_a_port_is_refused(port, error):
    with pytest.raises(error):
        replay_to(_datagrams([0.0]), "127.0.0.1", port)


@pytest.mark.parametrize(
    "options, error",
    [
        ({"speed": 0}, ValueError),
        ({"speed": -1}, ValueError),
        ({"speed": float("nan")}, ValueError),
        ({"speed": float("inf")}, ValueError),
        ({"speed": "fast"}, TypeError),
        ({"speed": True}, TypeError),
        ({"max_delay": -0.1}, ValueError),
        ({"max_delay": float("inf")}, ValueError),
        ({"max_delay": None}, TypeError),
        ({"limit": -1}, ValueError),
        ({"limit": 1.5}, TypeError),
    ],
)
def test_a_bad_option_is_refused_at_the_call_by_all_three(options, error):
    with pytest.raises(error):
        replay_schedule(_datagrams(TIMES), **options)
    with pytest.raises(error):
        replay(_datagrams(TIMES), lambda d: None, **options)
    with pytest.raises(error):
        replay_to(_datagrams(TIMES), "127.0.0.1", 9, **options)


def test_a_source_or_a_callable_of_the_wrong_kind_is_a_type_error():
    with pytest.raises(TypeError, match="iterable of datagrams"):
        replay_schedule(5)
    with pytest.raises(TypeError, match="callable"):
        replay(_datagrams(TIMES), None)
