"""Replaying a capture: its datagrams again, in order and in time (internal).

The schedule is a generator that reads no clock, so the same pacing serves a
blocking caller and an event loop. Two drivers sit on it: one hands each
datagram to a callable, the other sends each payload to one destination the
caller names. Nothing here ever sends to an address taken from the capture.
"""

from __future__ import annotations

import itertools
import math
import os
import time
from typing import (
    Callable,
    Iterable,
    Iterator,
    NamedTuple,
    Optional,
    Tuple,
    Union,
    cast,
)

from netimps import Host, HostLike, UDPEndpoint, bind

from ._captured import CapturedDatagram
from ._container import CaptureSource
from ._frames import read_datagrams

__all__ = ["ReplayResult", "ReplaySource", "replay", "replay_schedule", "replay_to"]

#: What a replay takes its datagrams from: a capture (a path or a binary
#: stream), or any iterable of datagrams.
ReplaySource = Union[CaptureSource, Iterable[CapturedDatagram]]


class ReplayResult(NamedTuple):
    """What :func:`replay_to` did.

    :ivar sent: datagrams sent.
    :ivar partial: datagrams not sent because they were marked ``fragmented``
        or ``truncated``: their payload is not the whole message.
    """

    sent: int
    partial: int


def _datagrams(source: ReplaySource) -> Iterator[CapturedDatagram]:
    if isinstance(source, (str, os.PathLike)) or hasattr(source, "read"):
        return read_datagrams(cast(CaptureSource, source))
    try:
        return iter(source)
    except TypeError:
        raise TypeError(
            "source must be a path, a binary stream or an iterable of datagrams"
        ) from None


def _paced(
    source: ReplaySource,
    speed: Optional[float],
    max_delay: float,
    limit: Optional[int],
) -> Iterator[Tuple[float, CapturedDatagram]]:
    """Check the options of a replay, then build its schedule."""
    if speed is not None:
        if isinstance(speed, bool) or not isinstance(speed, (int, float)):
            raise TypeError("speed must be a number, or None for no waiting")
        if not (math.isfinite(speed) and speed > 0):
            raise ValueError("speed must be positive, or None for no waiting")
    if isinstance(max_delay, bool) or not isinstance(max_delay, (int, float)):
        raise TypeError("max_delay must be a number of seconds")
    if not (math.isfinite(max_delay) and max_delay >= 0):
        raise ValueError("max_delay must be zero or more seconds")
    if limit is not None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an int, or None for no limit")
        if limit < 0:
            raise ValueError("limit must be zero or more")
    return _schedule(_datagrams(source), speed, float(max_delay), limit)


def _schedule(
    datagrams: Iterator[CapturedDatagram],
    speed: Optional[float],
    max_delay: float,
    limit: Optional[int],
) -> Iterator[Tuple[float, CapturedDatagram]]:
    previous: Optional[float] = None
    # islice stops before it takes one datagram more than the limit.
    for datagram in itertools.islice(datagrams, limit):
        delay = 0.0
        if speed is not None and previous is not None:
            gap = datagram.time - previous
            if gap > 0:  # false for a step backwards, and for a NaN
                delay = min(gap / speed, max_delay)
        previous = datagram.time
        yield delay, datagram


def replay_schedule(
    source: ReplaySource,
    *,
    speed: Optional[float] = 1.0,
    max_delay: float = 5.0,
    limit: Optional[int] = None,
) -> Iterator[Tuple[float, CapturedDatagram]]:
    """``(delay, datagram)`` for each datagram of a capture, in order.

    ``delay`` is how many seconds to wait before that datagram: the time since
    the one before it in the capture, divided by ``speed`` and never more than
    ``max_delay``. This reads no clock and waits for nothing, so an event loop
    can drive it with its own sleep.

    :param source: a path or binary stream of a pcap or pcapng capture, or an
        iterable of :class:`CapturedDatagram` (a generator that selects the
        datagrams to replay, for one).
    :param speed: ``1.0`` keeps the recorded timing, ``2.0`` halves every
        wait; ``None`` makes every delay zero.
    :param max_delay: the longest single wait, in seconds. The capture
        controls its timestamps: a jump of a year must not hang a replay. A
        step backwards in time is a wait of zero.
    :param limit: stop after this many datagrams.
    :raises ValueError: a ``speed`` that is not positive, a negative
        ``max_delay`` or ``limit``.
    :raises CaptureFormatError: while iterating, for a damaged capture.
    """
    return _paced(source, speed, max_delay, limit)


def replay(
    source: ReplaySource,
    deliver: Callable[[CapturedDatagram], object],
    *,
    speed: Optional[float] = 1.0,
    max_delay: float = 5.0,
    limit: Optional[int] = None,
) -> int:
    """Hand each datagram of a capture to ``deliver``, in order and in time.

    Blocks, sleeping between datagrams as :func:`replay_schedule` says. What
    ``deliver`` does with a datagram is the caller's: a protocol library that
    knows a reply goes to another port builds a faithful replay on this.
    An exception from ``deliver`` ends the replay and propagates.

    :param deliver: called with each :class:`CapturedDatagram`, partial ones
        included; what it returns is ignored.
    :returns: how many datagrams were delivered.
    """
    if not callable(deliver):
        raise TypeError("deliver must be callable")
    delivered = 0
    for delay, datagram in _paced(source, speed, max_delay, limit):
        if delay:
            time.sleep(delay)
        deliver(datagram)
        delivered += 1
    return delivered


def replay_to(
    source: ReplaySource,
    dst: HostLike,
    port: int,
    *,
    endpoint: Optional[UDPEndpoint] = None,
    speed: Optional[float] = 1.0,
    max_delay: float = 5.0,
    limit: Optional[int] = None,
) -> ReplayResult:
    """Send the payload of each datagram of a capture to ``(dst, port)``.

    Blocks. Every datagram goes to the one destination named here; the
    addresses recorded in the capture are never sent to. A datagram marked
    ``fragmented`` or ``truncated`` is counted and not sent.

    :param dst: where to send: an address or a host name, looked up once.
    :param port: the UDP port there, 1 to 65535.
    :param endpoint: a :class:`netimps.UDPEndpoint` to send through, left
        open. By default a socket is bound for ``dst``'s address family with
        ``netimps.bind``'s defaults (any free port, no broadcast) and closed
        afterwards: pass an endpoint to choose the source port or interface,
        or to send to a broadcast address.
    :param speed: as for :func:`replay_schedule`; the recorded timing by
        default, so a replay sends no faster than the capture did.
    :raises OSError: ``dst`` does not resolve, or a send fails; a payload
        longer than the destination's family allows is one of these.
    :raises ValueError: a ``port`` outside 1-65535, or a bad option.
    """
    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError("port must be an int")
    if not 1 <= port <= 65535:
        raise ValueError("port %d is outside 1-65535" % port)
    if dst is None or (isinstance(dst, str) and not dst.strip()):
        raise ValueError("dst must name the host to send to")
    schedule = _paced(source, speed, max_delay, limit)
    address = Host(dst).ip(check=True)
    if address is None:  # check=True raises for a name with no address
        raise OSError("%r has no address" % (dst,))
    own = None
    if endpoint is None:
        own = endpoint = UDPEndpoint(
            bind("::" if address.version == 6 else "", 0), pktinfo=False
        )
    sent = partial = 0
    try:
        for delay, datagram in schedule:
            if delay:
                time.sleep(delay)
            if datagram.fragmented or datagram.truncated:
                partial += 1
                continue
            endpoint.send(datagram.payload, str(address), port)
            sent += 1
    finally:
        if own is not None:
            own.close()
    return ReplayResult(sent, partial)
