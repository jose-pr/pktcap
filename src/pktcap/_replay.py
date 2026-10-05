"""Replaying a capture: what it holds again, in order and in time (internal).

The schedule is a generator that reads no clock, so the same pacing serves a
blocking caller and an event loop. Two drivers sit on it: one hands each item
to a callable, the other sends each UDP payload to one destination the caller
names. Nothing here ever sends to an address taken from the capture, and
nothing here sends a raw frame.
"""

from __future__ import annotations

import itertools
import math
import os
import time
from typing import (
    Any,
    Callable,
    Iterable,
    Iterator,
    NamedTuple,
    Optional,
    Tuple,
    TypeVar,
    Union,
    cast,
    overload,
)

from netimps import Host, HostLike, UDPEndpoint, bind

from ._captured import CapturedDatagram
from ._container import CaptureSource
from ._dissect import read_datagrams

__all__ = ["ReplayResult", "ReplaySource", "replay", "replay_schedule", "replay_to"]

_T = TypeVar("_T")

#: What a replay takes its items from: a capture (a path or a binary stream),
#: read as UDP datagrams, or any iterable of items that have a ``time`` in
#: seconds: datagrams, captured frames, dissected frames.
ReplaySource = Union[CaptureSource, Iterable[_T]]


class ReplayResult(NamedTuple):
    """What :func:`replay_to` did.

    :ivar sent: datagrams sent.
    :ivar partial: datagrams not sent because they were marked ``fragmented``
        or ``truncated``: their payload is not the whole message.
    """

    sent: int
    partial: int


def _items(source: object) -> Iterator[Any]:
    if isinstance(source, (str, os.PathLike)) or hasattr(source, "read"):
        return read_datagrams(cast(CaptureSource, source))
    try:
        return iter(cast("Iterable[Any]", source))
    except TypeError:
        raise TypeError(
            "source must be a path, a binary stream or an iterable of items "
            "with a time"
        ) from None


def _paced(
    source: object,
    speed: Optional[float],
    max_delay: float,
    limit: Optional[int],
) -> Iterator[Tuple[float, Any]]:
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
    return _schedule(_items(source), speed, float(max_delay), limit)


def _schedule(
    items: Iterator[Any],
    speed: Optional[float],
    max_delay: float,
    limit: Optional[int],
) -> Iterator[Tuple[float, Any]]:
    previous: Optional[float] = None
    # islice stops before it takes one item more than the limit.
    for item in itertools.islice(items, limit):
        try:
            when = float(item.time)
        except (AttributeError, TypeError, ValueError):
            raise TypeError("a replayed item has a time, in seconds") from None
        delay = 0.0
        if speed is not None and previous is not None:
            gap = when - previous
            if gap > 0:  # false for a step backwards, and for a NaN
                delay = min(gap / speed, max_delay)
        previous = when
        yield delay, item


@overload
def replay_schedule(
    source: CaptureSource,
    *,
    speed: Optional[float] = ...,
    max_delay: float = ...,
    limit: Optional[int] = ...,
) -> Iterator[Tuple[float, CapturedDatagram]]: ...


@overload
def replay_schedule(
    source: Iterable[_T],
    *,
    speed: Optional[float] = ...,
    max_delay: float = ...,
    limit: Optional[int] = ...,
) -> Iterator[Tuple[float, _T]]: ...


def replay_schedule(
    source: object,
    *,
    speed: Optional[float] = 1.0,
    max_delay: float = 5.0,
    limit: Optional[int] = None,
) -> Iterator[Tuple[float, Any]]:
    """``(delay, item)`` for each item of a capture, in order.

    ``delay`` is how many seconds to wait before that item: the time since the
    one before it in the capture, divided by ``speed`` and never more than
    ``max_delay``. This reads no clock and waits for nothing, so an event loop
    can drive it with its own sleep.

    :param source: a path or binary stream of a pcap or pcapng capture, which
        is read as UDP datagrams; or an iterable of anything with a ``time``
        in seconds, such as ``read_frames(path)`` for every frame or a
        generator that selects the datagrams to replay.
    :param speed: ``1.0`` keeps the recorded timing, ``2.0`` halves every
        wait; ``None`` makes every delay zero.
    :param max_delay: the longest single wait, in seconds. The capture
        controls its timestamps: a jump of a year must not hang a replay. A
        step backwards in time is a wait of zero.
    :param limit: stop after this many items.
    :raises ValueError: a ``speed`` that is not positive, a negative
        ``max_delay`` or ``limit``.
    :raises CaptureFormatError: while iterating, for a damaged capture.
    """
    return _paced(source, speed, max_delay, limit)


@overload
def replay(
    source: CaptureSource,
    deliver: Callable[[CapturedDatagram], object],
    *,
    speed: Optional[float] = ...,
    max_delay: float = ...,
    limit: Optional[int] = ...,
) -> int: ...


@overload
def replay(
    source: Iterable[_T],
    deliver: Callable[[_T], object],
    *,
    speed: Optional[float] = ...,
    max_delay: float = ...,
    limit: Optional[int] = ...,
) -> int: ...


def replay(
    source: object,
    deliver: Callable[[Any], object],
    *,
    speed: Optional[float] = 1.0,
    max_delay: float = 5.0,
    limit: Optional[int] = None,
) -> int:
    """Hand each item of a capture to ``deliver``, in order and in time.

    Blocks, sleeping between items as :func:`replay_schedule` says. What
    ``deliver`` does with an item is the caller's: a protocol library that
    knows a reply goes to another port builds a faithful replay on this, and
    frames that are not UDP are replayed by passing ``read_frames(path)`` or
    ``read_dissected(path)`` as the source. An exception from ``deliver`` ends
    the replay and propagates.

    :param deliver: called with each item, partial datagrams included; what
        it returns is ignored.
    :returns: how many items were delivered.
    """
    if not callable(deliver):
        raise TypeError("deliver must be callable")
    delivered = 0
    for delay, item in _paced(source, speed, max_delay, limit):
        if delay:
            time.sleep(delay)
        deliver(item)
        delivered += 1
    return delivered


def replay_to(
    source: Union[CaptureSource, Iterable[CapturedDatagram]],
    dst: HostLike,
    port: int,
    *,
    endpoint: Optional[UDPEndpoint] = None,
    speed: Optional[float] = 1.0,
    max_delay: float = 5.0,
    limit: Optional[int] = None,
) -> ReplayResult:
    """Send the payload of each UDP datagram of a capture to ``(dst, port)``.

    Blocks. Every datagram goes to the one destination named here; the
    addresses recorded in the capture are never sent to. A datagram marked
    ``fragmented`` or ``truncated`` is counted and not sent.

    :param source: a capture, or an iterable of :class:`CapturedDatagram`.
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
    :raises TypeError: an item of ``source`` is not a datagram.
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
            if not isinstance(datagram, CapturedDatagram):
                raise TypeError("replay_to sends CapturedDatagram items only")
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
