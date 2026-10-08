"""Putting TCP streams back together from dissected frames (internal).

A passive reader of a capture does not know which copy of an octet the
receiver kept or whether a reset was accepted, so each choice is one stated
rule (the shipped header lists them). Everything a capture controls is
bounded: connections, octets and pieces held, silence, and the work done for
one segment.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Dict, List, Optional, Tuple, Union

from .._dissect import DissectedFrame
from .._layers import IPv4Layer, IPv6FragmentLayer, IPv6Layer, TCPLayer
from ._direction import FAR, MASK, Direction
from ._engine import Engine
from ._types import TCPStreamData

__all__ = ["TCPReassembler"]

_Endpoint = Tuple[str, int]
_Key = Tuple[_Endpoint, _Endpoint]
_JOIN, _NEW, _IGNORE = 0, 1, 2


class _Connection:
    """The two directions between two socket addresses."""

    __slots__ = ("stream", "last", "directions", "aside")

    def __init__(self, stream: int) -> None:
        self.stream = stream
        self.last = 0.0  # the time of the last segment that had one
        self.directions: Dict[_Endpoint, Direction] = {}
        # A SYN set aside until something confirms it: its sender, its
        # receiver and its number. One per connection.
        self.aside: Optional[Tuple[_Endpoint, _Endpoint, int]] = None


def _snapped(layer: Union[IPv4Layer, IPv6Layer], packet: int) -> int:
    """The octets a snap length cut from the end of an IP packet, of which
    ``packet`` octets were captured: what its length field states beyond them.
    A zero field (a jumbogram, a send the network card segments) states no
    more than the header, and octets after the stated length are padding."""
    if isinstance(layer, IPv4Layer):
        stated = layer.length
    else:
        stated = layer.payload_length + 40
    return max(stated - packet, 0)


def _segment_of(
    frame: DissectedFrame,
) -> Optional[Tuple[TCPLayer, _Endpoint, _Endpoint, bytes, bool, int]]:
    """The innermost TCP segment of a frame: header, both socket addresses,
    octets, whether it lies in an IP fragment that was not reassembled, and
    how many octets of it a snap length cut. A segment read from a reassembled
    datagram is cut by nothing."""
    source = destination = None
    fragment = False
    snapped = 0
    before = frame.frame.data  # the octets the layer being read came from
    for layer, payload in zip(frame.layers, frame.payloads):
        if isinstance(layer, (IPv4Layer, IPv6Layer)):
            source, destination = layer.source, layer.destination
            fragment = isinstance(layer, IPv4Layer) and layer.is_fragment
            snapped = _snapped(layer, len(before))
        elif isinstance(layer, IPv6FragmentLayer):
            fragment = layer.is_fragment
        elif isinstance(layer, TCPLayer):
            if source is None or destination is None:
                return None
            return (
                layer,
                (source, layer.source_port),
                (destination, layer.destination_port),
                payload,
                fragment and not frame.reassembled,
                0 if frame.reassembled else snapped,
            )
        before = payload
    return None


class TCPReassembler(Engine):
    """Puts TCP streams back together from dissected frames.

    Feed it every frame of a capture, in capture order. It raises nothing for
    a frame and keeps its state within the bounds below. Not safe to share
    between threads.

    :param max_streams: the most connections tracked; one more forgets the
        least recently active, whose held octets are dropped.
    :param max_buffered: the most octets held out of order over all
        connections, each held piece charged its length plus 64. Past it, the
        direction that has waited longest gives up its holes and delivers.
    :param idle_timeout: seconds of capture time after which a silent
        connection is forgotten when its addresses are next seen; they then
        start a new stream.
    :raises TypeError: an option of the wrong type.
    :raises ValueError: a limit that is not positive.
    """

    def __init__(
        self,
        *,
        max_streams: int = 1024,
        max_buffered: int = 16777216,
        idle_timeout: float = 300.0,
    ) -> None:
        for name, value in (
            ("max_streams", max_streams),
            ("max_buffered", max_buffered),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError("%s must be an int" % name)
            if value < 1:
                raise ValueError("%s must be at least 1" % name)
        if isinstance(idle_timeout, bool) or not isinstance(idle_timeout, (int, float)):
            raise TypeError("idle_timeout must be a number")
        if not idle_timeout > 0:
            raise ValueError("idle_timeout must be positive")
        try:
            idle = float(idle_timeout)
        except OverflowError:
            raise ValueError("idle_timeout is too large for a float") from None
        super().__init__(max_buffered)
        self._max_streams = max_streams
        self._idle = idle
        self._table: "OrderedDict[_Key, _Connection]" = OrderedDict()
        # Connections every direction of which has ended, least recently
        # active first: they give up their place before any other.
        self._done: "OrderedDict[_Key, None]" = OrderedDict()

    def _pending(self) -> int:
        return len(self._table)

    def add(self, frame: DissectedFrame) -> Tuple[TCPStreamData, ...]:
        """One frame; what it made deliverable, in the order it became so.

        A frame can release the other direction's held octets, on an
        acknowledgment, before it delivers its own. A frame with no TCP over
        IP gives ``()``.
        """
        if not isinstance(frame, DissectedFrame):
            raise TypeError("frame must be a DissectedFrame")
        found = _segment_of(frame)
        if found is None:
            return ()
        tcp, source, destination, data, fragment, snapped = found
        self._segments += 1
        if fragment:
            self._ignored += 1
            return ()
        time = frame.time
        if time != time:  # not a number: says nothing, as a time of 0.0 does
            time = 0.0
        if time != 0.0:  # a pcapng simple packet block has no time
            self._now = time
        key: _Key = (
            (source, destination) if source < destination else (destination, source)
        )
        out: List[TCPStreamData] = []
        conn = self._lookup(key, time)
        if conn is None and (tcp.rst or not (data or tcp.syn or tcp.fin)):
            return ()
        if conn is not None and tcp.rst:
            # A reset from a side that has sent nothing is believed whatever
            # its number.
            sender = conn.directions.get(source)
            if sender is not None:
                start = sender.offset_of(tcp.sequence)
                behind = sender.behind(tcp.sequence)
                if behind:
                    self._ignored += 1
                if behind or (
                    start > sender.top + FAR
                    and self._set_aside(sender, start, start, time, out, False)
                ):
                    self._touch(key, conn, time)
                    return ()
            self._replace(key, conn, time, out)
            return tuple(out)
        if conn is not None and conn.aside is not None:
            if self._confirms(conn.aside, source, tcp):
                origin, target, number = conn.aside
                self._ignored -= 1
                self._replace(key, conn, time, out)
                conn = self._create(key)
                conn.directions[origin] = Direction(
                    origin, target, conn.stream, self._shared, number, True
                )
        if conn is not None and tcp.syn:
            verdict = self._syn(conn, source, destination, tcp)
            if verdict == _IGNORE:
                self._ignored += 1
                return tuple(out)
            if verdict == _NEW:
                if any(not d.ended for d in conn.directions.values()):
                    conn.aside = (source, destination, tcp.sequence)
                    self._ignored += 1
                    return tuple(out)
                self._replace(key, conn, time, out)
                conn = None
        if conn is None:
            conn = self._create(key)
        self._touch(key, conn, time)
        if tcp.ack:
            self._acknowledge(
                conn.directions.get(destination), tcp.acknowledgment, time, out
            )
        if data or tcp.syn or tcp.fin:
            direction = conn.directions.get(source)
            if direction is None:
                direction = Direction(
                    source,
                    destination,
                    conn.stream,
                    self._shared,
                    tcp.sequence,
                    tcp.syn,
                )
                conn.directions[source] = direction
            self._segment(direction, tcp, data, snapped, time, out)
        self._enforce(time, out)
        if key in self._table:
            self._note(key, conn)
        return tuple(out)

    def flush(self) -> Tuple[TCPStreamData, ...]:
        """The end of the capture: everything still held, each run after a
        hole with its ``missing``, connections in order of ``stream``. The
        table is empty afterwards. A FIN that was captured still ends its
        direction; flushing marks no other end."""
        out: List[TCPStreamData] = []
        for conn in sorted(self._table.values(), key=lambda item: item.stream):
            for direction in conn.directions.values():
                if not direction.ended:
                    self._give_up(direction, self._now, out)
        self._table.clear()
        self._done.clear()
        self._waiting.clear()
        return tuple(out)

    # -- the table ----------------------------------------------------------

    def _lookup(self, key: _Key, time: float) -> Optional[_Connection]:
        conn = self._table.get(key)
        if conn is None:
            return None
        # A time of zero says nothing; a jump either way counts as silence.
        if time != 0.0 and conn.last != 0.0 and not abs(time - conn.last) <= self._idle:
            self._forget(key, conn)
            return None
        return conn

    def _touch(self, key: _Key, conn: _Connection, time: float) -> None:
        self._table.move_to_end(key)
        if time != 0.0:
            conn.last = time

    def _note(self, key: _Key, conn: _Connection) -> None:
        """Whether the connection has finished: every direction it has seen
        has ended."""
        if conn.directions and all(d.ended for d in conn.directions.values()):
            self._done[key] = None
            self._done.move_to_end(key)
        else:
            self._done.pop(key, None)

    def _create(self, key: _Key) -> _Connection:
        while len(self._table) >= self._max_streams:
            if self._done:
                finished = next(iter(self._done))
                self._forget(finished, self._table[finished], counted=False)
            else:
                oldest = next(iter(self._table))
                self._forget(oldest, self._table[oldest])
        conn = self._table[key] = _Connection(self._streams)
        self._streams += 1
        return conn

    def _forget(self, key: _Key, conn: _Connection, counted: bool = True) -> None:
        for direction in conn.directions.values():
            self._dropped += direction.forget()
            self._waiting.pop(direction, None)
        del self._table[key]
        self._done.pop(key, None)
        if counted:
            self._evicted += 1

    def _replace(
        self, key: _Key, conn: _Connection, time: float, out: List[TCPStreamData]
    ) -> None:
        """The connection is over and leaves the table."""
        del self._table[key]
        self._done.pop(key, None)
        self._close(conn, time, out)

    @staticmethod
    def _confirms(
        aside: Tuple[_Endpoint, _Endpoint, int], source: _Endpoint, tcp: TCPLayer
    ) -> bool:
        """Whether a segment confirms the SYN set aside: its sender's next
        segment, from the octet after the SYN up to ``FAR`` beyond, or an
        acknowledgment of the SYN from the other side."""
        sender, _, number = aside
        after = (number + 1) & MASK
        if source == sender:
            # A SYN is not a continuation: a second one replaces the first.
            return not tcp.syn and ((tcp.sequence - after) & MASK) <= FAR
        return tcp.ack and tcp.acknowledgment == after

    def _close(self, conn: _Connection, time: float, out: List[TCPStreamData]) -> None:
        """The connection is over: every direction delivers and ends."""
        for direction in conn.directions.values():
            if not direction.ended:
                self._emit(direction, direction.release_all(), time, out)
                self._finish(direction, time, out)
            self._track(direction)

    def _syn(
        self,
        conn: _Connection,
        source: _Endpoint,
        destination: _Endpoint,
        tcp: TCPLayer,
    ) -> int:
        """Whether a SYN joins its connection, starts a new one on the same
        addresses, or contradicts it and is ignored."""
        mine = conn.directions.get(source)
        theirs = conn.directions.get(destination)
        if mine is not None:
            if mine.syn is not None:
                own = mine.syn == tcp.sequence
            else:
                own = ((tcp.sequence + 1) & MASK) == mine.base
            return _JOIN if own else _NEW
        if theirs is not None:
            if tcp.ack and theirs.syn is not None:
                # A SYN-ACK acknowledges the SYN and, for Fast Open, the
                # octets the SYN carried (RFC 7413 section 4.2).
                carried = (tcp.acknowledgment - theirs.syn - 1) & MASK
                answers = carried <= theirs.top
                return _JOIN if answers else _IGNORE
            if theirs.top > 0:
                return _NEW
        return _JOIN
