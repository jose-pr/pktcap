"""The rules for one segment, and the bounds on what is held (internal).

The table of connections is in ``_tcp``; this holds what happens to a
direction once a segment is placed in it.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import List, Optional

from .._layers import TCPLayer
from ._direction import MASK, Chunk, Direction, Shared
from ._types import TCPStreamData, TCPStreamStats

__all__ = ["Engine"]

#: The most pieces one direction holds out of order. 1,024 pieces cover a
#: window of 64 KiB cut into 64-octet segments.
MAX_PIECES = 1024
#: What each held piece is charged beyond its octets, so that a flood of
#: one-octet pieces meets ``max_buffered`` too.
PIECE_OVERHEAD = 64


class Engine:
    """Counters, the budget of held octets, and the rules that apply to a
    segment once its direction is known."""

    def __init__(self, max_buffered: int) -> None:
        self._max_buffered = max_buffered
        self._shared = Shared()
        # Directions holding octets, the one that has waited longest first.
        self._waiting: "OrderedDict[Direction, None]" = OrderedDict()
        self._now = 0.0
        self._streams = self._segments = self._delivered = 0
        self._retransmitted = self._out_of_order = self._conflicts = 0
        self._ignored = self._evicted = 0

    @property
    def stats(self) -> TCPStreamStats:
        """The counters as they stand."""
        return TCPStreamStats(
            self._segments,
            self._streams,
            self._delivered,
            self._retransmitted,
            self._out_of_order,
            self._shared.missing,
            self._conflicts,
            self._ignored,
            self._evicted,
            self._pending(),
            self._shared.held,
        )

    def _pending(self) -> int:
        raise NotImplementedError

    def _track(self, direction: Direction) -> None:
        if direction.starts:
            self._waiting.setdefault(direction)
        else:
            self._waiting.pop(direction, None)

    def _emit(
        self,
        direction: Direction,
        chunks: List[Chunk],
        time: float,
        out: List[TCPStreamData],
    ) -> None:
        for offset, data, missing in chunks:
            self._delivered += len(data)
            out.append(
                TCPStreamData(
                    time,
                    direction.source,
                    direction.destination,
                    data,
                    offset,
                    missing,
                    direction.stream,
                )
            )

    def _finish(
        self, direction: Direction, time: float, out: List[TCPStreamData]
    ) -> None:
        """End a direction after what it delivered, in the last item it has
        in ``out`` or in an empty one."""
        direction.ended = True
        for index in range(len(out) - 1, -1, -1):
            item = out[index]
            if (item.stream, item.source) == (direction.stream, direction.source):
                if not item.end:
                    out[index] = item._replace(end=True)
                    return
                break
        missing, direction.lost = direction.lost, 0
        out.append(
            TCPStreamData(
                time,
                direction.source,
                direction.destination,
                b"",
                direction.next,
                missing,
                direction.stream,
                True,
            )
        )

    def _settle(
        self, direction: Direction, time: float, out: List[TCPStreamData]
    ) -> None:
        """End the direction once everything up to its FIN is delivered."""
        if (
            direction.fin is not None
            and not direction.ended
            and direction.next == direction.fin
        ):
            self._finish(direction, time, out)
        self._track(direction)

    def _give_up(
        self, direction: Direction, time: float, out: List[TCPStreamData]
    ) -> None:
        self._emit(direction, direction.release_all(), time, out)
        self._settle(direction, time, out)

    def _acknowledge(
        self,
        direction: Optional[Direction],
        number: int,
        time: float,
        out: List[TCPStreamData],
    ) -> None:
        """An acknowledgment proves receipt of the octets it covers: the holes
        before it are given up. One beyond everything seen from the sender
        changes nothing."""
        if direction is None or not direction.started:
            return
        ahead = (number - direction.sequence()) & MASK
        if ahead == 0 or ahead >= 0x80000000:
            return
        target = direction.next + ahead
        if direction.fin is not None and target == direction.fin + 1:
            target = direction.fin  # the FIN takes a sequence number
        if target <= direction.next:
            return
        if target > direction.top:
            self._ignored += 1
            return
        self._emit(direction, direction.release(target), time, out)
        self._settle(direction, time, out)

    def _segment(
        self,
        direction: Direction,
        tcp: TCPLayer,
        data: bytes,
        time: float,
        out: List[TCPStreamData],
    ) -> None:
        syn, fin = tcp.syn, tcp.fin
        if not direction.started:
            direction.start(tcp.sequence, syn)
        elif syn and direction.syn is None:
            direction.syn = tcp.sequence
        offset = direction.offset_of((tcp.sequence + syn) & MASK)
        position = offset + len(data)  # where a FIN sits
        if offset < 0 and data:
            cut = min(-offset, len(data))
            self._ignored += 1  # octets before the start are not delivered
            data, offset = data[cut:], offset + cut
        if data and direction.fin is not None:
            keep = direction.fin - offset
            if keep < len(data):
                self._ignored += 1
                data = data[: max(keep, 0)]
        if data:
            if offset + len(data) <= direction.next:
                self._retransmitted += len(data)
                data = b""
            elif offset < direction.next:
                self._retransmitted += direction.next - offset
                data, offset = data[direction.next - offset :], direction.next
        if data:
            if offset > direction.next:
                self._out_of_order += 1
            self._place(direction, offset, data, time, out)
        if fin:
            self._fin(direction, position)
        self._settle(direction, time, out)

    def _fin(self, direction: Direction, position: int) -> None:
        """A FIN ends the direction at its position; octets beyond are dropped."""
        if direction.fin is None and position >= direction.next:
            direction.fin = position
            if direction.cut(position):
                self._ignored += 1
            direction.top = position
        elif direction.fin != position:
            self._ignored += 1

    def _place(
        self,
        direction: Direction,
        offset: int,
        data: bytes,
        time: float,
        out: List[TCPStreamData],
    ) -> None:
        if len(data) + PIECE_OVERHEAD > self._max_buffered and offset > direction.next:
            # Too large to wait for on its own: it is delivered at once, and
            # the holes before it are given up.
            self._emit(direction, direction.release(offset), time, out)
            if offset < direction.next:
                self._retransmitted += direction.next - offset
                data, offset = data[direction.next - offset :], direction.next
                if not data:
                    return
        if offset == direction.next and not direction.starts:
            chunk = (offset, data, direction.lost)
            direction.lost = 0
            direction.next = offset + len(data)
            direction.top = max(direction.top, direction.next)
            self._emit(direction, [chunk], time, out)
            return
        copied, conflicts = direction.insert(offset, data)
        self._retransmitted += copied
        self._conflicts += conflicts
        direction.top = max(direction.top, offset + len(data))
        run = direction.ready()
        if run is not None:
            self._emit(direction, [run], time, out)
        while len(direction.starts) > MAX_PIECES:
            self._emit(direction, [direction.take_run()], time, out)
        self._track(direction)

    def _enforce(self, time: float, out: List[TCPStreamData]) -> None:
        """Keep the octets held, with their overhead, within ``max_buffered``:
        the direction that has waited longest gives up its holes."""
        shared = self._shared
        while (
            shared.held + PIECE_OVERHEAD * shared.pieces > self._max_buffered
            and self._waiting
        ):
            self._give_up(next(iter(self._waiting)), time, out)
