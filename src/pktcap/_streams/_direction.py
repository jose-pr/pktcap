"""One direction of a TCP connection: where it stands and what it holds (internal).

Positions are *offsets*: plain integers counted from the first octet the
direction delivers, so they never wrap. A sequence number maps to an offset
modulo 2**32 (RFC 9293 section 3.4): within 2**31 ahead of the next expected
octet it is ahead, anything else is behind.

Octets that arrived ahead of a hole are held as pieces that never overlap, in
a sorted list of start offsets. Adding a piece is a binary search and a walk
over the pieces it covers. A new piece that begins where the piece before it
ends is appended to that piece's buffer, so the pieces are the runs in order
of arrival; a delivered run is handed out as ``bytes``.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from typing import Dict, List, Optional, Tuple, Union

__all__ = ["Direction", "Shared", "MASK", "HALF", "FAR"]

MASK = 0xFFFFFFFF
HALF = 0x80000000
_WRAP = 0x100000000
#: How far beyond the furthest octet believed from a sender a segment may start
#: and still be believed, and how far after a set-aside one a segment may start
#: and confirm it. A sender in order never lands there; a window is at most
#: 2**30 (RFC 7323) and a number corrupted at random lands within it one time
#: in four.
FAR = 16777216

#: A delivered run: where it starts, its octets, the octets given up before it.
Chunk = Tuple[int, bytes, int]


class Shared:
    """Counters every direction of one reassembler adds to."""

    __slots__ = ("held", "pieces", "missing")

    def __init__(self) -> None:
        self.held = 0  # octets held out of order
        self.pieces = 0  # pieces holding them
        self.missing = 0  # octets given up on


def _differing(old: Union[bytes, bytearray], new: bytes) -> int:
    """How many octets of two equal-length copies disagree."""
    if old == new:
        return 0
    # Counted without a loop over the octets in Python: a capture chooses how
    # many copies disagree and how long each is. The octets that agree are the
    # zero octets of the two copies combined bit by bit.
    size = len(old)
    mixed = int.from_bytes(old, "big") ^ int.from_bytes(new, "big")
    return size - mixed.to_bytes(size, "big").count(0)


class Direction:
    """The octets one endpoint sent to the other."""

    __slots__ = (
        "source",
        "destination",
        "stream",
        "shared",
        "base",
        "syn",
        "next",
        "top",
        "lost",
        "starts",
        "pieces",
        "held",
        "fin",
        "ended",
        "far",
    )

    def __init__(
        self,
        source: Tuple[str, int],
        destination: Tuple[str, int],
        stream: int,
        shared: Shared,
        sequence: int,
        syn: bool,
    ) -> None:
        self.source = source
        self.destination = destination
        self.stream = stream
        self.shared = shared
        # Offset 0 is the octet after a SYN, else the first octet seen.
        self.syn: Optional[int] = sequence if syn else None  # its SYN's number
        self.base = (sequence + 1) & MASK if syn else sequence  # offset 0's number
        self.next = 0  # the offset of the next octet to deliver
        self.top = 0  # the furthest offset any accepted segment reached
        self.lost = 0  # octets given up on and not yet reported
        self.starts: List[int] = []
        self.pieces: Dict[int, Union[bytes, bytearray]] = {}
        self.held = 0
        self.fin: Optional[int] = None  # the offset a FIN sits at
        self.ended = False
        # Where the last segment set aside as too far ahead started and ended.
        self.far: Optional[Tuple[int, int]] = None

    def sequence(self) -> int:
        """The sequence number of the next octet to deliver, not reduced:
        callers subtract it modulo 2**32."""
        return self.base + self.next

    def offset_of(self, sequence: int) -> int:
        """The offset a sequence number stands for; negative before the start
        of what was delivered."""
        ahead = (sequence - self.sequence()) & MASK
        return self.next + (ahead if ahead < HALF else ahead - _WRAP)

    def behind(self, sequence: int) -> bool:
        """Whether a sequence number lies behind the next expected octet."""
        return ((sequence - self.sequence()) & MASK) >= HALF

    def skip(self, target: int) -> None:
        """Give up the octets before ``target``."""
        gap = target - self.next
        if gap > 0:
            self.lost += gap
            self.shared.missing += gap
            self.next = target

    def insert(self, offset: int, data: bytes) -> Tuple[int, int]:
        """Hold the part of ``data`` no piece already covers.

        ``offset`` is at or past the next expected octet. Where a piece is
        already held, the first captured copy stays. Returns the octets that
        were copies and, of those, the octets that disagreed.
        """
        starts, pieces = self.starts, self.pieces
        end = offset + len(data)
        copied = conflicts = 0
        cursor = offset
        fresh: List[Tuple[int, bytes]] = []
        index = bisect_right(starts, offset) - 1
        if index >= 0:
            start = starts[index]
            stop = min(start + len(pieces[start]), end)
            if stop > offset:
                copied = stop - offset
                conflicts = _differing(
                    pieces[start][offset - start : stop - start],
                    data[: stop - offset],
                )
                cursor = stop
        index += 1
        while cursor < end:
            if index < len(starts) and starts[index] < end:
                start = starts[index]
                if start > cursor:
                    fresh.append((cursor, data[cursor - offset : start - offset]))
                    cursor = start
                stop = min(start + len(pieces[start]), end)
                copied += stop - cursor
                conflicts += _differing(
                    pieces[start][: stop - start], data[cursor - offset : stop - offset]
                )
                cursor = stop
                index += 1
            else:
                fresh.append((cursor, data[cursor - offset :]))
                cursor = end
        for start, chunk in fresh:
            self.held += len(chunk)
            self.shared.held += len(chunk)
            place = bisect_left(starts, start)
            if place:
                before = starts[place - 1]
                piece = pieces[before]
                if before + len(piece) == start:
                    if not isinstance(piece, bytearray):
                        piece = pieces[before] = bytearray(piece)
                    piece += chunk
                    continue
            starts.insert(place, start)
            pieces[start] = chunk
            self.shared.pieces += 1
        return copied, conflicts

    def take_run(self) -> Chunk:
        """Deliver the first held piece and every piece that follows it
        without a hole, giving up the hole before it."""
        starts, pieces = self.starts, self.pieces
        first = starts[0]
        self.skip(first)
        count, end = 1, first + len(pieces[first])
        while count < len(starts) and starts[count] == end:
            end += len(pieces[end])
            count += 1
        parts = [pieces.pop(start) for start in starts[:count]]
        del starts[:count]
        data = b"".join(parts)
        self.held -= len(data)
        self.shared.held -= len(data)
        self.shared.pieces -= count
        self.next = end
        missing, self.lost = self.lost, 0
        return first, data, missing

    def ready(self) -> Optional[Chunk]:
        """The run that starts at the next expected octet, if one is held."""
        if self.starts and self.starts[0] == self.next:
            return self.take_run()
        return None

    def release(self, target: int) -> List[Chunk]:
        """Give up every hole before ``target`` and deliver what is held up
        to it. A run that starts before ``target`` is delivered whole."""
        chunks: List[Chunk] = []
        while self.starts and self.starts[0] < target:
            chunks.append(self.take_run())
        if self.next < target:
            self.skip(target)
            run = self.ready()
            if run is not None:
                chunks.append(run)
        return chunks

    def release_all(self) -> List[Chunk]:
        """Give up every hole: the end of the connection or of the capture."""
        return self.release(self.top if self.fin is None else self.fin)

    def cut(self, position: int) -> bool:
        """Drop held octets at or beyond ``position``; whether any were."""
        starts, pieces = self.starts, self.pieces
        dropped = False
        while starts and starts[-1] + len(pieces[starts[-1]]) > position:
            start = starts[-1]
            piece = pieces[start]
            dropped = True
            if start >= position:
                starts.pop()
                del pieces[start]
                removed, count = len(piece), 1
            else:
                removed, count = len(piece) - (position - start), 0
                if isinstance(piece, bytearray):
                    del piece[position - start :]
                else:
                    pieces[start] = piece[: position - start]
            self.held -= removed
            self.shared.held -= removed
            self.shared.pieces -= count
        return dropped

    def forget(self) -> int:
        """Drop everything held, as the connection is forgotten; the octets."""
        dropped = self.held
        self.shared.held -= self.held
        self.shared.pieces -= len(self.starts)
        self.held = 0
        self.starts.clear()
        self.pieces.clear()
        return dropped
