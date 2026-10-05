"""Putting IP fragments back together, within fixed bounds (internal).

Fragments are untrusted: a capture, or a live network, chooses how many there
are, where each claims to go and how long they stay unfinished. The table
keeps a bounded number of datagrams in flight, each bounded in octets and in
pieces, and does a bounded amount of work per fragment.
"""

from __future__ import annotations

from bisect import bisect_left
from typing import Dict, Hashable, List, Optional

__all__ = ["Reassembler"]

#: The longest IP datagram: the length field is 16 bits in both families.
MAX_DATAGRAM_OCTETS = 65535
#: The most fragments one datagram may arrive in. 65,535 octets over a link
#: with an MTU of 576, the least an IPv4 host must accept, is 119 fragments;
#: 1,024 allows fragments of 64 octets.
MAX_FRAGMENTS = 1024


class _Conflict(Exception):
    """A fragment contradicts the datagram it claims to belong to."""


class _Pending:
    """One datagram with pieces still missing."""

    __slots__ = ("started", "offsets", "pieces", "received", "total")

    def __init__(self, started: float) -> None:
        self.started = started
        self.offsets: List[int] = []  # kept sorted
        self.pieces: Dict[int, bytes] = {}
        self.received = 0
        self.total: Optional[int] = None

    def place(self, offset: int, data: bytes, last: bool) -> Optional[bytes]:
        """Insert one piece; the whole payload once no hole is left.

        The cost is a binary search and one list insert, whatever the order of
        arrival, and the payload is joined once, at the end.
        """
        offsets, pieces = self.offsets, self.pieces
        end = offset + len(data)
        if not data or end > MAX_DATAGRAM_OCTETS:
            raise _Conflict
        if last:
            if offsets and offsets[-1] + len(pieces[offsets[-1]]) > end:
                raise _Conflict
            if self.total is not None and self.total != end:
                raise _Conflict
            self.total = end
        elif self.total is not None and end > self.total:
            raise _Conflict
        index = bisect_left(offsets, offset)
        if index < len(offsets) and offsets[index] == offset:
            if pieces[offset] != data:
                raise _Conflict
            # The same piece again is a frame captured twice, not an attack.
            return None
        if index and offsets[index - 1] + len(pieces[offsets[index - 1]]) > offset:
            raise _Conflict
        if index < len(offsets) and end > offsets[index]:
            raise _Conflict
        if len(offsets) >= MAX_FRAGMENTS:
            raise _Conflict
        offsets.insert(index, offset)
        pieces[offset] = data
        self.received += len(data)
        # No piece overlaps another and none passes the end, so the octets
        # received equal the total exactly when no hole is left.
        if self.received == self.total:
            return b"".join(pieces[position] for position in offsets)
        return None


class Reassembler:
    """A table of datagrams being reassembled, keyed by what identifies one.

    :param limit: the most datagrams in flight; one more discards the oldest.
    :param timeout: seconds of capture time after which an unfinished
        datagram is discarded. IP identifiers are reused, so a late fragment
        must not complete a datagram it never belonged to.
    """

    def __init__(self, limit: int, timeout: float) -> None:
        self._limit = limit
        self._timeout = timeout
        self._pending: Dict[Hashable, _Pending] = {}
        #: Datagrams discarded: an overlap, a bound, an eviction, old age.
        self.dropped = 0

    def __len__(self) -> int:
        return len(self._pending)

    def add(
        self, key: Hashable, time: float, offset: int, data: bytes, last: bool
    ) -> Optional[bytes]:
        """Account for one fragment; the whole datagram once it is complete."""
        state = self._pending.get(key)
        if state is not None and not abs(time - state.started) <= self._timeout:
            self._discard(key)
            state = None
        if state is None:
            if len(self._pending) >= self._limit:
                self._discard(next(iter(self._pending)))
            state = self._pending[key] = _Pending(time)
        try:
            whole = state.place(offset, data, last)
        except _Conflict:
            self._discard(key)
            return None
        if whole is not None:
            del self._pending[key]
        return whole

    def _discard(self, key: Hashable) -> None:
        del self._pending[key]
        self.dropped += 1
