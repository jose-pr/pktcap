"""The values a TCP stream reassembler hands out (internal)."""

from __future__ import annotations

from typing import NamedTuple, Tuple

__all__ = ["TCPStreamData", "TCPStreamStats"]


class TCPStreamData(NamedTuple):
    """Octets of one direction of a TCP connection, in order.

    :ivar time: the capture time of the frame that made the octets deliverable.
    :ivar source: the sender's ``(host, port)``.
    :ivar destination: the receiver's ``(host, port)``.
    :ivar data: the octets; empty only when ``end`` is true.
    :ivar offset: where ``data[0]`` lies in this direction, counted from 0 and
        never wrapping; octets given up on count.
    :ivar missing: the octets given up on immediately before ``data``; they
        are already counted in ``offset``.
    :ivar stream: the connection's number, shared by both directions, from 0
        in the order connections first appeared.
    :ivar end: this direction is over after ``data``. When octets were given
        up between the last ones handed out and the end, the end is an item
        of its own, with no ``data`` and those octets in ``missing``.
    """

    time: float
    source: Tuple[str, int]
    destination: Tuple[str, int]
    data: bytes
    offset: int
    missing: int = 0
    stream: int = 0
    end: bool = False


class TCPStreamStats(NamedTuple):
    """What a :class:`TCPReassembler` has met in the segments it was given.

    :ivar segments: TCP segments taken, whatever became of them.
    :ivar streams: connections numbered so far.
    :ivar delivered: octets handed out.
    :ivar retransmitted: octets dropped as copies of delivered or held ones.
    :ivar out_of_order: segments that arrived ahead of a hole.
    :ivar missing: octets given up on.
    :ivar conflicts: held octets that a later copy disagreed with.
    :ivar ignored: segments and acknowledgments set aside: octets before the
        start or beyond a FIN, an out-of-sequence RST, a SYN-ACK that
        contradicts the connection, an acknowledgment beyond everything seen,
        a segment in an IP fragment that was not reassembled.
    :ivar evicted: connections forgotten at ``max_streams`` or for age; their
        held octets are dropped.
    :ivar pending: connections in the table.
    :ivar held: octets held out of order at the moment.
    """

    segments: int
    streams: int
    delivered: int
    retransmitted: int
    out_of_order: int
    missing: int
    conflicts: int
    ignored: int
    evicted: int
    pending: int
    held: int
