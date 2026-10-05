"""What a capture is made of: a frame as recorded, a datagram as decoded
(internal).

Re-exported from :mod:`pktcap`.
"""

from __future__ import annotations

from typing import NamedTuple, Tuple

__all__ = ["CapturedFrame", "CapturedDatagram"]


class CapturedFrame(NamedTuple):
    """One packet as a capture recorded it, before any decoding.

    :ivar time: seconds since the epoch, as the capture states them. The file
        controls this value: it may be zero (a pcapng simple packet block has
        no timestamp) or far outside any calendar.
    :ivar linktype: the ``LINKTYPE_`` number saying what ``data`` starts with.
    :ivar data: the captured octets, which a snap length may have cut short.
    """

    time: float
    linktype: int
    data: bytes


class CapturedDatagram(NamedTuple):
    """One UDP datagram from a capture.

    :ivar time: seconds since the epoch; for a reassembled datagram, the time
        of the fragment that completed it.
    :ivar source: ``(host, port)`` of the sender, the host as address text.
    :ivar destination: ``(host, port)`` it was sent to.
    :ivar payload: the octets after the UDP header.
    :ivar fragmented: ``payload`` is only what the first IP fragment carried.
        Set only by a decoder that was told not to reassemble.
    :ivar truncated: ``payload`` is shorter than the datagram's own length
        field says, because the capture's snap length cut the frame.
    """

    time: float
    source: Tuple[str, int]
    destination: Tuple[str, int]
    payload: bytes
    fragmented: bool = False
    truncated: bool = False
