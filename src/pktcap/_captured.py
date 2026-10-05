"""What a capture is made of: a frame as it was recorded (internal).

Re-exported from :mod:`pktcap`.
"""

from __future__ import annotations

from typing import NamedTuple

__all__ = ["CapturedFrame"]


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
