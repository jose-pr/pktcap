"""pktcap -- capture files for UDP protocol libraries.

Reads pcap and pcapng captures, decodes captured frames to UDP datagrams,
writes datagrams back as pcap or as structured records, and replays a capture.
What a datagram means stays with the protocol library that uses this one.

Every public name is imported from :mod:`pktcap`; the modules beside this one
are private.
"""

from __future__ import annotations

from importlib.metadata import version as _version

from ._captured import CapturedDatagram, CapturedFrame
from ._container import CaptureSource, read_frames
from ._exceptions import CaptureFormatError, PktcapError
from ._frames import LINKTYPES, DecodeStats, FrameDecoder, read_datagrams
from ._writer import PcapWriter

__all__ = [
    "CaptureFormatError",
    "CaptureSource",
    "CapturedDatagram",
    "CapturedFrame",
    "DecodeStats",
    "FrameDecoder",
    "LINKTYPES",
    "PcapWriter",
    "PktcapError",
    "read_datagrams",
    "read_frames",
]

__version__ = _version("pktcap")
