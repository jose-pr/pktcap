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
from ._exceptions import (
    CaptureFilterError,
    CaptureFormatError,
    PktcapError,
    UnsupportedFormatError,
)
from ._filter import FilterClause, compile_capture_filter, parse_capture_filter
from ._formats import (
    OUTPUT_FORMATS,
    RECORD_FORMATS,
    dumps_record,
    has_output_format,
)
from ._frames import LINKTYPES, DecodeStats, FrameDecoder, read_datagrams
from ._output import CaptureWriter, datagram_record
from ._replay import ReplayResult, ReplaySource, replay, replay_schedule, replay_to
from ._writer import PcapWriter

__all__ = [
    "CaptureFilterError",
    "CaptureFormatError",
    "CaptureSource",
    "CaptureWriter",
    "CapturedDatagram",
    "CapturedFrame",
    "DecodeStats",
    "FilterClause",
    "FrameDecoder",
    "LINKTYPES",
    "OUTPUT_FORMATS",
    "PcapWriter",
    "PktcapError",
    "RECORD_FORMATS",
    "ReplayResult",
    "ReplaySource",
    "UnsupportedFormatError",
    "compile_capture_filter",
    "datagram_record",
    "dumps_record",
    "has_output_format",
    "parse_capture_filter",
    "read_datagrams",
    "read_frames",
    "replay",
    "replay_schedule",
    "replay_to",
]

__version__ = _version("pktcap")
