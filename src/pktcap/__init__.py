"""pktcap -- capture files, read, dissected, written and replayed.

Reads any pcap or pcapng capture, dissects each frame layer by layer with
dissectors anyone can register (Ethernet, VLAN, IPv4, IPv6, UDP and TCP are
built in), writes frames and datagrams back as pcap, pcapng or structured
records, and replays a capture. What is not dissected is handed back as
octets; what a protocol means stays with the library that registers its
dissector.

Every public name is imported from :mod:`pktcap`; the modules beside this one
are private.
"""

from __future__ import annotations

from importlib.metadata import version as _version

from ._captured import CapturedDatagram, CapturedFrame
from ._container import CaptureSource, read_frames
from ._copy import CopyResult, copy_frames
from ._dissect import (
    LINKTYPES,
    DissectedFrame,
    DissectStats,
    FrameDissector,
    read_datagrams,
    read_dissected,
)
from ._dissectors import (
    DissectorRegistry,
    check_dissector,
    default_registry,
    register_dissector,
)
from ._dissectors._contract import Dissected, Dissector, Fragment, Selector
from ._exceptions import (
    CaptureConfigError,
    CaptureFilterError,
    CaptureFormatError,
    CapturePluginError,
    DissectError,
    LiveCaptureError,
    MissingExtraError,
    PktcapError,
    RecordFormatError,
    UnsupportedFormatError,
)
from ._filter import FilterClause, compile_capture_filter, parse_capture_filter
from ._formats import (
    OUTPUT_FORMATS,
    RECORD_FORMATS,
    dumps_record,
    has_output_format,
    loads_record,
)
from ._frame_filter import (
    FRAME_FILTER_KEYS,
    frame_filter,
    frame_filter_for,
    frame_filter_keys,
)
from ._layers import (
    EthernetLayer,
    IPv4Layer,
    IPv6ExtensionLayer,
    IPv6FragmentLayer,
    IPv6Layer,
    LinuxCookedLayer,
    LoopbackLayer,
    TCPLayer,
    UDPLayer,
    VLANLayer,
)
from ._live import LiveCapture, has_live_capture, sniff, sniff_frames
from ._output import CaptureWriter
from ._plugins._config import capture_config_path
from ._plugins._load import LoadedPlugin, load_plugins
from ._records import datagram_record, frame_record
from ._replay import ReplayResult, ReplaySource, replay, replay_schedule, replay_to
from ._streams import (
    TCPReassembler,
    TCPStreamData,
    TCPStreamStats,
    read_tcp_streams,
)
from ._sources import UDPCapture, asniff_udp, sniff_udp
from ._writer import PcapngWriter, PcapWriter, datagram_frame

__all__ = [
    "CaptureConfigError",
    "CaptureFilterError",
    "CaptureFormatError",
    "CapturePluginError",
    "CaptureSource",
    "CaptureWriter",
    "CopyResult",
    "CapturedDatagram",
    "CapturedFrame",
    "DissectError",
    "DissectStats",
    "Dissected",
    "DissectedFrame",
    "Dissector",
    "DissectorRegistry",
    "EthernetLayer",
    "FRAME_FILTER_KEYS",
    "FilterClause",
    "Fragment",
    "FrameDissector",
    "IPv4Layer",
    "IPv6ExtensionLayer",
    "IPv6FragmentLayer",
    "IPv6Layer",
    "LINKTYPES",
    "LinuxCookedLayer",
    "LoadedPlugin",
    "LiveCapture",
    "LiveCaptureError",
    "LoopbackLayer",
    "MissingExtraError",
    "OUTPUT_FORMATS",
    "PcapWriter",
    "PcapngWriter",
    "PktcapError",
    "RECORD_FORMATS",
    "RecordFormatError",
    "ReplayResult",
    "ReplaySource",
    "Selector",
    "TCPLayer",
    "TCPReassembler",
    "TCPStreamData",
    "TCPStreamStats",
    "UDPCapture",
    "UDPLayer",
    "UnsupportedFormatError",
    "VLANLayer",
    "asniff_udp",
    "check_dissector",
    "compile_capture_filter",
    "copy_frames",
    "datagram_frame",
    "datagram_record",
    "default_registry",
    "dumps_record",
    "frame_filter",
    "frame_filter_for",
    "frame_filter_keys",
    "frame_record",
    "load_plugins",
    "loads_record",
    "capture_config_path",
    "has_live_capture",
    "has_output_format",
    "parse_capture_filter",
    "read_datagrams",
    "read_dissected",
    "read_frames",
    "read_tcp_streams",
    "register_dissector",
    "replay",
    "replay_schedule",
    "replay_to",
    "sniff",
    "sniff_frames",
    "sniff_udp",
]

__version__ = _version("pktcap")
