"""The static-typing contract, as a caller of the installed package sees it.

Never executed and never collected by pytest: ``mypy --strict`` checks it. Each
line is a use the shipped header promises type-checks, with ``assert_type``
stating the result a caller gets, so a public annotation that degrades to
``Any`` or changes fails here.
"""

import io
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from netimps import UDPEndpoint
from typing_extensions import assert_type

import pktcap

source: pktcap.CaptureSource = io.BytesIO(b"")
assert_type(pktcap.read_frames(source), Iterator[pktcap.CapturedFrame])
assert_type(
    pktcap.read_frames("x.pcap", max_frame_size=1500), Iterator[pktcap.CapturedFrame]
)


# -- dissecting -----------------------------------------------------------


def dissect_tftp(data: bytes) -> pktcap.Dissected:
    """A protocol library's dissector is a plain function of this shape."""
    if len(data) < 2:
        raise ValueError("a TFTP packet is at least 2 octets")
    return pktcap.Dissected({"opcode": data[1]}, data[2:], (("tftp-opcode", data[1]),))


typed: pktcap.Dissector = dissect_tftp
registry = pktcap.DissectorRegistry(builtins=True)
registry.register("udp", 69, dissect_tftp, replace=False)
assert_type(registry.get("udp", 69), Optional[pktcap.Dissector])
assert_type(registry.selectors(), Tuple[pktcap.Selector, ...])
assert_type(registry.copy(), pktcap.DissectorRegistry)
assert_type(pktcap.default_registry(), pktcap.DissectorRegistry)
pktcap.register_dissector("udp", 69, dissect_tftp)
pktcap.check_dissector(dissect_tftp, [b"\x00\x01"], rounds=10, seed=1)

dissector = pktcap.FrameDissector(
    registry, reassemble=False, max_reassemblies=8, reassembly_timeout=5.0
)
assert_type(
    pktcap.read_dissected(source, dissector=dissector), Iterator[pktcap.DissectedFrame]
)
assert_type(
    pktcap.read_datagrams(source, dissector=dissector),
    Iterator[pktcap.CapturedDatagram],
)
for captured in pktcap.read_frames(source):
    assert_type(captured.time, float)
    assert_type(captured.linktype, int)
    assert_type(captured.data, bytes)
    assert_type(captured.interface, Optional[int])
    frame = dissector.dissect(captured)
    assert_type(frame, pktcap.DissectedFrame)
    assert_type(frame.layers, Tuple[object, ...])
    assert_type(frame.payload, bytes)
    assert_type(frame.error, Optional[str])
    # Asking for a layer by its type gives that type back.
    assert_type(frame.layer(pktcap.UDPLayer), Optional[pktcap.UDPLayer])
    assert_type(frame.layer(pktcap.TCPLayer), Optional[pktcap.TCPLayer])
    assert_type(frame.payload_of(pktcap.IPv4Layer), Optional[bytes])
    assert_type(frame.datagram(), Optional[pktcap.CapturedDatagram])
    tcp = frame.layer(pktcap.TCPLayer)
    if tcp is not None:
        assert_type(tcp.syn, bool)
        assert_type(tcp.options, bytes)
    ipv4 = frame.layer(pktcap.IPv4Layer)
    if ipv4 is not None:
        assert_type(ipv4.source, str)
        assert_type(ipv4.is_fragment, bool)
assert_type(dissector.stats, pktcap.DissectStats)
assert_type(dissector.stats.pending, int)
assert_type(dissector.registry, pktcap.DissectorRegistry)
assert_type(pktcap.LINKTYPES[1], str)

datagram = pktcap.CapturedDatagram(0.0, ("10.0.0.5", 68), ("10.0.0.1", 67), b"")
assert_type(datagram.source, Tuple[str, int])
assert_type(datagram.truncated, bool)
dissected = dissector.dissect(pktcap.CapturedFrame(0.0, 1, b""))

# -- writing --------------------------------------------------------------

with pktcap.PcapWriter("x.pcap") as writer:
    assert_type(writer, pktcap.PcapWriter)
    writer.write(0.0, ("10.0.0.5", 68), ("fe80::1%eth0", 67, 0, 2), b"")
    writer.write_datagram(datagram)
    writer.write_frame(dissected.frame)
with pktcap.PcapngWriter(io.BytesIO()) as ng:
    assert_type(ng, pktcap.PcapngWriter)
    ng.write_frame(pktcap.CapturedFrame(0.0, 113, b"", 2))

with pktcap.CaptureWriter("x_{xid}.toml", per_record=True, fields=("xid",)) as output:
    output.write(datagram, {"a": 1}, names={"xid": "1"})
    output.write(dissected)
    assert_type(output.format, str)
    assert_type(output.refused, int)
assert_type(pktcap.dumps_record({"a": [1, 2]}, "json"), str)
assert_type(pktcap.datagram_record(datagram), Dict[str, Any])
assert_type(pktcap.frame_record(dissected), Dict[str, Any])
assert_type(pktcap.OUTPUT_FORMATS, Tuple[str, ...])
assert_type(pktcap.has_output_format("yaml"), bool)

# -- filtering ------------------------------------------------------------


def build(clause: pktcap.FilterClause) -> Callable[[pktcap.CapturedDatagram], bool]:
    assert_type(clause.values, Tuple[str, ...])
    return lambda item: item.source[1] == 68


# The predicate keeps the caller's own item type.
assert_type(
    pktcap.compile_capture_filter("port=68", build),
    Callable[[pktcap.CapturedDatagram], bool],
)
assert_type(
    pktcap.compile_capture_filter("proto=udp", pktcap.frame_filter),
    Callable[[pktcap.DissectedFrame], bool],
)
assert_type(pktcap.parse_capture_filter(None), Tuple[pktcap.FilterClause, ...])
assert_type(pktcap.FRAME_FILTER_KEYS, Tuple[str, ...])

# -- replaying ------------------------------------------------------------

# A capture is replayed as datagrams; an iterable keeps its own item type.
assert_type(
    pktcap.replay_schedule("x.pcap", speed=None, limit=3),
    Iterator[Tuple[float, pktcap.CapturedDatagram]],
)
assert_type(
    pktcap.replay_schedule(pktcap.read_frames("x.pcap")),
    Iterator[Tuple[float, pktcap.CapturedFrame]],
)


def take_frame(item: pktcap.DissectedFrame) -> None:
    """A callable for frames that are not UDP."""


assert_type(pktcap.replay(pktcap.read_dissected("x.pcap"), take_frame), int)
assert_type(pktcap.replay("x.pcap", print), int)
endpoint: Optional[UDPEndpoint] = None
assert_type(
    pktcap.replay_to([datagram], "127.0.0.1", 9, endpoint=endpoint),
    pktcap.ReplayResult,
)

# -- capturing live -------------------------------------------------------

with pktcap.LiveCapture("eth0", timeout=0.5) as capture:
    assert_type(capture.read(), Optional[pktcap.CapturedFrame])
assert_type(pktcap.sniff(stop=lambda: True), Iterator[pktcap.CapturedDatagram])
assert_type(pktcap.has_live_capture(), bool)

error = pktcap.CaptureFormatError("x", offset=3)
assert_type(error.offset, Optional[int])
