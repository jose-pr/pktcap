"""The static-typing contract, as a caller of the installed package sees it.

Never executed and never collected by pytest: ``mypy --strict`` checks it. Each
line is a use the shipped header promises type-checks, with ``assert_type``
stating the result a caller gets, so a public annotation that degrades to
``Any`` or changes fails here.
"""

import io
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from netimps import UDPEndpoint
from typing_extensions import assert_type

import pktcap

source: pktcap.CaptureSource = io.BytesIO(b"")
assert_type(pktcap.read_frames(source), Iterator[pktcap.CapturedFrame])
assert_type(
    pktcap.read_frames("x.pcap", max_frame_size=1500), Iterator[pktcap.CapturedFrame]
)

decoder = pktcap.FrameDecoder(
    reassemble=False, max_reassemblies=8, reassembly_timeout=5.0
)
assert_type(
    pktcap.read_datagrams(source, decoder=decoder), Iterator[pktcap.CapturedDatagram]
)
for frame in pktcap.read_frames(source):
    assert_type(frame.time, float)
    assert_type(frame.linktype, int)
    assert_type(frame.data, bytes)
    assert_type(decoder.decode(frame), List[pktcap.CapturedDatagram])
assert_type(decoder.stats, pktcap.DecodeStats)
assert_type(decoder.stats.pending, int)
assert_type(pktcap.LINKTYPES[1], str)

datagram = pktcap.CapturedDatagram(0.0, ("10.0.0.5", 68), ("10.0.0.1", 67), b"")
assert_type(datagram.source, Tuple[str, int])
assert_type(datagram.truncated, bool)

with pktcap.PcapWriter("x.pcap") as writer:
    assert_type(writer, pktcap.PcapWriter)
    writer.write(0.0, ("10.0.0.5", 68), ("fe80::1%eth0", 67, 0, 2), b"")
    writer.write_datagram(datagram)

with pktcap.CaptureWriter("x_{xid}.toml", per_record=True, fields=("xid",)) as output:
    output.write(datagram, {"a": 1}, names={"xid": "1"})
    assert_type(output.format, str)
    assert_type(output.refused, int)
assert_type(pktcap.dumps_record({"a": [1, 2]}, "json"), str)
assert_type(pktcap.datagram_record(datagram), Dict[str, Any])
assert_type(pktcap.OUTPUT_FORMATS, Tuple[str, ...])
assert_type(pktcap.has_output_format("yaml"), bool)


def build(clause: pktcap.FilterClause) -> Callable[[pktcap.CapturedDatagram], bool]:
    assert_type(clause.values, Tuple[str, ...])
    return lambda item: item.source[1] == 68


# The predicate keeps the caller's own item type.
assert_type(
    pktcap.compile_capture_filter("port=68", build),
    Callable[[pktcap.CapturedDatagram], bool],
)
assert_type(pktcap.parse_capture_filter(None), Tuple[pktcap.FilterClause, ...])

replayed: pktcap.ReplaySource = [datagram]
assert_type(
    pktcap.replay_schedule(replayed, speed=None, limit=3),
    Iterator[Tuple[float, pktcap.CapturedDatagram]],
)
assert_type(pktcap.replay(replayed, print), int)
endpoint: Optional[UDPEndpoint] = None
assert_type(
    pktcap.replay_to(replayed, "127.0.0.1", 9, endpoint=endpoint), pktcap.ReplayResult
)

with pktcap.LiveCapture("eth0", timeout=0.5) as capture:
    assert_type(capture.read(), Optional[pktcap.CapturedFrame])
assert_type(pktcap.sniff(stop=lambda: True), Iterator[pktcap.CapturedDatagram])
assert_type(pktcap.has_live_capture(), bool)

error = pktcap.CaptureFormatError("x", offset=3)
assert_type(error.offset, Optional[int])
