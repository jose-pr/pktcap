"""The static-typing contract, as a caller of the installed package sees it.

Never executed and never collected by pytest: ``mypy --strict`` checks it. Each
line is a use the shipped header promises type-checks, with ``assert_type``
stating the result a caller gets, so a public annotation that degrades to
``Any`` or changes fails here.
"""

import io
import pathlib
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Tuple,
)

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
    assert_type(dissector.unsupported_linktypes, Mapping[int, int])
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
    output.write(datagram, text="a = 1\n", names={"xid": "1"})
    output.write(dissected)
    assert_type(output.format, str)
    assert_type(output.refused, int)
assert_type(pktcap.dumps_record({"a": [1, 2]}, "json"), str)
assert_type(pktcap.loads_record('{"a": 1}'), Dict[str, Any])
assert_type(pktcap.loads_record("a = 1\n", "toml"), Dict[str, Any])
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
assert_type(
    pktcap.compile_capture_filter("ipv4.ttl=64", pktcap.frame_filter_for(registry)),
    Callable[[pktcap.DissectedFrame], bool],
)
assert_type(pktcap.frame_filter_keys(registry), Tuple[str, ...])
assert_type(pktcap.frame_filter_keys(), Tuple[str, ...])

# -- plugins --------------------------------------------------------------

loaded = pktcap.load_plugins(registry, "a.b", config="none")
assert_type(loaded, Tuple[pktcap.LoadedPlugin, ...])
assert_type(pktcap.load_plugins(registry), Tuple[pktcap.LoadedPlugin, ...])
assert_type(
    pktcap.load_plugins(registry, always=["a.b"]), Tuple[pktcap.LoadedPlugin, ...]
)
assert_type(
    pktcap.load_plugins(registry, ["a.b", "c"]), Tuple[pktcap.LoadedPlugin, ...]
)
for plugin in loaded:
    assert_type(plugin.name, str)
    assert_type(plugin.source, str)
    assert_type(plugin.selectors, Tuple[pktcap.Selector, ...])
    assert_type(plugin.layers, Tuple[str, ...])
assert_type(pktcap.capture_config_path(), Optional[pathlib.Path])
assert_type(pktcap.capture_config_path(pathlib.Path("x.ini")), Optional[pathlib.Path])


def hook(registry: pktcap.DissectorRegistry) -> None:
    """A plugin's hook is a function of this shape."""


try:
    pktcap.load_plugins(registry, "x")
except pktcap.CapturePluginError as problem:
    assert_type(problem.plugin, str)
    assert_type(problem.source, str)
except pktcap.CaptureConfigError as bad:
    assert_type(bad.path, Optional[str])
    assert_type(bad.lineno, Optional[int])


class DemoLayer(NamedTuple):
    opcode: int


registry.register_layer(
    DemoLayer, name="demo", keys={"op": lambda clause: lambda layer: True}, replace=True
)
registry.unregister_layer("demo")
assert_type(registry.layers(), Dict[str, type])
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

# -- a line a person reads ------------------------------------------------

for summarised in pktcap.read_dissected("x.pcap"):
    assert_type(pktcap.frame_summary(summarised), str)
    for summarised_layer in summarised.layers:
        assert_type(str(summarised_layer), str)
assert_type(pktcap.UDPLayer(1, 2, 3, 4).summary(), str)
assert_type(pktcap.TCPLayer(1, 2, 3, 4, 0, 5, 6, 7, b"").summary(), str)
with pktcap.CaptureWriter("out.txt", "text") as text_writer:
    assert_type(text_writer.format, str)

# -- copying --------------------------------------------------------------

with pktcap.CaptureWriter("out.json") as copy_target:
    copied = pktcap.copy_frames(
        pktcap.read_dissected("x.pcap"),
        copy_target,
        select=pktcap.compile_capture_filter("proto=udp", pktcap.frame_filter),
        datagrams=True,
        limit=10,
        names=lambda item: {"port": 69},
        each=lambda item: None,
    )
    hooked = pktcap.copy_frames(
        pktcap.read_dissected("x.pcap"),
        copy_target,
        each=pktcap.command_hook(
            "./hook",
            format="json",
            timeout=5.0,
            fail_fast=True,
            names=lambda item: {"xid": 1},
            datagrams=True,
        ),
    )
assert_type(copied, pktcap.CopyResult)
assert_type(hooked, pktcap.CopyResult)
assert_type(pktcap.command_hook("./hook"), Callable[[pktcap.DissectedFrame], None])
hook_error = pktcap.CaptureHookError("x", status=3, timed_out=False)
assert_type(hook_error.status, Optional[int])
assert_type(hook_error.timed_out, bool)
assert_type(copied.read, int)
assert_type(copied.refused, int)

# -- TCP streams ----------------------------------------------------------

reassembler = pktcap.TCPReassembler(max_streams=8, max_buffered=1024, idle_timeout=5.0)
for dissected in pktcap.read_dissected(source):
    streamed = reassembler.add(dissected)
    assert_type(streamed, Tuple[pktcap.TCPStreamData, ...])
    for chunk in streamed:
        assert_type(chunk.time, float)
        assert_type(chunk.source, Tuple[str, int])
        assert_type(chunk.destination, Tuple[str, int])
        assert_type(chunk.data, bytes)
        assert_type(chunk.offset, int)
        assert_type(chunk.missing, int)
        assert_type(chunk.stream, int)
        assert_type(chunk.end, bool)
assert_type(reassembler.flush(), Tuple[pktcap.TCPStreamData, ...])
assert_type(reassembler.stats, pktcap.TCPStreamStats)
assert_type(reassembler.stats.held, int)
assert_type(reassembler.stats.dropped, int)
assert_type(pktcap.read_tcp_streams(source), Iterator[pktcap.TCPStreamData])
assert_type(
    pktcap.read_tcp_streams(
        "x.pcap", reassembler=reassembler, dissector=dissector, max_frame_size=1500
    ),
    Iterator[pktcap.TCPStreamData],
)

# -- capturing live -------------------------------------------------------

with pktcap.LiveCapture("eth0", timeout=0.5) as capture:
    assert_type(capture.read(), Optional[pktcap.CapturedFrame])
assert_type(pktcap.sniff(stop=lambda: True), Iterator[pktcap.CapturedDatagram])
assert_type(
    pktcap.sniff_frames("lo", stop=lambda: True, dissector=dissector),
    Iterator[pktcap.DissectedFrame],
)
assert_type(pktcap.has_live_capture(), bool)

# -- capturing from a socket ----------------------------------------------

datagram = pktcap.CapturedDatagram(1.0, ("10.0.0.5", 1), ("10.0.0.1", 2), b"x")
assert_type(pktcap.datagram_frame(datagram, interface=3, ident=7), pktcap.CapturedFrame)
udp_endpoints: List[UDPEndpoint] = []
udp_capture = pktcap.UDPCapture(udp_endpoints, timeout=0.5, max_size=1500)
assert_type(udp_capture.read(), Optional[pktcap.CapturedFrame])
assert_type(udp_capture.truncated, int)
udp_capture.close()
with pktcap.UDPCapture(udp_endpoints) as entered:
    assert_type(entered, pktcap.UDPCapture)
for udp_frame in pktcap.UDPCapture(udp_endpoints):
    assert_type(udp_frame, pktcap.CapturedFrame)
assert_type(
    pktcap.sniff_udp(udp_endpoints, stop=lambda: True, dissector=dissector),
    Iterator[pktcap.DissectedFrame],
)
assert_type(
    pktcap.asniff_udp(udp_endpoints, dissector=dissector),
    AsyncIterator[pktcap.DissectedFrame],
)


async def read_from_sockets() -> None:
    assert_type(
        await pktcap.UDPCapture(udp_endpoints).aread(), Optional[pktcap.CapturedFrame]
    )
    await pktcap.UDPCapture(udp_endpoints).aclose()
    async for streamed in pktcap.asniff_udp(udp_endpoints):
        assert_type(streamed, pktcap.DissectedFrame)


error = pktcap.CaptureFormatError("x", offset=3)
assert_type(error.offset, Optional[int])
bad_record = pktcap.RecordFormatError("x", format="json", lineno=3)
assert_type(bad_record.format, str)
assert_type(bad_record.lineno, Optional[int])
missing = pktcap.MissingExtraError("x", format="toml", extra="toml")
assert_type(missing.format, str)
assert_type(missing.extra, str)
try:
    pktcap.dumps_record({}, "toml")
except ImportError as caught:
    assert_type(caught, ImportError)
try:
    pktcap.loads_record("", "ini")
except ValueError as caught:
    assert_type(caught, ValueError)
