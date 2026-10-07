# pktcap

[![Version](https://img.shields.io/pypi/v/pktcap.svg)](https://pypi.org/project/pktcap/)
[![Python versions](https://img.shields.io/pypi/pyversions/pktcap.svg)](https://pypi.org/project/pktcap/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/pktcap/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/pktcap/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/pktcap/test.yml)](https://github.com/jose-pr/pktcap/actions/workflows/test.yml)

**Read any packet capture, dissect it layer by layer, write it back, replay
it.** Every frame of a pcap or pcapng file comes back, whatever its link type;
the built-in dissectors read the link layer, IP, UDP and TCP, and any other
protocol is a dissector you register. Built on the standard library and
[netimps](https://github.com/jose-pr/netimps).
Documentation: <https://jose-pr.github.io/pktcap/>.

## Features

- **Reads any valid pcap or pcapng capture** — either byte order, microseconds
  or nanoseconds, several interfaces, from a file or from a pipe that cannot
  seek (`tcpdump -w -`, `dumpcap -w -`). Every frame is returned with its
  octets, link type, time and interface; a link type or protocol nothing
  dissects is never an error and never skipped.
- **Dissects layer by layer** — Ethernet with 802.1Q and QinQ tags, Linux
  cooked capture v1 and v2, BSD loopback and raw IP; IPv4, and IPv6 with its
  extension headers; UDP and TCP headers. A dissected frame is a value you
  walk: its layers in order, each a small immutable record, and what is left.
- **Pluggable dissectors** — a dissector is a function from one layer's octets
  to its fields, its payload and what follows. Register yours for a port, an
  IP protocol, an ethertype or a link type, in the process-wide registry or
  in one you build and pass.
- **A UDP datagram view** on top, for a protocol library that only wants
  addresses, ports and payload, with IP fragments reassembled.
- **Treats a capture as untrusted input** — every length, count and offset a
  file or a frame states has a ceiling checked before anything is allocated:
  a 48-octet file claiming a 1 GiB record costs under 1 MiB and one
  `CaptureFormatError`. A dissector that fails, built in or registered, costs
  that frame one layer and is counted; it never stops the reader.
- **Writes pcap and pcapng** that tcpdump and Wireshark read — any frame back
  with its link type, octet for octet, or a datagram seen at a socket under
  synthesised headers with valid checksums.
- **Writes records in a format chosen by name** — a frame or a datagram, or
  the plain data a protocol library makes of it, as JSON lines, YAML
  documents, TOML or INI files, into one growing file or one file per record.
- **Filters with `key=value and key!=value`** — addresses, ports, protocol,
  VLAN and link type built in, and a protocol library's own keys beside them.
- **Replays a capture** — on its recorded timing, to a callable, or its UDP
  payloads to one destination the caller names; never to the addresses in
  the file, and never as raw frames.
- **Captures live on Linux** without a capture tool, given `CAP_NET_RAW`.

## Installation

```bash
pip install pktcap
```

Requires Python 3.9 or newer. `netimps` is the one dependency.

| Extra | Adds | Needed for |
| --- | --- | --- |
| `yaml` | `PyYAML` | the `yaml` output format |
| `toml` | `tomli-w` | the `toml` output format |

Importing `pktcap` needs neither; a format whose extra is missing raises
`ImportError` naming the extra when it is used.

## Quick start

Write a capture, then read every frame of it, layer by layer:

```python
import pktcap

with pktcap.PcapWriter("trace.pcap") as writer:
    writer.write(1700000000.00, ("192.0.2.5", 50000), ("192.0.2.1", 69), b"\x00\x01boot.efi\x00octet\x00")
    writer.write(1700000000.05, ("192.0.2.1", 40000), ("192.0.2.5", 50000), b"\x00\x03\x00\x01data")
    writer.write(1700000000.10, ("192.0.2.5", 50000), ("192.0.2.1", 40000), b"\x00\x04\x00\x01")

for frame in pktcap.read_dissected("trace.pcap"):
    ip, udp = frame.layer(pktcap.IPv4Layer), frame.layer(pktcap.UDPLayer)
    print(ip.source, udp.source_port, "->", ip.destination, udp.destination_port, frame.payload)
```

Register a dissector for a protocol of your own:

```python
import struct
from typing import NamedTuple


class TFTPLayer(NamedTuple):
    opcode: int
    filename: str


def dissect_tftp(data: bytes) -> pktcap.Dissected:
    if len(data) < 4:
        raise pktcap.DissectError("a TFTP packet is at least 4 octets")
    (opcode,) = struct.unpack_from("!H", data)
    name, _, rest = data[2:].partition(b"\0")
    return pktcap.Dissected(TFTPLayer(opcode, name.decode("ascii", "replace")), rest)


registry = pktcap.DissectorRegistry()  # the built-in dissectors, and now yours
registry.register("udp", 69, dissect_tftp)
dissector = pktcap.FrameDissector(registry)
frames = list(pktcap.read_dissected("trace.pcap", dissector=dissector))
print(frames[0].layers[-1])  # TFTPLayer(opcode=1, filename='boot.efi')
print(dissector.stats)  # frames, malformed, failed, unsupported, fragments, ...
```

Take the UDP datagram view when addresses, ports and payload are all you need:

```python
for datagram in pktcap.read_datagrams("trace.pcap"):
    print(datagram.time, datagram.source, datagram.destination, len(datagram.payload))
```

Filter frames, and write them as records or as a capture:

```python
wanted = pktcap.compile_capture_filter("proto=tftp and src=192.0.2.0/24", pktcap.frame_filter)
with pktcap.CaptureWriter("requests.jsonl") as output:  # the ending names the format
    for frame in frames:
        if wanted(frame):
            output.write(frame)

with pktcap.PcapngWriter("copy.pcapng") as writer:  # any frame, as it was captured
    for captured in pktcap.read_frames("trace.pcap"):
        writer.write_frame(captured)

print(pktcap.dumps_record(pktcap.datagram_record(frames[0].datagram()), "ini"))
```

Replay it, at the recorded pace: UDP payloads to a destination you name, or
every frame to a callable:

```python
from netimps import bind

listener = bind("127.0.0.1", 0)  # a UDP socket on a free loopback port
result = pktcap.replay_to("trace.pcap", "127.0.0.1", listener.getsockname()[1])
print(result)  # ReplayResult(sent=3, partial=0)
print(listener.recvfrom(1500)[0])
listener.close()

seen = []
pktcap.replay(pktcap.read_frames("copy.pcapng"), seen.append, speed=None)
print(len(seen), "frames handed to a callable")
```

## API overview

Everything is imported from `pktcap`; the modules below it are private.

| Module | Purpose |
| --- | --- |
| `pktcap` | every public name, below |

| Names | Purpose |
| --- | --- |
| `read_frames`, `CapturedFrame`, `CaptureSource` | read every frame of a pcap or pcapng container |
| `read_dissected`, `FrameDissector`, `DissectedFrame`, `DissectStats`, `LINKTYPES` | dissect frames layer by layer, IP fragments reassembled |
| `EthernetLayer`, `VLANLayer`, `LinuxCookedLayer`, `LoopbackLayer`, `IPv4Layer`, `IPv6Layer`, `IPv6ExtensionLayer`, `IPv6FragmentLayer`, `UDPLayer`, `TCPLayer` | the records the built-in dissectors make |
| `Dissector`, `Dissected`, `Fragment`, `Selector`, `DissectorRegistry`, `default_registry`, `register_dissector`, `check_dissector` | write, register and check a dissector |
| `read_datagrams`, `CapturedDatagram` | the UDP datagram view |
| `PcapWriter`, `PcapngWriter` | write frames and datagrams as a capture |
| `CaptureWriter`, `dumps_record`, `datagram_record`, `frame_record`, `OUTPUT_FORMATS`, `RECORD_FORMATS`, `has_output_format` | write frames, datagrams or records in a named format |
| `parse_capture_filter`, `compile_capture_filter`, `FilterClause`, `frame_filter`, `FRAME_FILTER_KEYS` | the filter expression, and the keys of the built-in layers |
| `replay_schedule`, `replay`, `replay_to`, `ReplayResult`, `ReplaySource` | replay a capture |
| `LiveCapture`, `sniff`, `has_live_capture` | live capture on Linux |
| `PktcapError`, `CaptureFormatError`, `CaptureFilterError`, `UnsupportedFormatError`, `MissingExtraError`, `DissectError`, `LiveCaptureError` | the exceptions |

The reference with every signature, bound and gotcha is the API header that
ships inside the package, `pktcap/AGENTS.md`, also at
<https://github.com/jose-pr/pktcap/blob/main/src/pktcap/AGENTS.md>. The
dissector contract and each built-in dissector are in the header beside them,
<https://github.com/jose-pr/pktcap/blob/main/src/pktcap/_dissectors/AGENTS.md>.

## Differences from tshark

The reference for what a capture holds is **tshark 4.6.8** (Wireshark's
command-line reader). `tests/conformance/` records what it says about 41
captures, written by tcpdump 4.99.6, by Wireshark's editcap, by this library's
writers and its live capture, and by hand, and the suite replays those answers
with no tool installed. Fidelity is to results: how many frames a capture
holds; for each frame, which layers it has and the fields of each (addresses,
VLAN tags, protocol numbers, ports, TCP sequence numbers, flags, options and
segment payload); which UDP datagrams it carries; which captures are refused
and after how many frames; and that tshark reads what `PcapWriter` and
`PcapngWriter` write, as the frames they were given and with every checksum
good. Message texts and exit statuses are not reproduced.

pktcap differs on purpose in these cases, each a bound on untrusted input:

| Case | Difference |
| --- | --- |
| `read-built-ipv4-fragments-overlap` | A fragment that overlaps another: tshark reassembles the datagram and flags the overlap; pktcap discards the datagram and counts it in `dropped`. |
| `read-built-fragments-a-minute-apart` | Fragments more than `reassembly_timeout` (30 s) apart in capture time: tshark reassembles them however far apart; pktcap discards the unfinished datagram, since IP identifiers are reused. |
| `read-built-fragments-without-end` | One datagram in more than 1,024 fragments: tshark reassembles it; pktcap gives it up at the 1,025th. |
| `read-built-reassemblies-in-flight` | More than `max_reassemblies` (256) datagrams being reassembled at once: tshark holds them all and completes the first when its last fragment arrives; pktcap discarded the oldest when the 257th started, and the rest stay counted in `pending`. |
| `read-built-pcapng-interfaces-without-end` | More than 4,096 interfaces described in one pcapng section: tshark reads the capture; pktcap raises `CaptureFormatError`. |

Two more ceilings are lower than tshark's and have no case, because a capture
that reaches them is large: a pcapng packet block over 327,680 octets (tshark:
134,348,832) and a pcapng section header or interface description over 1 MiB
are refused.

| tshark reads | pktcap |
| --- | --- |
| pcap and pcapng, either byte order, microseconds and nanoseconds | yes |
| a frame of any link type | yes: read and returned; dissected when the link type has a dissector |
| Ethernet with 802.1Q and QinQ tags, Linux cooked v1 and v2, BSD loopback, raw IP | yes |
| IPv4, IPv6 extension and fragment headers, IP fragments reassembled | yes; IPv4 options and extension-header contents are kept as octets |
| UDP and TCP headers | yes; TCP options are kept as octets |
| TCP streams, reassembled across segments | no: a segment's payload is what follows its header |
| checksums, verified | no: none is checked |
| ARP, ICMP and every protocol above UDP and TCP | no built-in dissector: the frame ends there with the rest as its payload, until one is registered |
| other capture file formats | no |

Limits that are not differences in what is read: a pcapng file written back
keeps every frame, link type and time, and none of the options of the
original (comments, interface names); replay sends UDP payloads through an
ordinary socket and never a raw frame; live capture is Linux only.

## Development

```bash
py -3.14-arm64 -m venv .venv/3.14-nt-arm64
.venv/3.14-nt-arm64/Scripts/python -m pip install -e ".[dev,docs]"
.venv/3.14-nt-arm64/Scripts/python -m pytest -q -rs
```

The floor, Python 3.9, has its own venv and is run before a push. The
environments, the checks and the conventions are in
[`AGENTS.md`](https://github.com/jose-pr/pktcap/blob/main/AGENTS.md).

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/jose-pr/pktcap/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow: test gate → build
(checking the tag names the version built) → a strict docs build as a gate →
GitHub release → publish. The release workflow never deploys the docs site
itself: for a final release its last job dispatches the docs workflow at the
tag, which owns every Pages deploy.

## License

MIT — see [LICENSE](https://github.com/jose-pr/pktcap/blob/main/LICENSE).
