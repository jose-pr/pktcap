# pktcap

[![Version](https://img.shields.io/pypi/v/pktcap.svg)](https://pypi.org/project/pktcap/)
[![Python versions](https://img.shields.io/pypi/pyversions/pktcap.svg)](https://pypi.org/project/pktcap/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/pktcap/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/pktcap/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/pktcap/test.yml)](https://github.com/jose-pr/pktcap/actions/workflows/test.yml)

**The capture layer a UDP protocol library needs, and nothing above it**: read
pcap and pcapng, decode frames to UDP datagrams, write them back, replay them.
What a datagram means stays with the library that speaks the protocol. Built on
the standard library and [netimps](https://github.com/jose-pr/netimps).
Documentation: <https://jose-pr.github.io/pktcap/>.

## Features

- **Reads pcap and pcapng** — either byte order, microseconds or nanoseconds,
  several interfaces, from a file or from a pipe that cannot seek
  (`tcpdump -w -`, `dumpcap -w -`).
- **Decodes frames to UDP datagrams** — Ethernet with VLAN tags, Linux cooked
  capture, BSD loopback and raw IP; IPv4 and IPv6 with extension headers.
  Reassembling IP fragments is an option.
- **Treats a capture as untrusted input** — every length, count and offset a
  file states has a ceiling checked before anything is allocated: a 48-octet
  file claiming a 1 GiB record costs under 1 MiB and one `CaptureFormatError`.
  A frame that does not decode is counted, never dropped silently.
- **Writes pcap** that tcpdump and Wireshark read, with valid checksums, and
  opens the file only when there is something to write.
- **Writes records in a format chosen by name** — the datagram, or the plain
  data a protocol library makes of it, as JSON lines, YAML documents, TOML or
  INI files, into one growing file or one file per record.
- **Replays a capture** — on its recorded timing, to a callable or to one
  destination the caller names; never to the addresses in the file.
- **Parses the `key=value and key!=value` filter expression**, leaving what a
  key means to the caller.
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

Write a capture and read it back:

```python
import pktcap

with pktcap.PcapWriter("trace.pcap") as writer:
    writer.write(1700000000.00, ("192.0.2.5", 50000), ("192.0.2.1", 69), b"request")
    writer.write(1700000000.05, ("192.0.2.1", 40000), ("192.0.2.5", 50000), b"reply 1")
    writer.write(1700000000.10, ("192.0.2.1", 40000), ("192.0.2.5", 50000), b"reply 2")

for datagram in pktcap.read_datagrams("trace.pcap"):
    print(datagram.time, datagram.source, datagram.destination, datagram.payload)
```

See what a capture held that was not a datagram:

```python
decoder = pktcap.FrameDecoder(reassemble=True)
datagrams = list(pktcap.read_datagrams("trace.pcap", decoder=decoder))
print(decoder.stats)  # frames, datagrams, ignored, malformed, unsupported, ...
```

Write it in another format, with the record your own protocol makes:

```python
with pktcap.CaptureWriter("trace.json") as output:  # the format is the suffix
    for datagram in datagrams:
        output.write(datagram, {"size": len(datagram.payload), "to": datagram.destination[1]})

print(pktcap.dumps_record(pktcap.datagram_record(datagrams[0]), "ini"))
```

Filter with the shared expression grammar and your own keys:

```python
def build(clause):
    if clause.key != "port":
        raise ValueError("unknown filter key %r" % clause.key)
    ports = {int(value) for value in clause.values}
    return lambda d: d.source[1] in ports or d.destination[1] in ports

wanted = pktcap.compile_capture_filter("port=69,70 and port!=40000", build)
print([d.payload for d in datagrams if wanted(d)])
```

Replay it, at the recorded pace, to a destination you name:

```python
from netimps import bind

listener = bind("127.0.0.1", 0)  # a UDP socket on a free loopback port
result = pktcap.replay_to("trace.pcap", "127.0.0.1", listener.getsockname()[1])
print(result)  # ReplayResult(sent=3, partial=0)
print(listener.recvfrom(1500)[0])
listener.close()
```

## API overview

Everything is imported from `pktcap`; the modules below it are private.

| Module | Purpose |
| --- | --- |
| `pktcap` | every public name, below |

| Names | Purpose |
| --- | --- |
| `read_frames`, `CapturedFrame`, `CaptureSource` | read a pcap or pcapng container |
| `read_datagrams`, `FrameDecoder`, `CapturedDatagram`, `DecodeStats`, `LINKTYPES` | decode frames to UDP datagrams, reassembly optional |
| `PcapWriter` | write datagrams as pcap |
| `CaptureWriter`, `dumps_record`, `datagram_record`, `OUTPUT_FORMATS`, `RECORD_FORMATS`, `has_output_format` | write datagrams or records in a named format |
| `replay_schedule`, `replay`, `replay_to`, `ReplayResult`, `ReplaySource` | replay a capture |
| `parse_capture_filter`, `compile_capture_filter`, `FilterClause` | the filter expression |
| `LiveCapture`, `sniff`, `has_live_capture` | live capture on Linux |
| `PktcapError`, `CaptureFormatError`, `CaptureFilterError`, `UnsupportedFormatError`, `LiveCaptureError` | the exceptions |

The reference with every signature, bound and gotcha is the API header that
ships inside the package, `pktcap/AGENTS.md`, also at
<https://github.com/jose-pr/pktcap/blob/main/src/pktcap/AGENTS.md>.

## Differences from tshark

The reference for what a capture holds is **tshark 4.6.8** (Wireshark's
command-line reader). `tests/conformance/` records what it says about 39
captures, written by tcpdump 4.99.6, by Wireshark's editcap and by hand, and
the suite replays those answers with no tool installed. Fidelity is to
results: which datagrams a capture holds (time, addresses, ports, payload),
which captures are refused and after how many frames, and that tshark reads
what `PcapWriter` writes with every checksum good. Message texts and exit
statuses are not reproduced.

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
| Ethernet with VLAN tags, Linux cooked v1 and v2, BSD loopback, raw IP | yes |
| IPv4 options, IPv6 extension headers, IP fragments | yes |
| UDP | yes |
| every other link type, TCP, and every protocol above UDP | no: counted, never decoded |
| other capture file formats | no |

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
