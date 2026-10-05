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

- **One exception base** — `PktcapError`, for anything the library reports on
  its own account.

## Installation

```bash
pip install pktcap
```

Requires Python 3.9 or newer.

| Extra | Adds | Needed for |
| --- | --- | --- |
| `yaml` | `PyYAML` | writing records as YAML |
| `toml` | `tomli-w` | writing records as TOML |

## Quick start

```python
import pktcap

print(pktcap.__version__)
```

## API overview

Everything is imported from `pktcap`; the modules below it are private.

| Module | Purpose |
| --- | --- |
| `pktcap` | every public name |

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
