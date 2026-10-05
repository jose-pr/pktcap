# Tests

Running and writing the tests of `pktcap`. The root `AGENTS.md` points here.

## Running them

From the root of a checkout, on the newest interpreter and on the floor:

```bash
.venv/3.14-nt-arm64/Scripts/python -m pytest -q -rs
.venv/3.9-nt-arm64/Scripts/python -m pytest -q -rs
```

`pyproject.toml` puts `src/` on the path and turns warnings into errors. `-rs`
prints the reason for every skip: a skip is not a pass.

## What is here

| File | Covers |
| --- | --- |
| `conftest.py` | the network guard: a test that sends anywhere but loopback fails at the call |
| `test_network_guard.py` | the guard itself refuses an off-host destination and a name lookup |
| `test_surface.py` | exactly what `pktcap.__all__` exports, and that options are keyword-only |
| `test_shipped_header.py` | the shipped `AGENTS.md`: every export is in it, every printed signature is the live one |
| `test_import_structure.py` | no module takes a name from the root, none is over 400 lines, nothing imports a private netimps module |
| `test_comments.py` | the source and the shipped header describe the code as it is |
| `captures.py` | not a test: builders for headers, frames, pcap records and pcapng blocks, each able to state a wrong length; `Pipe`, a stream that cannot seek and records the largest read asked of it |
| `test_container.py` | `read_frames`: both containers, byte orders and resolutions; every way a capture is damaged; what a hostile one can cost; two seeded fuzzes |
| `test_frames.py` | `FrameDecoder` and `read_datagrams`: every link type, IPv4 and IPv6 headers, what is counted as ignored, malformed or unsupported, truncation, the per-frame ceilings, a seeded fuzz per link type |
| `test_writer.py` | `PcapWriter`: the round trip through `read_datagrams`, checksums, the lazy open, what a bad argument leaves untouched |
| `test_filter.py` | the filter grammar: the expressions both protocol libraries use, what is refused, the round trip of the canonical text, compiling with a caller's builder |
| `test_formats.py` | the record formats: one contract suite over every name in `RECORD_FORMATS` (the text parses back with a parser this library did not write), then each format's dialect and the missing-extra message |
| `test_output.py` | `CaptureWriter`: every format as a growing file and as one file per record, choosing the format, the name pattern, the file budget, values that try to leave the directory |
| `test_replay.py` | `replay_schedule`, `replay` and `replay_to`: the waits and their cap, the limit, sends to loopback sockets the test owns over IPv4 and IPv6, partial datagrams, and that the guard sees a replay that would leave the host |
| `test_live.py` | `LiveCapture` and `sniff` with the privileged socket replaced: the lifecycle, what a read is worth, loopback seen once, naming the interface; and one test of the real `AF_PACKET` socket |
| `test_reassembly.py` | IP reassembly through `FrameDecoder`: any order, both families, reassembly off, overlaps and duplicates, and each bound (count, octets, fragments, age, work per fragment, memory) |

## Conformance

`conformance/` holds what the reference, **tshark 4.6.8**, said about each
capture in `conformance/cases/`, and replays it with no tool installed.

| File | What it is |
| --- | --- |
| `conformance/cases/<kind>-<origin>-<topic>/` | one case: the input (`case.pcap`, `case.pcapng`, or `case.json` for what `PcapWriter` is asked to write) and `golden.json`, tshark's answer. `read-` cases decode alike, `refuse-` cases are refused alike, `write-` cases are read by tshark with every checksum good |
| `conformance/test_conformance.py` | the replay; also asserts the README's "Differences from tshark" table is exactly `deviations.json` |
| `conformance/deviations.json` | hand-written: the cases where pktcap differs on purpose, with the sentence the README prints and what pktcap does |
| `conformance/build_cases.py` | development only: writes the hand-built cases octet by octet |
| `conformance/capture_cases.py` | development only, Linux, root: records the cases tcpdump writes and has editcap rewrite three as pcapng |
| `conformance/record.py` | development only, needs tshark: writes each `golden.json`; `--check` re-records in memory and reports drift |

A golden is never edited: change the case, or the code, and record again. A
case file is recorded evidence and is not normalised (`.gitattributes`). A
capture written by dumpcap carries the capturing host's kernel release, so
pcapng cases are written by editcap, which adds only its own name.

## Rules

- **A test asserts through `pktcap`'s public names.** No test imports a private
  module to call it. One file patches a private name: `test_live.py` replaces
  `pktcap._live._open_socket`, because the real socket needs a capability.
- **Expected skips**: one, the real `AF_PACKET` test in `test_live.py`, on any
  platform but Linux and on Linux without `CAP_NET_RAW`. As root on Linux
  there are none. The IPv6 tests of `test_replay.py` skip on a host with no
  IPv6 loopback address.
- **A bound is seen to fail.** A test for a ceiling is run once against the
  code with the ceiling removed, and must fail there.
- **Nothing leaves the host.** Sockets are loopback, bound to port 0. The guard
  in `conftest.py` enforces it.
