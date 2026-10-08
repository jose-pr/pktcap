# Release notes

The detailed companion to [`CHANGELOG.md`](CHANGELOG.md): benchmark figures,
their caveats and the validation evidence behind each release. The changelog
says *what changed*; this says *what it costs and how it was checked*.

## [Unreleased]

Nothing has been released. The package is prepared at version 0.1.0; no tag
exists and nothing has been published.

### TCP stream reassembly

`TCPReassembler` and `read_tcp_streams` put each direction of a TCP connection
back together. How it was checked:

- `tests/test_tcp_streams.py` builds segments with the suite's own builders,
  has a real `FrameDissector` read them and compares the octets handed out with
  the octets the segments were cut from: every ordering of a stream's segments
  with repeats and re-cuts (60 seeded cases), each rule, and each of the five
  bounds (connections, silence, octets held, pieces held, a piece larger than
  the budget) and the guard on acknowledgments, each with a test that fails
  when the bound is removed. A seeded fuzz of mutated segments never raises
  and never passes the bounds; the same mutation mixes far sequence numbers,
  SYNs numbered blind, frames cut by a snap length and padded frames.
- The rules a forged or corrupted segment could walk around each have a test
  built from the octets and numbers a capture carries: one segment far ahead,
  with and without an acknowledgment of it and with another connection filling
  the budget; two that follow one another; a SYN numbered at random on a live
  connection (200 numbers, no octet lost); a capture cut at 64 octets a
  segment; 5,000 segments in order behind one lost segment.
- `tests/conformance/` replays what tshark 4.6.8's `follow,tcp,raw` said about
  twelve built captures and the seven existing ones that hold TCP: the same
  octets in each direction, with the same gaps. pktcap differs in three cases,
  each by a rule it states: octets beyond a hole that is never acknowledged
  (given up when the capture ends), and what follows a reset in sequence (a new
  stream). They are listed in the README and asserted.
- A model written apart from the code, a dictionary of the first captured
  copy of each octet, agrees with one direction's items on 300 seeded streams
  of segments that overlap, repeat, disagree and start near the wrap.
- A mutation of each rule and each bound (106 in all) makes a test fail.

`benchmarks/run.py` measures the reassembler on 2,000 segments of one stream,
in order and with each pair swapped. No figure is recorded here: a local run
is a sanity check and the metrics have not been run on the hosted runners.

### Reading a record back

`loads_record` reads the text `dumps_record` writes. The text is a file
somebody hands the library, so how it was checked is mostly about refusals:

- `tests/test_records_hostile.py` writes 3,000 seeded random records per
  format (nested mappings and lists, every scalar kind, text from ASCII,
  control characters, non-ASCII, astral characters and lone surrogates, keys
  that need percent-encoding) and reads each back. Every exception it found is
  listed in the format header and pinned by a test: two lone surrogates that
  JSON and INI read as one character, names that collide once TOML has
  replaced a lone surrogate, the empty name INI cannot read.
- Hostile text: nesting 100,000 deep in each format; a YAML document of a few
  hundred characters whose aliases would expand to 10**12 items, refused at
  the first alias with nothing built (the writer writes none); a chain of
  YAML merge keys, which would double at every link, refused; numbers of
  100,000 digits; 4,000 texts of random octets per format; a written record
  cut at every position and with random edits, a marker planted in the text
  and searched for in every message and chained exception.
- 54 mutations (one or more for each refusal and each error) are all caught on
  Python 3.14; two more, for the TOML reader on Python before 3.11, on 3.9.

### Benchmark baseline

`benchmarks/results/0.1.0-win_arm64-py3.14.json` and `...-py3.9.json`, the
first results there are, so there is no previous figure to compare with.
Median milliseconds per call, 25 samples, Windows on ARM64, measured
2026-10-05 on a developer's machine that was doing other work:

| Metric | Python 3.14.7 | Python 3.9.10 |
| --- | --- | --- |
| `read_frames/pcap-2000` | 1.78 | 2.48 |
| `read_frames/pcapng-2000` | 3.73 | 5.42 |
| `read_dissected/ethernet-ipv4-udp-2000` | 8.67 | 12.11 |
| `read_dissected/qinq-ipv4-tcp-2000` | 15.72 | 18.26 |
| `read_dissected/registered-dissector-2000` | 13.87 | 13.72 |
| `read_datagrams/ethernet-ipv4-2000` | 17.15 | 15.24 |
| `read_datagrams/fragments-3x666` | 18.45 | 15.15 |
| `dissect/1000-fragments-of-one-datagram` | 3.75 | 4.01 |
| `PcapWriter.write/2000` | 22.55 | 26.73 |
| `PcapngWriter.write_frame/2000` | 4.91 | 4.60 |
| `dumps_record/datagram-json-2000` | 18.97 | 20.45 |
| `dumps_record/frame-json-2000` | 32.28 | 37.24 |
| `compile_capture_filter/apply-2000` | 0.51 | 0.79 |
| `frame_filter/apply-2000` | 8.86 | 11.57 |

**These are a sanity check, not evidence.** The spread between the fastest
and the slowest sample of one metric is up to threefold in these files, and
the two interpreters trade places from one metric to the next for that reason
alone. What the figures do show is the order of magnitude: reading a frame
from its container costs about 1 microsecond, and dissecting it into three to
five layers 3 to 7 more.

The one figure that is a property and not a speed:
`dissect/1000-fragments-of-one-datagram` holds 1,000 fragments of a datagram
that never completes in about 4 ms, because a fragment is placed by a binary
search and the pieces are joined once. `tests/test_reassembly.py` asserts the
shape itself (eight times the fragments cost under sixteen times the work),
so it does not depend on a clock being quiet.

### The cost of the walk per frame

`read_dissected/ethernet-ipv4-udp-2000` is the figure every reader depends on:
the datagram view, the filter keys and live capture are all built on the walk.
It was measured on hosted runners before anything was changed, and one cost
stood out: writing an IPv6 address as text, twice a frame, took about half of
an IPv6 frame's dissection. An address now keeps its text (the 1,024 used
last), so a capture of addresses that never repeat is bounded and costs what
it did.

Median milliseconds per call, 25 samples, `ubuntu-latest`, Python 3.14.7, from
the `Benchmarks` workflow, before (`878c7d1`) and after (`12a69b3`); the files
are `benchmarks/results/ipv6-text-before-Linux-py3.14.json` and
`...-after-...`:

| Metric | Before | After |
| --- | --- | --- |
| `read_frames/pcap-2000` (not changed: it shows the two machines) | 3.76 | 4.10 |
| `read_dissected/ethernet-ipv4-udp-2000` (not changed) | 19.83 | 22.19 |
| `read_dissected/ethernet-ipv6-udp-2000` | 38.57 | 21.19 |

The IPv6 figure halved in every pair of runs on all three hosted systems
(ubuntu 38.6 and 39.8 to 21.2, windows 37.2 to 20.4 on machines of like speed,
macos 26.8 and 26.9 to 11.1).

**What a hosted runner cannot show.** Two runs of one commit differed by 1.8
times on every metric, on ubuntu and on windows, because the jobs landed on
different machines; and the proportion between two metrics moved with the
machine too (the fragment-joining metric cost between 7.1 and 8.8 times a
frame read with the same code). A change to the walk's own loop that measured
about 6% faster on a developer's machine could not be told from that spread
and was not kept. Compare a changed metric with one the change cannot touch,
from the same file, and run a control before believing a regression.

### Validation

- Tests: 2,033 passed and 4 skipped on Windows on ARM64 (Python 3.14 and 3.9);
  2,034 passed and 3 skipped on Intel macOS (Python 3.9) and on FreeBSD
  (Python 3.11). The skips are live capture, which is Linux only, and the
  configuration file's ownership checks, which need POSIX permissions or root.
- The hosted matrix, 18 jobs, green: Python 3.9
  to 3.14 on ubuntu, 3.9 and 3.14 on windows and macos, the dependency floors,
  an install with no extra on each system, and lint with `mypy --strict` for
  `--platform linux`, `darwin` and `win32`. netimps comes from PyPI.
- `black --check` under both supported formatter versions, the caller's
  typing contract and `mkdocs build --strict`: clean.
- Conformance: 41 captures against TShark 4.6.8, replayed with no tool
  installed; `record.py --check` reports no drift from that version.

### Publication state

Public at `github.com/jose-pr/pktcap`, with its documentation site. Not
tagged, and nothing is on PyPI.
