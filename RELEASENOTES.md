# Release notes

The detailed companion to [`CHANGELOG.md`](CHANGELOG.md): benchmark figures,
their caveats and the validation evidence behind each release. The changelog
says *what changed*; this says *what it costs and how it was checked*.

## 0.1.2 — 2026-10-18

Writing TCP: `write_tcp()` on both writers, one segment under synthesised
IPv4 or IPv6 and TCP headers, and `TCPFlowWriter`, a whole connection written
from the octets of each direction (see [`CHANGELOG.md`](CHANGELOG.md)). The
IP and UDP synthesis behind `write()` moved to a module shared by both
transports, so the write path was measured.

### Benchmarks

`benchmarks/run.py` on Windows on ARM64, 0.1.1 and 0.1.2 run one after the
other on the same machine, medians of 15 samples. A local sanity check, not a
claim: nothing moved by more than 10%. `PcapWriter.write/2000` went from
15.98 to 16.74 ms on Python 3.14 (+4.7%) and from 25.51 to 26.33 ms on 3.9
(+3.2%); every reading benchmark is within 5% either way.

### Validation

Measured on 2026-10-18 at commit `b59b8dc`, with netimps 0.4.1 and duho
0.7.4, each as published.

- Windows on ARM64: 2,650 passed and 8 skipped on Python 3.14; 2,651 passed
  and 7 skipped on Python 3.9. The 66 new tests include the law that every
  written connection reads back exactly through `read_tcp_streams` (IPv4,
  IPv6, mixed, sequence numbers wrapping, `mss` from 1), with the checksums
  verified by an independent implementation.
- Linux (Fedora 44 under WSL2), unprivileged and as root, on Python 3.14 and
  3.9: between 2,644 and 2,648 passed, no failure.
- Intel macOS 15.7, Python 3.9: 2,646 passed, 12 skipped. FreeBSD 16.0,
  Python 3.11, an unprivileged account: 2,644 passed, 14 skipped.
- The hosted matrix, 18 jobs, green (run 39144331983). `black --check`,
  `mypy --strict` for the three platforms, `mkdocs build --strict`, the build
  and `twine check`: clean.

## 0.1.1 — 2026-10-14

A dependency release: the `cli` extra requires duho 0.7.4, and what that
changes for a user of the command line is in [`CHANGELOG.md`](CHANGELOG.md).
Nothing on a measured path changed, so no benchmark was run.

### Validation

Measured on 2026-10-14 at commit `e5a128e`, with netimps 0.4.1 and duho 0.7.4,
each as published.

- Windows on ARM64: 2,584 passed and 8 skipped on Python 3.14; 2,585 passed
  and 7 skipped on Python 3.9. That is one more passed than 0.1.0 on each: the
  test of a relative `APPDATA` runs on Windows now.
- Linux (Fedora 44 under WSL2), unprivileged and as root, on Python 3.14 and
  3.9: between 2,578 and 2,582 passed, no failure.
- Intel macOS 15.7, Python 3.9: 2,580 passed, 12 skipped. FreeBSD 16.0,
  Python 3.11, an unprivileged account: 2,578 passed, 14 skipped.
- The hosted matrix, 18 jobs, green, as for 0.1.0. `black --check`, `mypy
  --strict` for the three platforms, the caller's typing contract and `mkdocs
  build --strict`: clean.

## 0.1.0 — 2026-10-12

The first release of `pktcap`: reading, dissecting, filtering, writing and
replaying pcap and pcapng captures, TCP stream reassembly, live and UDP-socket
capture, hooks, plugins, and a `duho` command line that is also served as MCP
tools and is a base a protocol library subclasses. What it contains is in
[`CHANGELOG.md`](CHANGELOG.md); this is what it costs and how it was checked.

### The commands as a base, the socket source and hooks

How it was checked:

- `tests/test_cli_subclass.py` is the contract: a demonstration subclass of
  `Convert`, `Capture` and `Replay` uses every override point, mixed with a base
  class that has a `config` and a `listen` of its own; the Python block of
  `cli/AGENTS.md` is executed there.
- `tests/test_cli_listen.py` drives `capture --listen` on loopback sockets the
  tests own, and once through `python -m pktcap` as a child process, which
  prints one line for a datagram sent to the address `-v` reports.
- `tests/test_cli_hook.py` runs real programs and Python functions as hooks.
- Mutations of the override points being called, each bound of the socket
  source and of the hook program, the datagram an endpoint does not admit, the
  `always` rule of the plugin list, and the escaping and the cut of a text
  line each make a test fail (the counts are under "Validation").
- Measured 2026-10-09: a socket on macOS 15.7 and FreeBSD 16.0 cannot send a UDP
  datagram above `net.inet.udp.maxdgram` (9216 octets by default), so the test
  of the largest datagram sends what the host will.

### The settings file of the command line

The rules a user needs: the argument wins over the variable, the variable over
the file, and a layer replaces a lower one for that option only. The default
file must be the user's or root's and not writable by everyone (POSIX); a file
named by `--config` or `PKTCAP_CONFIG` is read as it is. A key or table nobody
has, a `config` key, a `[pktcap]` table, an invalid document and a file over
65,536 octets are status 2 with one line that never holds text of the file.
An empty path means no file. A hook and a plugin list are taken from the
layers a class lists and from no other, because both run code.

How it was checked:

- `tests/test_cli_settings.py` drives the real command: a table for a command
  in INI, TOML and JSON; the top-level `load` reaching every command; the
  argument over the variable over the file; each refusal with a marker planted
  in the file and absent from the one line printed; the default file's
  location on each platform, its owner and mode (POSIX, as root under Linux for
  the owner); a real server (`PKTCAP_MCP=stdio`) given the user's file, the
  variable and a call naming `config`, reading the user's own file and neither
  of the others; a subclass that narrows the layers a list may come from.
- Mutations of the loader's refusals, the cap, the default file's checks, the
  layers a list or a hook may come from, a served tree, the library reading a
  variable or a file, and the plugins being loaded before the output is looked
  at each make a test fail; those that depend on file permissions run under
  Linux (the counts are under "Validation").
- Measured 2026-10-12 on duho 0.7.3 (Python 3.9 and 3.14): the loader is told
  where its path came from (`field`, `env` or `default`); a real server applies
  the class-level default file but not the variable's file or a call's `config`;
  `--config ""` and an empty `PKTCAP_CONFIG` read no file; a tool call that asks
  for `pcap` or `pcapng` has its octets written to the server's output target
  (`PKTCAP_MCP_OUTPUT`) byte for byte as the command line writes them.

### TCP stream reassembly

`TCPReassembler` and `read_tcp_streams` put each direction of a TCP connection
back together. A reader of a capture is passive, so what it refuses is
stated: a hole is waited for and given up at an acknowledgment past it, a
bound or the end; a segment, FIN or reset more than 16,777,216 octets beyond
what the sender is believed to have sent, and a SYN that is not a live
connection's own, are set aside until a later segment confirms them, so one
forged number moves nothing; every table a capture can grow is bounded. How it
was checked:

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
  the captures that hold TCP: the same octets in each direction, with the same
  gaps. pktcap differs in three cases, each by a rule it states: octets beyond
  a hole that is never acknowledged (given up when the capture ends), what
  follows a reset in sequence (a new stream), and the numbering of the streams
  after one. They are listed in the README and asserted.
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
- Mutations of each refusal and each error are all caught on Python 3.14, and
  those of the TOML reader on Python before 3.11 on 3.9 (the counts are under
  "Validation").

### Benchmark baseline

`benchmarks/results/0.1.0-win_arm64-py3.14.json` and `...-py3.9.json`, the
baseline a later release is compared with.
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
Writing an IPv6 address as text, twice a frame, took about half of an IPv6
frame's dissection, so an address keeps its text (the 1,024 used last): a
capture of addresses that never repeat is bounded and costs what an uncached
walk costs, and a capture that repeats them costs about half.

Median milliseconds per call, 25 samples, `ubuntu-latest`, Python 3.14.7, from
the `Benchmarks` workflow, without the cache (`878c7d1`) and with it
(`12a69b3`); the files are
`benchmarks/results/ipv6-text-before-Linux-py3.14.json` and `...-after-...`:

| Metric | Without | With |
| --- | --- | --- |
| `read_frames/pcap-2000` (not changed: it shows the two machines) | 3.76 | 4.10 |
| `read_dissected/ethernet-ipv4-udp-2000` (not changed) | 19.83 | 22.19 |
| `read_dissected/ethernet-ipv6-udp-2000` | 38.57 | 21.19 |

The IPv6 figure halves in every pair of runs on all three hosted systems
(ubuntu 38.6 and 39.8 to 21.2, windows 37.2 to 20.4 on machines of like speed,
macos 26.8 and 26.9 to 11.1).

**What a hosted runner cannot show.** Two runs of one commit differed by 1.8
times on every metric, on ubuntu and on windows, because the jobs landed on
different machines; and the proportion between two metrics moved with the
machine too (the fragment-joining metric cost between 7.1 and 8.8 times a
frame read with the same code). A difference of about 6% in the walk's own loop
cannot be told from that spread. Compare a changed metric with one the change cannot touch,
from the same file, and run a control before believing a regression.

### Validation

Measured on 2026-10-12 at commit `071a8d5`, with netimps 0.4.1 and duho 0.7.3.

- Windows on ARM64: 2,583 passed and 9 skipped on Python 3.14; 2,584 passed
  and 8 skipped on Python 3.9.
- Linux (Fedora 44 under WSL2), unprivileged and as root, on Python 3.14 and
  3.9: between 2,578 and 2,582 passed, no failure. As root the live-capture
  tests run; elsewhere they skip, as do the configuration file's ownership
  checks that need POSIX permissions or root.
- Intel macOS 15.7, Python 3.9: 2,580 passed, 12 skipped. FreeBSD 16.0,
  Python 3.11, an unprivileged account: 2,578 passed, 14 skipped.
- The hosted matrix, 18 jobs, green: Python 3.9 to 3.14 on ubuntu, 3.9 and
  3.14 on windows and macos, the dependency floors, an install with no extra
  on each system, and lint with `mypy --strict` for `--platform linux`,
  `darwin` and `win32`. netimps comes from PyPI.
- `black --check` under both supported formatter versions, the caller's
  typing contract and `mkdocs build --strict`: clean.
- Mutation checks, every one caught by a test: 120 of the commands, 62 of the
  record formats, 34 of the settings file plus 7 of its POSIX ownership rules,
  106 of the TCP reassembler, and those of the plugin loader.
- An independent adversarial review of the socket source, the hooks, the text
  output and the command classes found 15 things; all were fixed or settled
  before this release.
- Conformance: 53 cases against TShark 4.6.8 (40 read, 9 refused, 4 written),
  replayed with no tool installed; `tests/conformance/record.py --check`
  re-records them against an installed tshark and reports drift.

### Publication state

Published on PyPI and on GitHub (`github.com/jose-pr/pktcap`), tagged `v0.1.0`,
with its documentation site.
