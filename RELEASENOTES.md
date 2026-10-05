# Release notes

The detailed companion to [`CHANGELOG.md`](CHANGELOG.md): benchmark figures,
their caveats and the validation evidence behind each release. The changelog
says *what changed*; this says *what it costs and how it was checked*.

## [Unreleased]

Nothing has been released. The package is prepared at version 0.1.0; no tag
exists and nothing has been published.

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

### Next performance target

The cost of the walk per frame: `read_dissected/ethernet-ipv4-udp-2000`.
A regression there slows every reader in the package, since the datagram
view, the filter keys and live capture are all built on it.

### Validation

- Tests: 970 on Linux as root (Python 3.14.3 and 3.9.25, aarch64), where the
  one test of a real `AF_PACKET` socket runs; 969 passed and that one skipped
  on Windows on ARM64 (Python 3.14.7 and 3.9.10) and on Linux without
  `CAP_NET_RAW`.
- `black --check`, `mypy --strict` for `--platform linux`, `darwin` and
  `win32`, and `mypy` over the caller's typing contract: clean.
- `mkdocs build --strict`: clean.
- Conformance: 41 captures against TShark 4.6.8, replayed with no tool
  installed; `record.py --check` reports no drift from that version.
- macOS, the BSDs and x86-64 have not been run: no continuous integration has
  run yet, since the repository has no remote.

### Publication state

Prepared locally. Not pushed, not tagged, not published.
