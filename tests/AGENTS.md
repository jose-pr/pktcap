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
| `test_reassembly.py` | IP reassembly through `FrameDecoder`: any order, both families, reassembly off, overlaps and duplicates, and each bound (count, octets, fragments, age, work per fragment, memory) |

## Rules

- **A test asserts through `pktcap`'s public names.** No test imports a private
  module to call it.
- **A bound is seen to fail.** A test for a ceiling is run once against the
  code with the ceiling removed, and must fail there.
- **Nothing leaves the host.** Sockets are loopback, bound to port 0. The guard
  in `conftest.py` enforces it.
