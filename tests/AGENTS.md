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
| `conftest.py` | the network guard: a test that sends anywhere but loopback fails at the call; every test runs with no `PKTCAP_LOAD` and `PKTCAP_CONFIG=none`; `plugin_module` writes a plugin module under a unique name into a temporary directory on `sys.path` |
| `test_network_guard.py` | the guard itself refuses an off-host destination and a name lookup |
| `test_surface.py` | exactly what `pktcap.__all__` exports, and that options are keyword-only |
| `test_shipped_header.py` | the shipped `AGENTS.md` headers: every export is in the top one, every printed signature is the live one, every option a command declares is in `cli/AGENTS.md`, and a built wheel holds it and the console script |
| `test_import_structure.py` | no module takes a name from the root, none is over 400 lines, nothing imports a private netimps module; the trust boundary of plugin loading: which module may import by name, read the environment, import the loader |
| `test_comments.py` | the source and the shipped header describe the code as it is |
| `test_readme.py` | the README's sections, badges and links, every Python block of "Quick start" executed in an empty directory, and every `pktcap` line of "Command line" run as written |
| `test_examples.py` | each script under `examples/` run as its own process, with no argument and with a capture and a filter |
| `test_values.py` | the named tuples as values (immutable, hashable, copy, pickle, repr) and the exception hierarchy |
| `typing/api.py` | the static-typing contract of a caller; never executed, checked by `mypy tests/typing/api.py` |
| `captures.py` | not a test: builders for headers, frames, pcap records and pcapng blocks, each able to state a wrong length; `Pipe`, a stream that cannot seek and records the largest read asked of it |
| `test_container.py` | `read_frames`: both containers, byte orders and resolutions; every way a capture is damaged; what a hostile one can cost; two seeded fuzzes |
| `test_registry.py` | `DissectorRegistry`, the default registry and `check_dissector`: a taken selector, replacing, two registries sharing nothing, a dissector that breaks the contract failing the check |
| `test_dissectors.py` | each built-in dissector called on its own: every field of every layer, every header cut short or lying about its length, and `check_dissector` over each with 5,000 damaged inputs |
| `test_dissect.py` | `FrameDissector`, `read_dissected` and `read_datagrams`: the walk under every link type, what ends it, the 32-dissector ceiling, a registered dissector that refuses its octets or fails outright, the datagram view, a seeded fuzz per link type |
| `test_writer.py` | `PcapWriter` and `PcapngWriter`: datagrams under synthesised headers with their checksums, frames written back octet for octet, one link type per pcap file and any mix in pcapng, the lazy open, what a bad argument leaves untouched |
| `test_plugin_config.py` | where a plugin list comes from: the order argument, variable, file; the file's location and dialect, each malformed file, the trust of the default file against a named one, the bounds |
| `test_plugins.py` | `load_plugins`: both forms of an item, every way a plugin fails with the registry left as it was, and fresh-interpreter tests that `import pktcap` reads no variable and imports no plugin |
| `test_layer_filter.py` | layers and filter keys in a registry: `LAYER.FIELD` by each type a field holds, a library's own keys, every collision, each refusal at compile and each bound |
| `test_filter.py` | the filter grammar: the expressions protocol libraries use, what is refused, the round trip of the canonical text, compiling with a caller's builder |
| `test_frame_filter.py` | `frame_filter`: each built-in key against IPv4, IPv6, TCP, UDP and tagged frames, a frame without the layer, a wrong value, a caller's own keys on top |
| `test_formats.py` | the record formats: one contract suite over every name in `RECORD_FORMATS` (the text parses back with a parser this library did not write), then each format's dialect and the missing-extra message |
| `test_output.py` | `CaptureWriter`: every format as a growing file and as one file per record, datagrams and dissected frames, choosing the format, the name pattern, the file budget, values that try to leave the directory |
| `test_cli.py` | the command line as a whole: `python -m pktcap`, the version, the statuses of a wrong invocation, the missing `cli` extra read in a process where duho cannot be imported, and that `import pktcap` loads neither duho nor the command package |
| `test_cli_convert.py` | `pktcap convert`: one record per frame, a round trip through pcapng octet for octet, the filter, the datagram view, a cut capture, each combination refused before anything is read, and the capture octets on a real standard output compared with the file's |
| `test_cli_replay.py` | `pktcap replay` to loopback sockets the test owns: the whole datagrams in order and the partial one counted, `--json`, the limit, the filter, the recorded pace and `--max-delay`, the source port, a destination with no port or that does not resolve, a cut capture, standard input |
| `test_cli_plugins.py` | the commands and plugins: the option, the variable and the file give one output, a name that does not import, `pktcap plugins` in text, per layer and as JSON, a tool call refused when it names plugins or a file, and the trust test of a hostile working directory and capture |
| `test_cli_tools.py` | `convert` and `plugins` served as tools and nothing else: the tool list, a call that returns the records as its result, capture octets refused as text, and the real server driven over pipes with `PKTCAP_MCP=stdio` |
| `test_cli_capture.py` | `pktcap capture`: the refusal off Linux, every option with `test_live.py`'s stand-in socket (count, filter, datagram view, duration, Ctrl-C, no capability), and one test of the real socket on loopback |
| `test_copy.py` | `copy_frames`: a capture of UDP, TCP and ARP frames copied whole and as datagrams, the filter, the limit that leaves the source unread, the file budget's refusals, and what is refused at the call |
| `test_replay.py` | `replay_schedule`, `replay` and `replay_to`: the waits and their cap, the limit, sends to loopback sockets the test owns over IPv4 and IPv6, partial datagrams, frames replayed to a callable and never sent, and that the guard sees a replay that would leave the host |
| `test_live.py` | `LiveCapture`, `sniff_frames` and `sniff` with the privileged socket replaced: the lifecycle, every packet as a cooked frame, loopback seen once, naming the interface; and one test of the real `AF_PACKET` socket |
| `test_tcp_streams.py` | TCP stream reassembly through `FrameDissector` and real segments: order, retransmission, overlap, wrap, start and end, a reset, a new stream on the same addresses once a SYN is confirmed, a segment far beyond what was believed, frames cut by a snap length, both families, and any order of a stream's segments giving its octets back |
| `test_reassembly.py` | IP reassembly through `FrameDissector`: any order, both families, any protocol, reassembly off, overlaps and duplicates, and each bound (count, octets, fragments, age, work per fragment, memory) |

## Conformance

`conformance/` holds what the reference, **tshark 4.6.8**, said about each
capture in `conformance/cases/`, and replays it with no tool installed.

| File | What it is |
| --- | --- |
| `conformance/cases/<kind>-<origin>-<topic>/` | one case: the input (`case.pcap`, `case.pcapng`, or `case.json` for what a writer is asked to write) and `golden.json`, tshark's answer: per frame, the fields of each layer this library dissects; per UDP datagram, its addresses and payload; per TCP stream, the octets of each direction as `follow` gives them, with the gaps. `read-` cases are read alike, layer by layer; `refuse-` cases are refused alike; `write-` cases are read by tshark as the frames or datagrams asked for |
| `conformance/test_conformance.py` | the replay; also asserts the README's "Differences from tshark" table is exactly `deviations.json` |
| `conformance/deviations.json` | hand-written: the cases where pktcap differs on purpose, with the sentence the README prints and what pktcap does |
| `conformance/build_cases.py` | development only: writes the hand-built cases octet by octet, and the `case.json` of three `write-` cases |
| `conformance/capture_cases.py` | development only, Linux, root: records the cases tcpdump writes (UDP datagrams, fragments, two TCP connections), has editcap rewrite four as pcapng, and takes one with this library's own `LiveCapture`; naming cases records only those |
| `conformance/record.py` | development only, needs tshark: writes each `golden.json`; `--check` re-records in memory and reports drift |

A golden is never edited: change the case, or the code, and record again. A
case file is recorded evidence and is not normalised (`.gitattributes`). A
capture written by dumpcap carries the capturing host's kernel release, so
pcapng cases are written by editcap, which adds only its own name.

## Rules

- **A test asserts through `pktcap`'s public names.** No test imports a private
  module to call it. One file patches private names: `test_live.py` replaces
  `pktcap._live._open_socket` and `_AF_PACKET`, because the real socket needs
  a capability and a platform that has it; `test_cli_capture.py` uses its
  `packet_socket` fixture and patches nothing itself.
- **Expected skips**: two, the real `AF_PACKET` tests in `test_live.py` and
  `test_cli_capture.py`, on any platform but Linux and on Linux without
  `CAP_NET_RAW`. As root on Linux
  there are none. The IPv6 tests of `test_replay.py` skip on a host with no
  IPv6 loopback address.
- **A bound is seen to fail.** A test for a ceiling is run once against the
  code with the ceiling removed, and must fail there.
- **Nothing leaves the host.** Sockets are loopback, bound to port 0. The guard
  in `conftest.py` enforces it.
