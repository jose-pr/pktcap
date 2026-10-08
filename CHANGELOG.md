# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Dissecting an IPv6 frame costs about half. An IPv6 address keeps its text
  (the 1,024 a process used last), since a capture names few hosts and every
  frame names two. What a caller gets back is the same.
- A field value used in a per-record file name and longer than 64 characters
  is cut to 55 and ends in `-` and 8 hexadecimal digits of the SHA-256 of the
  whole value, so two long values that start alike name two files. Before, the
  value was cut at 64 characters and they named one.
- A field value can no longer make a directory of a per-record path
  (`{client}/{index}.json`) a name Windows opens as a device: the part gets a
  leading `_` on every platform, as the file's own name did. Before, a value
  of `nul` there made every write under it fail on Windows. A part the
  pattern spells out is kept as written.

### Added

- `TCPReassembler(*, max_streams=1024, max_buffered=16777216,
  idle_timeout=300.0)` puts TCP streams back together from dissected frames:
  `add(frame)` returns the `TCPStreamData` the frame made deliverable, each
  direction's octets in order with an `offset`, the octets given up on before
  them (`missing`), a connection number (`stream`) and an `end` marker;
  `flush()` gives what is still held at the end of a capture; `stats` is a
  `TCPStreamStats`. Sequence numbers wrap, the first captured copy of an
  octet wins, a FIN or an in-sequence RST ends a direction or a connection, and
  a SYN that is not a retransmission starts a new stream on the same
  addresses. The checksum is not verified and a segment in an IP fragment that
  was not reassembled is ignored.
- `DissectorRegistry.register_layer(layer, *, name=None, keys=None,
  replace=False)`, `unregister_layer(name)` and `layers()` declare the class
  of a layer a dissector returns, and optionally the filter keys over it.
  `frame_filter_for(registry)` is the filter `build` that knows them:
  `LAYER.FIELD` reads any field of a built-in or declared layer by the type of
  its value (`ipv4.ttl=64`, `udp.destination_port=0x270f`), `LAYER.KEY` and
  the bare `KEY` read a library's own keys, and a wrong key or a value that
  can never match is refused when the filter is compiled.
  `frame_filter_keys(registry=None)` lists every key that compiles.
  `frame_filter` reads no registry; it answers `LAYER.FIELD` of the built-in
  layers.
- `load_plugins(registry, plugins=None, *, config=None)` imports the modules
  a list names and calls each one's hook, `pktcap_plugin(registry)` (or any
  `MODULE.CALLABLE` taking the registry), so a protocol library's dissector and
  filter keys are registered with no code of the user's. The list is the first
  of the argument, the variable `PKTCAP_PLUGINS` and the `plugins` key of one
  configuration file that names one; it is read from those places and never
  from the working directory or a capture. The file is `pktcap/pktcap.ini`
  under `$XDG_CONFIG_HOME` (else `~/.config`), or `%APPDATA%` on Windows;
  `PKTCAP_CONFIG` or `config` names another, read as it is, while the one found
  by default must be the user's own and not writable by everyone (POSIX).
  `capture_config_path(config=None)` says which file applies and
  `LoadedPlugin` is one result. A plugin that cannot be loaded raises
  `CapturePluginError` and leaves the registry as it was; a malformed file
  raises `CaptureConfigError` with its path and line, never a line of the file.
  `import pktcap` reads no variable and imports no plugin.
- The `pktcap` command, also `python -m pktcap`, behind the new `cli` extra
  (`pip install "pktcap[cli]"`, which brings `duho`). Without the extra the
  command prints the one line naming it and exits 1. `import pktcap` imports
  neither `duho` nor the command package, `pktcap.cli`, which is not library
  API. Exit status: 0 done, 1 the operation failed, 2 the invocation was
  wrong.
- `pktcap convert --input FILE|- [--output TARGET] [--format FMT] [--filter
  EXPR] [--datagrams] [--per-record] [--max-files N] [--limit N]` copies a
  pcap or pcapng capture into pcap, pcapng or records (json, yaml, toml,
  ini), through `copy_frames`. Standard output is the default target and may
  be the capture; the summary is on standard error.
- `pktcap replay --input FILE|- --to HOST:PORT [--filter EXPR] [--speed X |
  --no-delay] [--max-delay SECONDS] [--limit N] [--source-port N]
  [--broadcast] [--json]` sends the UDP payloads of a capture, in order and in
  time, through `replay_to`. `--to` is the only destination there is: the
  addresses in the file are never sent to. The result is the one line
  `sent 12, partial 0`, or an object with `--json`.
- `pktcap capture [--interface NAME] [--filter EXPR] [--output TARGET]
  [--format FMT] [--datagrams] [--per-record] [--max-files N] [--count N]
  [--duration SECONDS]` captures live through `sniff_frames` and `copy_frames`
  (Linux, `CAP_NET_RAW`). Ctrl-C ends it with status 0 and the summary; off
  Linux the one line says to pipe a capture tool into `pktcap convert`.
- Every command takes `--plugins NAME` (repeatable; `none` for none) and
  `--config`/`-c FILE` (`none` for no file), loading into a registry of its
  own before the filter is compiled, so `pktcap capture -f "proto=dhcp"` and a
  library's own keys work with no code written; `--count` of `capture` has no
  short form, `-c` being the configuration file on every command.
  `pktcap plugins [--layer NAME] [--json]` shows the file, what was loaded and
  every filter key, and is served as the tool `pktcap.plugins`. A tool call
  cannot name `plugins` or `config`: it is refused, and the server's own
  `PKTCAP_PLUGINS` and file decide.
- `PKTCAP_MCP=stdio pktcap` serves `convert` as a tool (`pktcap.convert`):
  the records come back as the tool's result, and a capture format is refused
  for standard output, which a tool call has no octets for. `capture` and
  `replay` are not served: one runs until stopped and needs a privilege, the
  other puts datagrams on a network.
- `sniff_frames(interface=None, *, stop=None, dissector=None)` yields every
  frame seen live, dissected, as `read_dissected` does for a file; `sniff` is
  its datagram view, with the behaviour it had.
- `copy_frames(frames, writer, *, select=None, datagrams=False, limit=None)`
  writes the frames a predicate accepts into a `CaptureWriter` the caller
  owns, optionally as the UDP datagram of each, and stops reading at `limit`;
  it returns `CopyResult(read, written, skipped, refused)`.
- `MissingExtraError`, an `ImportError` and a `PktcapError`, is what a format
  whose optional dependency is not installed raises. `format` is the format's
  name and `extra` the pktcap extra that installs what it needs (`"toml"`,
  `"toml"`), so a library that offers the format under its own extra words
  its own message without reading this one. The message is unchanged, and
  `except ImportError` still catches it.
- `FrameDissector.unsupported_linktypes`, a read-only snapshot mapping each
  link type that had no dissector to the number of frames of it (`{105: 3}`),
  so a caller can say which link type a capture it could not read was made
  on. The first 64 distinct link types are told apart;
  `DissectStats.unsupported` counts every frame.
- The package, with one exception base, `PktcapError`, and `__version__`.
- `read_frames(source, *, max_frame_size=262144)` reads every frame of a pcap
  or pcapng capture, from a path or from a stream that cannot seek, as
  `CapturedFrame(time, linktype, data, interface=None)` named tuples, whatever
  the link type. Every length the file states is checked against a ceiling
  before it is read: a 48-octet file whose record claims 1 GiB raises
  `CaptureFormatError` having allocated under 1 MiB. Any damaged capture
  raises `CaptureFormatError`, a `ValueError`, with the octet offset.
- `FrameDissector(registry=None, *, reassemble=True, max_reassemblies=256,
  reassembly_timeout=30.0)` and `read_dissected(source, *, dissector=None)`
  dissect frames layer by layer into `DissectedFrame` named tuples: the layer
  records in order, the octets after each, and what no dissector read. A
  frame is never raised for: a layer cut short is counted `malformed` and
  named in `DissectedFrame.error`, a link type with no dissector is counted
  `unsupported` and returned whole, and at most 32 dissectors run on one
  frame (`DissectStats`).
- Built-in dissectors for Ethernet, 802.1Q and 802.1ad tags, Linux cooked
  capture v1 and v2, BSD loopback, raw IP, IPv4, IPv6 with its hop-by-hop,
  routing, destination and fragment headers, UDP and TCP, each making a named
  tuple: `EthernetLayer`, `VLANLayer`, `LinuxCookedLayer`, `LoopbackLayer`,
  `IPv4Layer`, `IPv6Layer`, `IPv6ExtensionLayer`, `IPv6FragmentLayer`,
  `UDPLayer`, `TCPLayer`. TCP is read a segment at a time; streams are not
  reassembled, and no checksum is verified.
- A dissector is any callable `(data: bytes) -> Dissected(layer, payload,
  next=(), fragment=None)`. `DissectorRegistry(*, builtins=True)` maps a
  selector `(kind, number)` (`linktype`, `ethertype`, `ip`, `udp`, `tcp`, or
  any other kind) to one, refusing a selector that is taken unless
  `replace=True`; `default_registry()` and `register_dissector(kind, value,
  dissector)` are the process-wide one. Entry points are not read. A
  registered dissector that raises costs that frame one layer, is counted
  `failed` and logged once per selector; the reader goes on.
  `check_dissector(dissector, samples)` runs the contract check the built-in
  dissectors pass. `DissectError` is the `ValueError` they raise.
- IP reassembly, for any protocol, is on by default and bounded: 256
  datagrams in flight, 65,535 octets and 1,024 fragments each, 30 seconds of
  capture time. A fragment costs a binary search whatever the order of
  arrival, and a fragment that overlaps another discards its datagram.
- `read_datagrams(source, *, dissector=None)` and `DissectedFrame.datagram()`
  give the UDP view, `CapturedDatagram(time, source, destination, payload,
  fragmented, truncated)`; a datagram cut by the snap length is marked
  `truncated`.
- `PcapWriter(target)` and `PcapngWriter(target)` write captures:
  `write_frame(frame)` writes a captured frame back with its link type, octet
  for octet, and `write(time, source, destination, payload)` writes a UDP
  datagram as raw IP under IPv4 or IPv6 and UDP headers with valid checksums.
  A pcap file holds one link type and refuses another; pcapng holds any mix.
  The file is opened by the first write, not by the constructor. A payload
  over 65,507 octets (IPv4) or 65,527 (IPv6), a frame over 262,144, a port
  outside 0-65535 and a time outside 0 to 2**32 raise `ValueError` and write
  nothing.
- `CaptureWriter(target, format=None, *, per_record=False, append=False,
  fields=(), max_files=1000)` writes datagrams or dissected frames as `pcap`
  or `pcapng`, or the records made of them as `json` (one line each), `yaml`
  (one document each), `toml` or `ini` (one file each), into one growing file
  or one file per record under a name pattern. `dumps_record(record, format)`
  writes one record as text; `datagram_record(datagram)` and
  `frame_record(frame)` are the default records; `OUTPUT_FORMATS`,
  `RECORD_FORMATS` and `has_output_format(name)` say what can be written.
  `yaml` and `toml` need the extras of those names and raise `ImportError`
  naming the extra without them. Every record format writes printable ASCII.
  A per-record writer creates at most `max_files` files and makes each field
  value safe for a file name.
- `parse_capture_filter(text)` and `compile_capture_filter(text, build)` read
  the `key=value and key!=value` filter expression into `FilterClause` named
  tuples and one predicate; `build` gives each key its meaning, once per
  clause, and its `ValueError` becomes a `CaptureFilterError` naming the
  clause. `frame_filter` is the `build` for dissected frames, with the keys
  of `FRAME_FILTER_KEYS`: `src`, `dst`, `host`, `sport`, `dport`, `port`,
  `proto`, `vlan`, `linktype`. `or` is refused by name.
- `replay_schedule(source, *, speed=1.0, max_delay=5.0, limit=None)` yields
  `(delay, item)` for a capture's datagrams or any iterable of datagrams or
  frames, and reads no clock; `replay(source, deliver)` sleeps each delay and
  calls `deliver`; `replay_to(source, dst, port, *, endpoint=None)` sends each
  UDP payload to the one destination named, through a `netimps` socket, and
  returns `ReplayResult(sent, partial)`. The addresses in the capture are
  never sent to, no raw frame is ever sent, the recorded timing is the
  default, each wait is capped at `max_delay`, and a `fragmented` or
  `truncated` datagram is counted and not sent.
- `CaptureWriter.write(item, record=None, *, text=None, names=None)` takes a
  record the caller rendered, for a record format: the writer keeps the
  container (the growing file with its separator, the name pattern, the file
  budget) and the octets are the caller's, written exactly as given. The
  directories above a growing file are made at its first write, as a
  per-record file's are.
- `LiveCapture(interface=None, *, timeout=1.0)` captures every packet on Linux
  through an `AF_PACKET` socket, which needs `CAP_NET_RAW`, as Linux cooked v2
  frames a writer can save for other tools; `sniff(interface=None, *,
  stop=None, dissector=None)` is its UDP datagram view; `has_live_capture()`
  says whether the platform has one, and `LiveCaptureError`, an `OSError`, is
  raised where it does not.

[Unreleased]: https://github.com/jose-pr/pktcap/commits/main
