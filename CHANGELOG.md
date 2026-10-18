# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `PcapWriter.write_tcp()` and `PcapngWriter.write_tcp()` append one TCP
  segment under synthesised IPv4/IPv6 and TCP headers with valid checksums.
- `TCPFlowWriter` writes a whole TCP connection (handshake, data split at an
  `mss`, FIN or RST) from the octets of each direction, keeping the sequence
  numbers, so a reader that reassembles TCP gets exactly those octets back.

## [0.1.1] - 2026-10-14

### Changed

- **The `cli` extra requires `duho>=0.7.4,<0.8`.** With it every error of the settings
  file is one line, `pktcap: error: ...`, status 2: a key or table nobody has no longer
  prints the usage lines before that line. A `config` key in the file is refused by
  duho's own check, in its words (`duho: config file <file>: unknown key 'config'`).
- On Windows a relative `APPDATA` is ignored when the default settings file is
  looked for, as a relative `XDG_CONFIG_HOME` already was elsewhere.

## [0.1.0] - 2026-10-12

### Added

Python 3.9 or newer; `netimps>=0.4.1,<0.5` is the one dependency. Optional
extras: `yaml` (`PyYAML>=6.0,<7`), `toml` (`tomli-w>=1.0,<2`, and
`tomli>=2.0,<3` before Python 3.11) and `cli` (`duho>=0.7.3,<0.8`). `import
pktcap` imports none of them, reads no variable and imports no plugin.

**The package**

- The package, with one exception base, `PktcapError`, and `__version__`.
- `MissingExtraError`, an `ImportError` and a `PktcapError`, is what a format
  whose optional dependency is not installed raises. `format` is the format's
  name and `extra` the pktcap extra that installs what it needs (`"toml"`), so
  a library that offers the format under its own extra words its own message
  without reading this one.

**Reading captures**

- `read_frames(source, *, max_frame_size=262144)` reads every frame of a pcap
  or pcapng capture, from a path or from a stream that cannot seek, as
  `CapturedFrame(time, linktype, data, interface=None)` named tuples, whatever
  the link type. Every length the file states is checked against a ceiling
  before it is read: a 48-octet file whose record claims 1 GiB raises
  `CaptureFormatError` having allocated under 1 MiB. Any damaged capture
  raises `CaptureFormatError`, a `ValueError`, with the octet offset.

**Dissecting frames**

- `FrameDissector(registry=None, *, reassemble=True, max_reassemblies=256,
  reassembly_timeout=30.0)` and `read_dissected(source, *, dissector=None)`
  dissect frames layer by layer into `DissectedFrame` named tuples: the layer
  records in order, the octets after each, and what no dissector read. A
  frame is never raised for: a layer cut short is counted `malformed` and
  named in `DissectedFrame.error`, a link type with no dissector is counted
  `unsupported` and returned whole, and at most 32 dissectors run on one
  frame (`DissectStats`).
- `FrameDissector.unsupported_linktypes` is a read-only snapshot mapping each
  link type that had no dissector to the number of frames of it (`{105: 3}`),
  so a caller can say which link type a capture it could not read was made
  on. The first 64 distinct link types are told apart;
  `DissectStats.unsupported` counts every frame.
- Built-in dissectors for Ethernet, 802.1Q and 802.1ad tags, Linux cooked
  capture v1 and v2, BSD loopback, raw IP, IPv4, IPv6 with its hop-by-hop,
  routing, destination and fragment headers, UDP and TCP, each making a named
  tuple: `EthernetLayer`, `VLANLayer`, `LinuxCookedLayer`, `LoopbackLayer`,
  `IPv4Layer`, `IPv6Layer`, `IPv6ExtensionLayer`, `IPv6FragmentLayer`,
  `UDPLayer`, `TCPLayer`. TCP is read a segment at a time and no checksum is
  verified. An IPv6 address keeps its text (the 1,024 a process used last),
  since a capture names few hosts and every frame names two.
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
- A layer may say how it reads: a layer record may have a method `summary()`
  returning one line saying what it holds. Every built-in layer has one, and
  a registered layer without one is described by its name.
  `frame_summary(frame)` is a frame's time (UTC), its two socket addresses
  when it has them, the name of its innermost layer and that layer's summary.
  The line is escaped to printable ASCII, cut at 512 characters, and a
  `summary()` that raises or gives no text is logged once for its class and
  never stops anything.

**Filtering**

- `parse_capture_filter(text)` and `compile_capture_filter(text, build)` read
  the `key=value and key!=value` filter expression into `FilterClause` named
  tuples and one predicate; `build` gives each key its meaning, once per
  clause, and its `ValueError` becomes a `CaptureFilterError` naming the
  clause. `frame_filter` is the `build` for dissected frames, with the keys
  of `FRAME_FILTER_KEYS`: `src`, `dst`, `host`, `sport`, `dport`, `port`,
  `proto`, `vlan`, `linktype`. `or` is refused by name.
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

**TCP stream reassembly**

- `TCPReassembler(*, max_streams=1024, max_buffered=16777216,
  idle_timeout=300.0)` puts TCP streams back together from dissected frames:
  `add(frame)` returns the `TCPStreamData` the frame made deliverable, each
  direction's octets in order with an `offset`, the octets given up on before
  them (`missing`), a connection number (`stream`) and an `end` marker;
  `flush()` gives what is still held at the end of a capture; `stats` is a
  `TCPStreamStats` of twelve counters. A reader of a capture is passive, so
  each choice it has to make is a stated rule:
  - Sequence numbers wrap and offsets do not; octets already delivered are
    final; of two copies not yet delivered the first captured wins.
  - A hole is waited for. It is given up, and what was held is delivered with
    the count of octets missing, when the other side acknowledges past it,
    when a bound is reached, or when the direction, the connection or the
    capture ends. An acknowledgment beyond everything seen from the sender
    changes nothing.
  - A FIN ends a direction and an in-sequence reset ends the connection. A
    SYN on a live connection that is not the connection's own is set aside
    until a segment confirms it, so one forged SYN ends nothing; on a
    connection that has ended it starts a new stream at once. A SYN-ACK may
    acknowledge the octets a TCP Fast Open SYN carried.
  - A segment, FIN or reset more than 16,777,216 octets beyond the furthest
    octet believed from its sender is set aside until the sender's next
    segment follows on from it, so one forged or corrupted sequence number
    moves nothing.
  - A segment is as long as its IP header says: the octets a snap length cut
    are given up at once and reported in `missing`.
  - Not done: the checksum is not verified, a segment in an IP fragment that
    was not reassembled is ignored, VLAN and interface do not tell
    connections apart, and no dissector is given a stream.

  Everything a capture controls is bounded: connections (`max_streams`),
  capture time of silence (`idle_timeout`), octets held out of order over all
  connections (`max_buffered`, each held piece charged its length plus 64) and
  pieces held in one direction (1,024, a piece being a run of held octets).
  Reaching the last two gives up the longest wait and drops nothing; a
  forgotten connection drops what it held, counted in `dropped`.
- `read_tcp_streams(source, *, reassembler=None, dissector=None,
  max_frame_size=262144)` reads the TCP streams of a capture in one call:
  `read_dissected` through `TCPReassembler.add`, then `flush()` at the end.

**Writing, and the record formats**

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
  (one document each), `toml` or `ini` (one file each), or as `text`, into one
  growing file or one file per record under a name pattern.
  `write(item, record=None, *, names=None)` takes the record, or renders it
  itself, so the octets of a record are one library's, and makes the
  directories above a growing file at its first write, as it does for a
  per-record file. `append=True` adds to a record file; with `per_record` it
  raises `ValueError`.
- `dumps_record(record, format)` writes one record as text;
  `datagram_record(datagram)` and `frame_record(frame)` are the default
  records; `OUTPUT_FORMATS`, `RECORD_FORMATS` and `has_output_format(name)`
  say what can be written. `yaml` and `toml` need the extras of those names
  and raise `MissingExtraError` naming the extra without them. Every record
  format writes printable ASCII.
- `"text"` is in `OUTPUT_FORMATS` (endings `.txt` and `.log`): `CaptureWriter`
  writes a frame's `frame_summary`, or a line for a datagram, many lines to a
  file or one file a line with `per_record`. It is not a record format, so
  `RECORD_FORMATS` does not hold it and `dumps_record` and `loads_record`
  refuse it, as they refuse `pcap`.
- A per-record writer creates at most `max_files` files and makes each field
  value safe for a file name. A value longer than 64 characters is cut to 55
  and ends in `-` and 8 hexadecimal digits of the SHA-256 of the whole value,
  so two long values that start alike name two files. A value cannot make a
  directory of a per-record path (`{client}/{index}.json`) a name Windows opens
  as a device: the part gets a leading `_` on every platform, as the file's
  own name does. A part the pattern spells out is kept as written.
- `copy_frames(frames, writer, *, select=None, datagrams=False, limit=None,
  names=None, each=None)` writes the frames a predicate accepts into a
  `CaptureWriter` the caller owns, optionally as the UDP datagram of each,
  and stops reading at `limit`; it returns `CopyResult(read, written,
  skipped, refused)`. `names` is called for each frame kept to give the writer
  the values of its `fields`, and `each` with the frame after its item is
  written, not for a frame that was dropped, had no datagram or was turned
  away by the file budget.
- `datagram_frame(datagram, *, interface=None, ident=0)` builds the raw-IP
  frame of a `CapturedDatagram`, the octets `PcapWriter` writes for it, so
  that dissecting it gives the datagram back for a whole datagram; a payload
  that is not bytes-like is a `TypeError`.

**Reading a record back**

- `loads_record(text, format="json")` reads one record back from the text
  `dumps_record` writes, in the same four formats, as its inverse: for every
  record `dumps_record` takes, `loads_record(dumps_record(r, f), f) == r`,
  with the exceptions the formats force, which the header lists (a key that
  was not text comes back as text in JSON and INI, a lone surrogate in a value
  is U+FFFD in TOML, and a few more). A name a format could not write so that
  it reads back is refused with a `ValueError` that quotes nothing of the
  record: a lone surrogate in a TOML key, a lone surrogate or an empty name in
  an INI section or option name. Text that is not one record raises
  `RecordFormatError(message, *, format, lineno=None)`, a `PktcapError` and a
  `ValueError`, whose message never quotes the text and which chains nothing.
- The text is untrusted: a key written twice, `NaN` and the infinities in
  JSON, a YAML tag that is not plain, a YAML merge key, a YAML alias, a date
  in TOML or YAML, and nesting past the recursion limit are refused. The YAML
  writer writes no anchor and no alias: an object a record holds twice is
  written twice. In INI a value that is not JSON is its text, so a file
  written by hand reads. YAML needs the `yaml` extra; TOML is read with
  `tomllib` from Python 3.11 and needs `tomli` before it, which the `toml`
  extra installs there.

**Replay**

- `replay_schedule(source, *, speed=1.0, max_delay=5.0, limit=None)` yields
  `(delay, item)` for a capture's datagrams or any iterable of datagrams or
  frames, and reads no clock; `replay(source, deliver)` sleeps each delay and
  calls `deliver`; `replay_to(source, dst, port, *, endpoint=None)` sends each
  UDP payload to the one destination named, through a `netimps` socket, and
  returns `ReplayResult(sent, partial)`. The addresses in the capture are
  never sent to, no raw frame is ever sent, the recorded timing is the
  default, each wait is capped at `max_delay`, and a `fragmented` or
  `truncated` datagram is counted and not sent.

**Live capture, and the UDP socket source**

- `LiveCapture(interface=None, *, timeout=1.0)` captures every packet on Linux
  through an `AF_PACKET` socket, which needs `CAP_NET_RAW`, as Linux cooked v2
  frames a writer can save for other tools; `sniff_frames(interface=None, *,
  stop=None, dissector=None)` yields every frame seen live, dissected, as
  `read_dissected` does for a file; `sniff(interface=None, *, stop=None,
  dissector=None)` is its UDP datagram view; `has_live_capture()` says
  whether the platform has one, and `LiveCaptureError`, an `OSError`, is
  raised where it does not.
- A UDP socket is a capture source, on every platform and with no privilege.
  `UDPCapture(endpoints, *, timeout=1.0, max_size=65535)` reads datagrams
  from bound `netimps.UDPEndpoint` objects (at most 256; a repeated endpoint
  is a `ValueError`) and returns each as a raw-IP frame (link type 101) with
  the arrival interface when the host reports one; a datagram over `max_size`
  is counted in `truncated` and not returned, and one an endpoint does not
  admit (`UDPEndpoint.admits`) is counted in `not_admitted` and gives no
  frame. `sniff_udp(endpoints, *, stop=None, dissector=None)` yields them
  dissected, with the registered dissector of the port applied, and closes the
  sockets when it ends, fails, is closed or is dropped. `asniff_udp(endpoints,
  *, dissector=None)` is its asynchronous twin on `UDPEndpoint.arecv`, with
  `UDPCapture.aread()` and `aclose()`; every task is cancelled and every
  socket closed when it stops, and `import pktcap` imports no `asyncio`.
  The IP header of such a frame is made up, and a socket never sees other
  hosts' traffic, the link layer or fragments.

**Hooks**

- `command_hook(command, *, format="json", timeout=10.0, fail_fast=False,
  names=None, datagrams=False)` is a hook for a copy that runs a program for
  each frame written: the record of the frame on standard input, the values
  `names(frame)` gives as `PKTCAP_HOOK_<FIELD>` variables (each passing the
  file-name rule of `CaptureWriter`), no argument and no shell. The program is
  found once, as an absolute path (a bare name in the directories `PATH`
  lists and nowhere else), and a `.bat` or `.cmd` file is refused on Windows.
  The run is the program's own exit: a process it leaves holding its streams
  delays nothing. Past `timeout` the program and everything it started are
  killed (a job object on Windows, started suspended and resumed through
  documented calls; the process group on POSIX). A program that cannot be
  started is a failure like a non-zero exit. A failure is counted in the
  callable's `failures`, logged on `pktcap._copy._hook` with a bounded,
  escaped tail of the error output (the first, then at most one a minute), and
  with `fail_fast` raises `CaptureHookError(message, *, status=None,
  timed_out=False)`, a `PktcapError` and an `OSError`.

**Plugins**

- `load_plugins(registry, plugins=None, *, always=())` imports the modules a
  list names and calls each one's hook, `pktcap_plugin(registry)` (or any
  `MODULE.CALLABLE` taking the registry), so a protocol library's dissector and
  filter keys are registered with no code of the user's. The list is the one
  it is given: the library reads no variable and no configuration file, and a
  program passes a list only from a place it trusts. `LoadedPlugin` is one
  result. A plugin that cannot be loaded raises `CapturePluginError` and leaves
  the registry as it was.
- `always` loads the plugins a caller's own code names before the user's list,
  with the source `"always"`. They are never read from `PKTCAP_LOAD` or the
  configuration file, which still decide the user's list. An item of the
  user's list that is the same hook is skipped; a different hook claiming a
  selector that is taken is still a `CapturePluginError`, and a failure
  anywhere leaves the registry as it was.

**The command line and its settings file**

- The `pktcap` command, also `python -m pktcap`, behind the `cli` extra
  (`pip install "pktcap[cli]"`, which brings `duho`). Without the extra the
  command prints the one line naming it and exits 1. `import pktcap` imports
  neither `duho` nor the command package, `pktcap.cli`, which is not library
  API. Exit status: 0 done, 1 the operation failed, 2 the invocation was
  wrong. A command whose standard output the reader closed ends with status 1
  and no line on standard error, on Windows as elsewhere; an `EINVAL` of a
  file or a socket stays an error with its line.
- `pktcap convert --input FILE|- [--output TARGET] [--format FMT] [--filter
  EXPR] [--datagrams] [--per-record] [--append] [--max-files N] [--limit N]`
  copies a pcap or pcapng capture into pcap, pcapng, records (json, yaml,
  toml, ini) or text, through `copy_frames`. Standard output is the default
  target and may be the capture; the summary is on standard error. An output
  file ending in `.txt` or `.log` is text. `--format toml` or `ini` without
  `--per-record` is status 2 with a line that names `--per-record`;
  `--append` with `--per-record` is status 2.
- `pktcap replay --input FILE|- --to HOST:PORT [--filter EXPR] [--speed X |
  --no-delay] [--max-delay SECONDS] [--limit N] [--source-port N]
  [--broadcast] [--json]` sends the UDP payloads of a capture, in order and in
  time, through `replay_to`. `--to` is the only destination there is: the
  addresses in the file are never sent to. The result is the one line
  `sent 12, partial 0`, or an object with `--json`.
- `pktcap capture [--interface NAME | --listen SPEC...] [--filter EXPR]
  [--output TARGET] [--format FMT] [--datagrams] [--per-record] [--append]
  [--max-files N] [--count N] [--duration SECONDS] [--hook COMMAND]
  [--hook-fail-fast] [--hook-timeout SECONDS]` captures live through
  `sniff_frames` and `copy_frames` (Linux, `CAP_NET_RAW`). Ctrl-C ends it with
  status 0 and the summary; off Linux the one line says to pipe a capture tool
  into `pktcap convert`. `--listen SPEC` (repeatable, excludes `--interface`)
  captures the datagrams that arrive at UDP ports, on every platform and with
  no privilege; `SPEC` is the grammar of `netimps.parse_listen`, bound with
  `netimps.bind_listen`. `--hook` runs a program (or a Python
  `MODULE:FUNCTION`) for each record written, as `command_hook` does; a hook
  is given the format the writer writes (the ending of `--output` when it
  decides), and the sockets a command bound are closed when the source refuses
  them. `--count` has no short form.
- Every command takes `--load NAME` (repeatable; `none` for none), loading
  into a registry of its own before the filter is compiled, so `pktcap capture
  -f "proto=dhcp"` and a library's own keys work with no code written. The
  plugin list of a command is the field `load` (`--load`, `PKTCAP_LOAD`, the
  key `load`); a variable that is only white space is a list with no plugin,
  and only an empty one is unset. `pktcap plugins [--layer NAME] [--json]`
  shows the settings file the root read, what was loaded and every filter key.
  A hook and a plugin list come from the command line, not from a settings
  file or a variable a library's root applies to every field: such a value is
  status 2 naming the layer.
- The root takes `--config`/`-c FILE` before the command's name, else
  `PKTCAP_CONFIG`, else the user's own `pktcap/pktcap.ini`. The file is duho's
  layout (top-level keys for the root, a table for each command), in INI,
  TOML, JSON or YAML by its name, and a `[convert]` table sets the options of
  `convert`. A top-level `load` is the list of every command. The argument
  wins over the variable, the variable over the file. An empty path
  (`--config ""`, `PKTCAP_CONFIG=`) means no file, the user's own included. An
  unknown key or table (duho's usage error, which names the key and never
  holds a value), a `config` key, a `[pktcap]` table and a file that is not
  valid are status 2 with one line that holds no text of the file. The default
  file is checked where owners are: on POSIX it must be the user's or root's
  and not writable by everyone. A relative `APPDATA` is taken as it is on
  Windows. The `cli` extra needs duho 0.7.3, which publishes `running_mode()`:
  a command tells a tool call by it.

**The command classes as a base**

- The command classes are the base of a protocol library's commands.
  `pktcap.cli` exports `main`, `Loading`, `Selecting`, `Writing`, `Capture`,
  `Convert`, `Replay` and `Plugins`, bound on first use so that importing it
  still needs no `duho`. A subclass sets `_plugins_`, `_filter_`, `_fields_`,
  `_format_`, `_interruptible_`, `_default_port_`, `_listen_` and
  `_env_prefix_`, and overrides `_select`, `_frames`, `_names`, `_limit`,
  `_hook`, `_report`, `_endpoints`, `_stop`, `_datagrams` and `_replay`; the
  loop that `convert` and `capture` share is `Writing.__call__`.
- `Capture._endpoints(self, dissector)` is given the dissector the frames are
  read with, so a protocol is registered on the port that was bound without
  keeping the dissector in an attribute. `Capture._listen_` (default `None`:
  every interface) is what the command listens on when neither `--listen` nor
  `--interface` is given. `Capture._stop` is asked whatever the options are.
  `Capture._hook_from_` (default `("argument",)`) lists the layers a subclass
  takes a hook from, of `"argument"`, `"environment"` and `"file"`;
  `Loading._load_from_` names the layers a class takes the plugin list from,
  and the plugin list never comes from a root's layers beyond them.
- `Loading._env_prefix_` (default `None`) gives every option of a class that
  names no variable, inherited ones among them, the variable made of the
  prefix and its field name in upper case (`MYPROG_CAPTURE_FORMAT`); the
  logging options and `--load`, which keeps `PKTCAP_LOAD`, are not renamed,
  and `Meta(env="")` keeps an option without a variable.
- No command has a configuration option, so a library that subclasses the
  commands names its settings file on its own root and meets no clash. Every
  private member of the command classes that is not an override point begins
  `_pk_`, and a subclass defines and uses none.

**Tools served over MCP**

- `PKTCAP_MCP=stdio pktcap` serves `convert` as a tool (`pktcap.convert`) and `plugins` as `pktcap.plugins`: the records come
  back as the tool's result. A call asking for `pcap` or `pcapng` on standard
  output has its octets written to the server's output target (file descriptor
  3, or what `PKTCAP_MCP_OUTPUT` names: a descriptor number, a file or a pipe)
  and the result says how many bytes went where; with no target the call fails
  with duho's message. `capture` and `replay` are not served: one runs until
  stopped and needs a privilege, the other puts datagrams on a network.
- A tool call that names `load` or `append` is refused, and the server's own
  `PKTCAP_LOAD` decides the plugins. The settings file a served tree reads is
  the server's own default file, checked as any default is; neither
  `PKTCAP_CONFIG` nor a `config` a call names is read.

[Unreleased]: https://github.com/jose-pr/pktcap/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jose-pr/pktcap/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jose-pr/pktcap/releases/tag/v0.1.0
