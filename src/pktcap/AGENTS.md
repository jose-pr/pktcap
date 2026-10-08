# `pktcap` — public API header

Header-file-style reference for the `pktcap` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/pktcap>.

Everything is imported from `pktcap` directly. Every module under `pktcap`
(each name starts with `_`) is implementation detail: do not import them.

Install with `pip install pktcap`, which brings `netimps`. The `yaml` extra
(`pip install "pktcap[yaml]"`) adds `PyYAML` and the `toml` extra adds
`tomli-w`, each for the output format of that name, and the `cli` extra
(`pip install "pktcap[cli]"`) adds `duho` for the `pktcap` command. Importing
`pktcap` needs none of them. Python 3.9 or newer.

`pktcap.__version__` — the package version string, the same value the
installed distribution's metadata carries.

Topics with much detail keep it in a header beside their code, inside the
installed package (`importlib.resources.files("pktcap")`):

| Header | Covers |
| --- | --- |
| `pktcap/AGENTS.md` | this file: reading, dissecting, the datagram view, filtering, replaying, live capture, the exceptions |
| `pktcap/_dissectors/AGENTS.md` | the dissector contract, the registry, writing and checking a dissector, each built-in dissector and each layer record |
| `pktcap/_plugins/AGENTS.md` | layers and the filter keys a registry holds for them, how a filter reads a layer's fields, and loading plugins by name |
| `pktcap/cli/AGENTS.md` | the `pktcap` command: `capture`, `replay`, `convert` and `plugins`, every option, what each prints, its statuses |
| `pktcap/_streams/AGENTS.md` | `TCPReassembler`, `TCPStreamData`, `TCPStreamStats`: the rules for putting TCP streams back together, and the bounds |
| `pktcap/_formats/AGENTS.md` | `PcapWriter` and `PcapngWriter`, `CaptureWriter` in full, what a record is, and exactly what each record format writes |

**Any valid capture is read.** Every frame of a pcap or pcapng file comes
back whatever its link type and whatever it carries: a link type, an
ethertype or a protocol nothing here dissects is never an error and never
skipped, it is the frame's undissected payload. Only a damaged container
raises.

**A capture is untrusted input.** Every length, count and offset a file or a
frame states is compared with a ceiling before anything is allocated or looped
over; each section below gives its ceilings and what happens at them.

**Options are keyword-only.** A function takes the thing it acts on (and one
more operand where the signature shows it) positionally; the `*` in a
signature below marks where the keyword-only options begin. The named tuples
are positional by nature. Durations are seconds as `float`.

## Reading a capture

**`read_frames(source, *, max_frame_size=262144) -> Iterator[CapturedFrame]`**
— every packet of a pcap or pcapng capture, in file order, undissected.

- `source` (`CaptureSource`) is a path (`str` or `os.PathLike`) or a binary
  stream. The stream need not be seekable, so `sys.stdin.buffer` fed by
  `tcpdump -w -` or `dumpcap -w -` works. A stream stays the caller's to close.
- Both formats, either byte order, microsecond and nanosecond pcap, and in
  pcapng several sections and interfaces, the `if_tsresol` and `if_tsoffset`
  options, and the enhanced, simple and obsolete packet blocks.
- Arguments are checked at the call; nothing is read until the first frame is
  asked for. Frames are yielded as they are read: a damaged capture gives
  every frame before the damage and then raises.
- An empty input is an empty capture and yields nothing.
- Raises `CaptureFormatError` for anything that is not a capture or is a
  damaged one, `OSError` when the path cannot be opened or the stream read,
  `TypeError` for a text stream or a `source` that is neither, and
  `ValueError` for a `max_frame_size` that is not positive.

**`CapturedFrame(time, linktype, data, interface=None)`** — a named tuple: one
packet as the capture recorded it. `time` is seconds since the epoch as a
`float`, `linktype` the `LINKTYPE_` number saying what `data` starts with,
`data` the captured octets (a snap length may have cut them short),
`interface` the number of the pcapng interface it was captured on, counted
within its section, and `None` in a pcap file, which has none.

- **The file controls `time`.** It is `0.0` for a pcapng simple packet block,
  which has no timestamp, and may be far outside any calendar: guard a call to
  `datetime.fromtimestamp`. A nanosecond stamp loses precision below about
  0.2 µs in a `float`.

Ceilings, each checked before the octets it covers are read:

| What the file states | Ceiling | At the ceiling |
| --- | --- | --- |
| the length of a pcap record or of a packet in a pcapng block | `max_frame_size` (262,144, the most tcpdump and dumpcap record) | `CaptureFormatError` |
| the length of a pcapng packet block | `max_frame_size` + 65,536 | `CaptureFormatError` |
| the length of a pcapng section header or interface description | 1,048,576 | `CaptureFormatError` |
| the length of any other pcapng block | none: it is read 65,536 octets at a time and discarded | `CaptureFormatError` if the input ends inside it |
| interfaces described in one pcapng section | 4,096 | `CaptureFormatError` |

A pcapng block is also refused when its length is not a multiple of four or is
too small for its kind, when its two length fields disagree, when a packet is
longer than the block holding it, and when a packet names an interface its
section did not describe.

## Dissecting frames

A frame is dissected layer by layer. The frame's link type selects a
**dissector**; each dissector reads one layer and names what may follow it;
the walk ends when no dissector is registered for what follows. The built-in
dissectors read the link layer (Ethernet, 802.1Q and QinQ tags, Linux cooked
capture v1 and v2, BSD loopback, raw IP), IPv4 and IPv6 with their extension
and fragment headers, and UDP and TCP headers. Every other protocol is a
dissector someone registers: the contract, the registry and each built-in are
in `pktcap/_dissectors/AGENTS.md`.

**`read_dissected(source, *, dissector=None, max_frame_size=262144) -> Iterator[DissectedFrame]`**
— `read_frames` and `FrameDissector.dissect` in one call: every frame of a
capture, dissected, in capture order. It raises `CaptureFormatError` for a
damaged container and nothing for a frame. Pass a `FrameDissector` to choose
its registry and options and to read its `stats` afterwards.

**`FrameDissector(registry=None, *, reassemble=True, max_reassemblies=256, reassembly_timeout=30.0)`**
— dissects frames, keeping IP fragment state between them. Feed it every frame
of a capture, in order. Not safe to share between threads. `ValueError` for a
limit that is not positive.

- `registry` is a `DissectorRegistry`; `None` is `default_registry()`, the one
  `register_dissector` adds to. It is read at each frame, so a dissector
  registered later is used from then on. `FrameDissector.registry` is it.
- **`FrameDissector.dissect(frame) -> DissectedFrame`** — `frame` (a
  `CapturedFrame`) with every layer a registered dissector could read. **It
  never raises for a frame**, whatever the frame holds and whatever a
  registered dissector does.
- **`FrameDissector.stats`** — a `DissectStats` snapshot of the counters;
  `FrameDissector.unsupported_linktypes` says which link types it counted.
- **IP fragments are reassembled**, of any protocol; the frame that completes
  a datagram has `reassembled=True`, and `reassemble=False` keeps no state.
  An overlap discards the datagram. The rules are in
  `pktcap/_dissectors/AGENTS.md`.

**`DissectedFrame(frame, layers, payloads, error=None, reassembled=False)`** —
a named tuple: a captured frame and what was read from it.

- `frame` is the `CapturedFrame`; `DissectedFrame.time` is its time.
- `layers` is the layer records, outermost first: `EthernetLayer`,
  `VLANLayer`, `LinuxCookedLayer`, `LoopbackLayer`, `IPv4Layer`, `IPv6Layer`,
  `IPv6ExtensionLayer`, `IPv6FragmentLayer`, `UDPLayer`, `TCPLayer`, and
  whatever a registered dissector returned. Each built-in one is a named
  tuple of plain values.
- `payloads[i]` is the octets that follow `layers[i]`.
  **`DissectedFrame.payload`** is the last of them: what no dissector read.
  For a frame with no layer it is the whole frame.
- **`DissectedFrame.layer(kind) -> Optional[kind]`** — the outermost layer
  that is an instance of the class `kind`, or `None`:
  `frame.layer(TCPLayer)`.
- **`DissectedFrame.payload_of(kind) -> Optional[bytes]`** — the octets after
  that layer: `frame.payload_of(TCPLayer)` is the TCP segment's payload.
- **`DissectedFrame.datagram() -> Optional[CapturedDatagram]`** — the frame as
  a UDP datagram, or `None` when it carries no UDP over IP.
- `error` is `None`, or why dissection stopped early, as
  `"<kind> <number>: <reason>"` naming the selector whose dissector could not
  read its layer (`"ip 17: a UDP header is 8 octets"`). The layers before it
  are kept and its octets are the payload.

**`DissectStats(frames, malformed, failed, unsupported, fragments, dropped, pending)`**
— a named tuple of counts, one per `FrameDissector.stats`: frames given to
`dissect`, those a dissector could not read or broke on, and those of a link
type nothing dissects. Each counter is in `pktcap/_dissectors/AGENTS.md`.

**`LINKTYPES`** — a read-only mapping from the `LINKTYPE_` numbers with a
built-in dissector to a name (the list is in `pktcap/_dissectors/AGENTS.md`).
A frame of any other link type is read and returned undissected; register a
dissector under `("linktype", number)` to dissect it.

Registering a protocol is one call, `register_dissector("udp", 69, dissect)`
for the process or `DissectorRegistry.register` for one registry, with a
function `dissect(data: bytes) -> Dissected`. The names the other header
documents: `Dissector` and `Selector` (type aliases), `Dissected`, `Fragment`,
`DissectorRegistry`, `default_registry`, `register_dissector`,
`check_dissector`, `DissectError`.

Ceilings:

| What a frame or a capture states | Ceiling | At the ceiling |
| --- | --- | --- |
| dissectors run on one frame (a tag stack, a chain of extension headers) | 32 | the walk stops, the frame is `malformed`, the rest is its payload |
| datagrams being reassembled at once | `max_reassemblies` (256) | the oldest is discarded, `dropped` |
| octets in one reassembled datagram | 65,535 | the datagram is discarded, `dropped` |
| fragments of one datagram | 1,024 | the datagram is discarded, `dropped` |
| capture time between a datagram's first fragment and a later one | `reassembly_timeout` (30 s) | the datagram is discarded, `dropped`, and a new one starts |

A fragment costs a binary search and one insertion whatever the order of
arrival, and a full table holds at most about 250 KiB for each reassembly in
flight.

**TCP is read a segment at a time.** `TCPLayer` is the header and
`payload_of(TCPLayer)` the segment's octets. **`TCPReassembler`**, fed the
dissected frames of a capture in order, hands out **`TCPStreamData`**: each
direction's octets in order, with an offset, a count of octets given up on, a
connection number and an end marker; it counts what it met in
**`TCPStreamStats`**, and **`read_tcp_streams`** does both from a capture.
Everything a capture controls is bounded; the signatures, rules and bounds
are in `pktcap/_streams/AGENTS.md`.

## The UDP datagram view

What a UDP protocol library works on, built on the dissection above.

**`read_datagrams(source, *, dissector=None, max_frame_size=262144) -> Iterator[CapturedDatagram]`**
— `read_dissected` through `DissectedFrame.datagram`: every UDP datagram of a
capture, in capture order, IP fragments reassembled. Frames that carry no UDP
are not yielded; pass a `dissector` and read its `stats` to tell an empty
capture from one of a link type nothing dissects.

**`CapturedDatagram(time, source, destination, payload, fragmented=False, truncated=False)`**
— a named tuple: one UDP datagram from a capture.

- `source` and `destination` are `(host, port)` pairs, the host as address
  text: usable as a socket address, and as `netimps.SocketAddress`.
- `payload` is the octets after the UDP header, **whatever dissected them
  further**: a protocol's registered dissector does not change it.
- **An address on the wire is not rewritten.** A v4-mapped IPv6 address stays
  mapped, and is written `::ffff:10.0.0.5` on every Python (the standard
  library writes `::ffff:a00:5` before 3.13).
- `time` of a reassembled datagram is that of the fragment that completed it.
- `fragmented`: `payload` is only what the first IP fragment carried. Set
  only under a dissector built with `reassemble=False`.
- `truncated`: `payload` is shorter than the datagram's own length field says,
  because the capture's snap length cut the frame. **Check it before reading a
  short payload as a short message.**

## Writing a capture

**`PcapWriter(target)`** and **`PcapngWriter(target)`** write a capture that
tcpdump and Wireshark read, from frames or from datagrams; the whole contract
is in `pktcap/_formats/AGENTS.md`, with `CaptureWriter`.

## Writing in a named format

A capture format takes the frame or datagram itself; a record format takes a
**record**: plain data (`dict`, `list`, `str`, `int`, `float`, `bool`,
`None`) describing it.

**`OUTPUT_FORMATS`** — `("pcap", "pcapng", "json", "yaml", "toml", "ini")`,
and **`RECORD_FORMATS`** — the last four. `yaml` needs the `yaml` extra and
`toml` the `toml` extra; a format whose extra is missing stays in both tuples.

**`has_output_format(name) -> bool`** — whether that format can be written on
this installation. `UnsupportedFormatError` for a name that is no format.

**`dumps_record(record, format="json") -> str`** — one record as text, ending
in a newline. `MissingExtraError` when the format's extra is missing.

**`datagram_record(datagram) -> Dict[str, Any]`** and **`frame_record(frame) -> Dict[str, Any]`**
— the record of a `CapturedDatagram` and of a `DissectedFrame`; what each holds
is in `pktcap/_formats/AGENTS.md`, under "What a record is".

**`CaptureWriter`** — one writer for all six: a growing file, or one file per
record under a name pattern. It takes a `CapturedDatagram` or a
`DissectedFrame`; a capture format writes the item itself and a record format
the record given, or `datagram_record` or `frame_record` of the item. Its
signature, the name pattern, the file budget and every check are in
`pktcap/_formats/AGENTS.md`, with **`copy_frames`** and its result
`CopyResult`: a source of dissected frames, filtered, into one of these
writers.

## Filtering

Clauses `key=value` or `key!=value` joined by `and`:
`proto=tcp and host=10.0.0.0/8 and port!=22`. The grammar is shared; what a
key means is the builder's.

**`parse_capture_filter(text) -> Tuple[FilterClause, ...]`** — the clauses, in
order. `None`, empty or blank text is no clause.

**`compile_capture_filter(text, build) -> Callable[[T], bool]`** — one
predicate over the caller's own item type. `build(clause)` is called once per
clause, when the filter is compiled and never per item, and returns the test
for that clause; a `!=` clause is inverted for it; the predicate is true when
every clause holds. `None` or blank text matches everything.

- `build` raises `ValueError` for a key it does not know or a value that does
  not convert. It is re-raised as `CaptureFilterError` naming the clause, the
  original chained: one error at start-up, not one per packet. Any other
  exception propagates; a `build` that returns something not callable is a
  `TypeError`.

**`frame_filter(clause) -> Callable[[DissectedFrame], bool]`** — the `build`
for the built-in layers: `compile_capture_filter(text, frame_filter)` filters
dissected frames. A comma in a value means "any of". **`FRAME_FILTER_KEYS`**
is the keys, as a tuple, in this order:

| Key | Matches |
| --- | --- |
| `src`, `dst`, `host` | the source, the destination, or either address of the outermost IP layer: an address or a network (`10.0.0.5`, `10.0.0.0/8`, `2001:db8::/32`). A v4-mapped address is the IPv4 host it stands for |
| `sport`, `dport`, `port` | the source, the destination, or either port of the UDP or TCP layer |
| `proto` | a layer the frame has, by name (`udp`, `tcp`, `ipv4`, `ipv6`, `vlan`, `ethernet`; for a registered dissector's layer, its class name in lower case without a trailing `Layer`), or an IP protocol number (`17`) |
| `vlan` | a VLAN identifier on any tag of the frame |
| `linktype` | the capture's link-type number |
| `LAYER.FIELD` | a field of a layer, by the type of its value: `ipv4.ttl=64`, `udp.destination_port=9999`. `LAYER` is a built-in layer's name (`ethernet`, `vlan`, `linuxcooked`, `loopback`, `ipv4`, `ipv6`, `ipv6extension`, `ipv6fragment`, `udp`, `tcp`) or one a registry declares |

A frame without the layer a key asks about fails the clause, so its `!=` form
holds. A protocol library adds its own keys by wrapping: its `build` answers
the keys it knows and returns `frame_filter(clause)` for the rest.

A registry also holds **layers and the filter keys over them**:
`DissectorRegistry.register_layer` declares a layer's class and its keys,
`frame_filter_for(registry)` is the `build` that knows them (`frame_filter`
itself reads no registry) and `frame_filter_keys(registry=None)` lists every
key that compiles. The rule, the bounds and what is refused are in
`pktcap/_plugins/AGENTS.md`.

**`FilterClause(key, value, negated=False)`** — a named tuple. `key` is as
written (case kept), `value` the text after the operator with surrounding
space removed, `negated` whether the operator was `!=`.
`FilterClause.values` is `value` split on commas, each item stripped and
empty ones dropped. `str(clause)` is the canonical text, and parsing the
clauses' texts joined by ` and ` gives the same clauses back.

The dialect: `and` joins clauses in any letter case and needs space on both
sides. **There is no `or`**: the word alone is refused by name, so a value
cannot contain ` or ` or ` and `. A key is one or more of
`A-Z a-z 0-9 _ . -`; the first `=` ends it and a `!` just before that `=`
negates; everything after is the value and must not be blank, so a value may
contain `=`. An expression is at most 4,096 characters. Each violation raises
`CaptureFilterError`; text that is not `str` or `None` is a `TypeError`.

## Replaying a capture

What a capture holds again, in order and in time. Three functions over one
schedule; the options `speed`, `max_delay` and `limit` mean the same in each.

`source` (`ReplaySource`) is a path or binary stream of a pcap or pcapng
capture, read as its UDP datagrams, **or any iterable of items with a `time`
in seconds**: `CapturedDatagram`, `CapturedFrame` or `DissectedFrame`, so
`read_dissected(path)` replays every frame, and a generator expression
chooses which. The waits are the gaps between the items given.

**`replay_schedule(source, *, speed=1.0, max_delay=5.0, limit=None) -> Iterator[Tuple[float, item]]`**
— `(delay, item)` for each item. `delay` is the seconds to wait before it: the
time since the one before it, divided by `speed`. **It reads no clock and
waits for nothing**, so an event loop drives it with its own sleep.

**`replay(source, deliver, *, speed=1.0, max_delay=5.0, limit=None) -> int`**
— blocks: sleeps each delay, calls `deliver(item)`, and returns how many were
delivered. An exception from `deliver` ends the replay and propagates. This is
the replay for **anything that is not UDP**: what to do with a TCP segment or
an ARP frame is the callable's.

**`replay_to(source, dst, port, *, endpoint=None, speed=1.0, max_delay=5.0, limit=None) -> ReplayResult`**
— blocks: sends the payload of each UDP datagram to `(dst, port)`.

- **The destination is always the caller's.** The addresses recorded in the
  capture are never sent to. `dst` is `netimps.HostLike`; a name is looked up
  once. `port` is 1 to 65535.
- **Only datagrams are sent, as UDP payloads through an ordinary socket.** An
  item that is not a `CapturedDatagram` is a `TypeError`. This library never
  writes a raw frame to a network.
- **A datagram marked `fragmented` or `truncated` is not sent**: it is counted
  in `ReplayResult.partial`.
- By default a UDP socket is made with `netimps.bind()` for `dst`'s address
  family (any free port, broadcast off) and closed on return. Pass a
  `netimps.UDPEndpoint` as `endpoint` to choose the source port or interface
  or to allow broadcast; it is left open.
- `OSError` when `dst` does not resolve (`netimps.ResolutionError`) or a send
  fails, a payload too long for the family included.

**`ReplayResult(sent, partial)`** — a named tuple: datagrams sent, and partial
datagrams passed over.

| Option | Meaning |
| --- | --- |
| `speed` | `1.0` keeps the recorded timing and is the default, so a replay sends no faster than the capture did; `2.0` halves every wait; **`None` removes them** and has to be asked for |
| `max_delay` | the longest single wait, in seconds. A capture controls its timestamps, and a jump of a year must not hang a replay. A step backwards in time, or a time that is not a number, is a wait of zero |
| `limit` | stop after this many items; the source is not read past it |

`ValueError` for a `speed` that is not positive and finite, a `max_delay` or
`limit` below zero, a `port` outside 1-65535 or an empty `dst`; `TypeError`
for an option of the wrong type, a `deliver` that is not callable or an item
with no `time`.

## Capturing live

**Linux only**, through an `AF_PACKET` socket, and the process needs the
`CAP_NET_RAW` capability (root, or `setcap cap_net_raw+ep` on the
interpreter). Everywhere else, and wherever a capture tool is preferred, pipe
one in: `tcpdump -i eth0 -U -w - | your-program` and
`read_dissected(sys.stdin.buffer)`. Capturing never sends anything.

**`has_live_capture() -> bool`** — whether this platform has `AF_PACKET`. It
says nothing about permission.

**`LiveCapture(interface=None, *, timeout=1.0)`** — every packet on one
interface, or on all of them when `interface` is `None`. A context manager;
constructing one opens nothing.

- `interface` is `netimps.InterfaceLike`: a name, a `netimps.Interface`, or
  anything `netimps.get_interface` finds one by (an address, a MAC).
- **`LiveCapture.open() -> None`** — open the socket; `with` does it. Does
  nothing when already open. `LiveCaptureError` where the platform has no
  `AF_PACKET` (before any interface is looked up), the kernel's `PermissionError` without the capability,
  `ValueError` when no interface matches.
- **`LiveCapture.read() -> Optional[CapturedFrame]`** — the next packet, IP or
  not, or `None` when `timeout` seconds pass without one. A frame has link
  type 276 (Linux cooked capture v2, what tcpdump writes for its `any`
  device), the time it was read and the interface's index: ready for a
  `FrameDissector`, and for a writer, whose file other tools then read.
- Iterating a capture yields frames until it is closed.
- **`LiveCapture.fileno() -> int`** — the socket's descriptor, for a caller's
  own selector or event loop. There is no asynchronous twin.
- **`LiveCapture.close() -> None`** — final, complete on return, harmless
  twice.
- On a loopback device every packet is seen leaving and arriving; only the
  arriving copy is returned. Loopback is told by the device type the kernel
  reports, not by the name `lo`.

**`sniff_frames(interface=None, *, stop=None, dissector=None) -> Iterator[DissectedFrame]`**
— `LiveCapture` and a `FrameDissector` in one call, what `read_dissected` is
for a file: every frame as it arrives, dissected, whatever it carries. The
socket is opened when the first frame is asked for (which is when
`LiveCaptureError` or `PermissionError` is raised) and closed when the
iterator ends or is closed. `stop()` is called between packets, and at least
once a second on a quiet interface; returning true ends the iteration.
`TypeError` at the call for a `stop` that is not callable or a `dissector`
that is not a `FrameDissector`.

**`sniff(interface=None, *, stop=None, dissector=None) -> Iterator[CapturedDatagram]`**
— `sniff_frames` through the datagram view: UDP datagrams as they arrive, the
rest passed over. The same opening, closing, `stop` and errors.

## Plugins

**`load_plugins(registry, plugins=None, *, config=None) -> Tuple[LoadedPlugin, ...]`**
imports the modules a list names and calls each one's hook,
`pktcap_plugin(registry)`, into `registry`. The list is the first of the
argument, `PKTCAP_PLUGINS` and the user's configuration file that names one,
read from those places alone, never from the working directory or a capture.
`capture_config_path(config=None)` is the file that applies. A plugin that fails
is a `CapturePluginError` and leaves the registry as it was. More:
`pktcap/_plugins/AGENTS.md`.

## Command line

`pip install "pktcap[cli]"` installs the `pktcap` command (also
`python -m pktcap`) with `capture`, `replay`, `convert` and `plugins`, each a
call into this API (`sniff_frames`, `replay_to`, `copy_frames`, `load_plugins`).
`pktcap.cli` is not library API and is in no export. `PKTCAP_MCP=stdio` serves
`convert` and `plugins` as tools. Every option and status: `pktcap/cli/AGENTS.md`.

## Exceptions

Every exception pktcap raises on its own account descends from
**`PktcapError(Exception)`**, and each one also inherits the builtin a caller
would already catch. A caller's own mistake (a bad option, a wrong argument
type) is a plain `ValueError` or `TypeError`, never a `PktcapError`.

| Class | Bases | Raised for |
| --- | --- | --- |
| `PktcapError` | `Exception` | the base; catch it for "anything pktcap reported" |
| `CaptureFormatError` | `PktcapError`, `ValueError` | input that is not a pcap or pcapng capture, or is a damaged one |
| `CaptureFilterError` | `PktcapError`, `ValueError` | a capture-filter expression that cannot be parsed or compiled |
| `UnsupportedFormatError` | `PktcapError`, `ValueError` | an output format that does not exist, or that a file name does not tell |
| `MissingExtraError` | `PktcapError`, `ImportError` | a format that exists and whose extra is not installed |
| `DissectError` | `PktcapError`, `ValueError` | raised **by a dissector** for octets that are not its layer. A caller of `FrameDissector` never sees it: it becomes the frame's `error` |
| `LiveCaptureError` | `PktcapError`, `OSError` | a platform with no `AF_PACKET`, asked to capture live |
| `CapturePluginError` | `PktcapError`, `ValueError` | a plugin the user named that cannot be loaded: `plugin` and `source` say which, and from where |
| `CaptureConfigError` | `PktcapError`, `ValueError` | a configuration file, or `PKTCAP_CONFIG`, that is malformed or not trusted: `path` and `lineno` |

`MissingExtraError(message, *, format, extra)` has `format` (the format's name,
`"toml"`) and `extra` (the extra to install, `"toml"`), and its message names
the extra: a caller that offers the format under its own extra words its own.
A process that may not open a packet socket gets the kernel's
`PermissionError`. `OSError` from opening, reading or writing a file or a
socket is let through as it is.

`CaptureFormatError.offset` is how many octets of the input had been read when
the problem was found, or `None`; the message ends with it and never quotes the
file.

## Environment variables

Read when a list of plugins is asked for, never at import.

- `PKTCAP_PLUGINS` — the plugins to load; `,` `;` `:` or space between items, `none` for none.
- `PKTCAP_CONFIG` — the configuration file: an absolute path, or `none`; read as it is.
- `XDG_CONFIG_HOME` (POSIX), `APPDATA` (Windows) — where `pktcap/pktcap.ini` is looked for.

## Gotchas

- **The readers and `replay_schedule` return iterators.** Arguments are
  checked at the call; the file is opened and a damaged capture raises only
  while iterating. Wrap the loop, not the call.
- **Zero datagrams is not "no traffic" until the counters agree.** Pass a
  `FrameDissector` and read `stats`: `unsupported` equal to `frames` is a
  link type nothing dissects, `malformed` a capture cut too short.
- **`register_dissector` changes the process.** Every `FrameDissector` built
  without a registry sees it. A library that must not affect its host builds
  its own `DissectorRegistry` and passes it.
- **Installing a package registers nothing.** Entry points are not read: a
  dissector is in a registry because some code put it there, or because a
  plugin the user named (`load_plugins`) did.
- **A `CapturedDatagram` is not `netimps.Datagram`.** One is read from a
  capture (time, both addresses, payload); the other is received on a socket.
- **A writer replaces an existing file at the first write**, not when it is
  built. `CaptureWriter(append=True)` adds to a record file.
- **Nothing here is safe to share between threads.** A frame dissector, a
  writer and a live capture each keep state.
- **This library configures no logging, installs no signal handler and
  prints nothing.** It logs at `WARNING` on `pktcap._dissect` (a dissector
  that failed) and `pktcap._output` (the file budget reached).
