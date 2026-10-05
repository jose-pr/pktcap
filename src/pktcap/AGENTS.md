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
`tomli-w`, each for the output format of that name. Importing `pktcap` needs
neither. Python 3.9 or newer.

`pktcap.__version__` — the package version string, the same value the
installed distribution's metadata carries.

One topic keeps its detail in a header beside its code, also inside the
installed package (`importlib.resources.files("pktcap")`):

| Header | Covers |
| --- | --- |
| `pktcap/AGENTS.md` | this file: reading, decoding, writing, replaying, live capture, the filter expression, the exceptions |
| `pktcap/_formats/AGENTS.md` | what a record is, and exactly what each record format writes |

**A capture is untrusted input.** Every length, count and offset a file or a
frame states is compared with a ceiling before anything is allocated or looped
over; each section below gives its ceilings and what happens at them.

**Options are keyword-only.** A function takes the thing it acts on (and one
more operand where the signature shows it) positionally; the `*` in a
signature below marks where the keyword-only options begin. The named tuples
are positional by nature. Durations are seconds as `float`.

## Reading a capture

**`read_frames(source, *, max_frame_size=262144) -> Iterator[CapturedFrame]`**
— every packet of a pcap or pcapng capture, in file order.

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

**`CapturedFrame(time, linktype, data)`** — a named tuple: one packet as the
capture recorded it. `time` is seconds since the epoch as a `float`,
`linktype` the `LINKTYPE_` number saying what `data` starts with, `data` the
captured octets (a snap length may have cut them short).

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

## Decoding frames to UDP datagrams

**`read_datagrams(source, *, decoder=None, max_frame_size=262144) -> Iterator[CapturedDatagram]`**
— `read_frames` and `FrameDecoder.decode` in one call: every UDP datagram of a
capture, in capture order, IP fragments reassembled. It raises
`CaptureFormatError` for a damaged container and nothing for a frame that does
not decode: pass a `decoder` to choose its options and to read `decoder.stats`
afterwards.

**`CapturedDatagram(time, source, destination, payload, fragmented=False, truncated=False)`**
— a named tuple: one UDP datagram from a capture.

- `source` and `destination` are `(host, port)` pairs, the host as address
  text: usable as a socket address, and as `netimps.SocketAddress`.
- **An address on the wire is not rewritten.** A v4-mapped IPv6 address stays
  mapped, and is written `::ffff:10.0.0.5` on every Python (the standard
  library writes `::ffff:a00:5` before 3.13).
- `time` of a reassembled datagram is that of the fragment that completed it.
- `fragmented`: `payload` is only what the first IP fragment carried. Set
  only by a decoder built with `reassemble=False`.
- `truncated`: `payload` is shorter than the datagram's own length field says,
  because the capture's snap length cut the frame. **Check it before reading a
  short payload as a short message.**

**`FrameDecoder(*, reassemble=True, max_reassemblies=256, reassembly_timeout=30.0)`**
— decodes frames, keeping IP fragment state between them. Feed it every frame
of a capture, in order. Not safe to share between threads. `ValueError` for a
limit that is not positive.

- **`FrameDecoder.decode(frame) -> List[CapturedDatagram]`** — the datagram
  `frame` (a `CapturedFrame`) carries or completes, as a list of one; an empty
  list for anything else. **It never raises for a frame**: what it could not
  use is counted.
- **`FrameDecoder.stats`** — a `DecodeStats` snapshot of the counters.
- `reassemble=False` keeps no state: a first fragment is returned with
  `fragmented=True` and the octets it carries; later fragments are counted and
  passed over.
- Fragments of anything that is not UDP are never held.
- **A fragment that overlaps another discards its whole datagram**, in IPv4 as
  in IPv6 (RFC 5722 requires it for IPv6). The same fragment seen twice, octet
  for octet, is ignored: a capture taken on a bridge shows a frame more than
  once.

**`DecodeStats(frames, datagrams, ignored, malformed, unsupported, fragments, dropped, pending)`**
— a named tuple of counts.

| Field | Counts |
| --- | --- |
| `frames` | frames given to `decode` |
| `datagrams` | UDP datagrams returned |
| `ignored` | well-formed frames that are not UDP over IP: ARP, TCP, ICMP |
| `malformed` | frames cut short or inconsistent |
| `unsupported` | frames of a link type not in `LINKTYPES`; each such type is logged once, at `WARNING` on the logger `pktcap._frames`, for the first eight |
| `fragments` | frames that were IP fragments of a UDP datagram |
| `dropped` | reassemblies discarded: an overlap, a ceiling, old age |
| `pending` | reassemblies still waiting for a fragment |

A capture that decodes to nothing is told from an empty one by these:
`unsupported` equal to `frames` is a link type this library does not read.

**`LINKTYPES`** — a read-only mapping from the `LINKTYPE_` numbers understood
to a name: `0` NULL, `1` ETHERNET (up to eight VLAN or QinQ tags are skipped),
`12`, `14` and `101` RAW, `108` LOOP, `113` LINUX_SLL, `228` IPV4, `229` IPV6,
`276` LINUX_SLL2. IPv4 options and the IPv6 hop-by-hop, routing, destination
and fragment headers are read.

Ceilings:

| What a frame or a capture states | Ceiling | At the ceiling |
| --- | --- | --- |
| datagrams being reassembled at once | `max_reassemblies` (256) | the oldest is discarded, `dropped` |
| octets in one reassembled datagram | 65,535 | the datagram is discarded, `dropped` |
| fragments of one datagram | 1,024 | the datagram is discarded, `dropped` |
| capture time between a datagram's first fragment and a later one | `reassembly_timeout` (30 s) | the datagram is discarded, `dropped`, and a new one starts |
| IPv6 extension headers in one packet | 64 | the frame is `malformed` |
| VLAN tags on one frame | 8 | the frame is `malformed` |

A fragment costs a binary search and one insertion whatever the order of
arrival, and a full table holds at most about 250 KiB for each reassembly in
flight.

## Writing a pcap capture

**`PcapWriter(target)`** — writes UDP datagrams as a pcap file that tcpdump and
Wireshark read: little-endian, microsecond, link type RAW (101). A datagram
seen at a socket has no IP header left, so each is written under synthesised
IPv4 or IPv6 and UDP headers with valid checksums. A context manager.

- `target` is a path or a binary stream. A stream stays the caller's to
  close; a path this writer opened is closed by `close()`.
- **Constructing a writer touches nothing.** A path is opened, an existing
  file replaced and the file header written by the first `write`; a writer
  that never writes creates no file.
- **`PcapWriter.write(time, source, destination, payload) -> None`** — append
  one datagram. `source` and `destination` are `netimps.SocketAddress` values:
  `(host, port)` or the four-item IPv6 form, the host as address text with or
  without a `%zone`. `time` is seconds since the epoch, from 0 up to 2**32,
  kept to the microsecond. `payload` is at most 65,507 octets for IPv4 and
  65,527 for IPv6.
- **`PcapWriter.write_datagram(datagram) -> None`** — the same for a
  `CapturedDatagram`. A `fragmented` or `truncated` one is written with the
  payload it has; the capture does not record that it was partial.
- **`PcapWriter.close() -> None`** — complete on return, harmless when
  repeated. A closed writer refuses to write.
- A v4-mapped IPv6 address is written as IPv4, which is what was on the wire
  when a dual-stack socket reported it; a datagram with one IPv4 and one IPv6
  end is written as IPv6, the IPv4 end in its mapped form.
- Each record is flushed, so a capture can be read while it grows.
- Raises `ValueError` for a host that is not an address (a name is not looked
  up), a port outside 0-65535, a payload too long, a time out of range or a
  closed writer, and `TypeError` for an argument of the wrong type; in every
  case nothing is written. `OSError` when the path cannot be opened.
- Not safe to share between threads: serialise the calls.

pcapng is read and not written.

## Writing in a named format

One writer for every output a capture tool offers. `pcap` takes the datagram;
a record format takes a **record**: plain data (`dict`, `list`, `str`, `int`,
`float`, `bool`, `None`) that the protocol library made from one of its
messages. What each record format writes, exactly: `pktcap/_formats/AGENTS.md`.

**`OUTPUT_FORMATS`** — `("pcap", "json", "yaml", "toml", "ini")`, and
**`RECORD_FORMATS`** — the last four. `yaml` needs the `yaml` extra and `toml`
the `toml` extra; a format whose extra is missing stays in both tuples.

**`has_output_format(name) -> bool`** — whether that format can be written on
this installation. `UnsupportedFormatError` for a name that is no format.

**`dumps_record(record, format="json") -> str`** — one record as text, ending
in a newline. `ImportError` naming the extra when it is missing.

**`datagram_record(datagram) -> Dict[str, Any]`** — the record of a
`CapturedDatagram` for a caller with no protocol to decode it: `time`,
`source` and `destination` as `host:port` text (an IPv6 host in brackets),
`length`, `payload` as hex, and `fragmented` or `truncated` only when true.

**`CaptureWriter(target, format=None, *, per_record=False, append=False, fields=(), max_files=1000)`**
— writes datagrams, or the records made of them, in one format. A context
manager.

- `target` is a path or a **binary** stream (`sys.stdout.buffer`, not
  `sys.stdout`); a stream stays the caller's to close.
- `format=None` takes the format from the ending of the target's name
  (`.pcap`, `.cap`, `.json`, `.jsonl`, `.ndjson`, `.yaml`, `.yml`, `.toml`,
  `.ini`; letter case ignored, the longest ending wins). A name given wins
  over the ending. Content is never sniffed. `UnsupportedFormatError`,
  listing the formats, when neither says.
- **`CaptureWriter.write(datagram, record=None, *, names=None) -> None`** —
  `pcap` writes the datagram and ignores `record`. A record format writes
  `record`, or `datagram_record(datagram)` when it is `None`.
- **Nothing is opened until the first `write`**, and each record is flushed.
  Without `append` an existing file is replaced then; `append=True` adds to
  it (`json` and `yaml` stay valid streams; `pcap` cannot be appended to).
- `toml` and `ini` hold one record per file, so they need `per_record=True`.
- **`per_record=True`**: `target` is a file-name pattern in `str.format`
  syntax, and each record goes to its own file, directories created as
  needed. The writer fills `{timestamp}` (the datagram's time in UTC,
  `20231114T221320.500000Z`), `{index}` (an `int` counting from 0, so
  `{index:06d}` works) and `{format}`. The caller declares its own fields in
  `fields=("xid", "client_id")` and gives their values in
  `write(..., names={"xid": ..., "client_id": ...})`.
- **`CaptureWriter.close() -> None`** — complete on return, harmless twice.
- `CaptureWriter.format` is the format's name; `.written` counts what was
  written and `.refused` the records a full budget turned away.
- The checks made when the writer is built, each a `ValueError` unless
  noted: a pattern that is malformed or uses anything but bare field names
  (`{}`, `{0}`, `{xid.real}`); a pattern field that is neither built in nor in
  `fields`; a `fields` entry that is built in; a stream of `toml` or `ini`;
  `append` with `pcap`; `per_record` with a stream; a missing extra
  (`ImportError`); a text stream (`TypeError`).
- `write` raises `ValueError` for a closed writer or a field with no value,
  and what `dumps_record` or `PcapWriter.write` raise; nothing is written.

Ceilings, for a pattern field whose value a peer chose (a client identifier):

| What the network states | Ceiling | At the ceiling |
| --- | --- | --- |
| distinct files one writer creates | `max_files` (1,000) | the record is not written, `refused`, one `WARNING` on the logger `pktcap._output` |
| characters one field value adds to a name | 64 | the rest is dropped |

A field value has every run of characters outside `A-Z a-z 0-9 _ . -`
replaced by `_` and leading and trailing `.` and `_` removed (`unknown` when
nothing is left), so it cannot hold a path separator or be `..`; a file name
that Windows would open as a device (`NUL`, `COM1`) gets a leading `_`. A time
outside any calendar is written as `t<seconds>`.

## Replaying a capture

The datagrams of a capture again, in order and in time. Three functions over
one schedule; the options `speed`, `max_delay` and `limit` mean the same in
each.

`source` (`ReplaySource`) is a path or binary stream of a pcap or pcapng
capture, **or any iterable of `CapturedDatagram`**: choosing which datagrams
to replay is a generator expression, and the waits are then the gaps between
the ones chosen.

**`replay_schedule(source, *, speed=1.0, max_delay=5.0, limit=None) -> Iterator[Tuple[float, CapturedDatagram]]`**
— `(delay, datagram)` for each datagram. `delay` is the seconds to wait before
it: the time since the one before it in the capture, divided by `speed`. **It
reads no clock and waits for nothing**, so an event loop drives it with its
own sleep (`await asyncio.sleep(delay)`, then `endpoint.asend(...)`).

**`replay(source, deliver, *, speed=1.0, max_delay=5.0, limit=None) -> int`**
— blocks: sleeps each delay, calls `deliver(datagram)`, and returns how many
were delivered. Partial datagrams are delivered too; an exception from
`deliver` ends the replay and propagates. A protocol library that knows a
reply goes to another port builds a faithful replay on this.

**`replay_to(source, dst, port, *, endpoint=None, speed=1.0, max_delay=5.0, limit=None) -> ReplayResult`**
— blocks: sends each payload to `(dst, port)`.

- **The destination is always the caller's.** The addresses recorded in the
  capture are never sent to. `dst` is `netimps.HostLike`; a name is looked up
  once. `port` is 1 to 65535.
- **A datagram marked `fragmented` or `truncated` is not sent**, since its
  payload is not the whole message: it is counted in `ReplayResult.partial`.
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
| `limit` | stop after this many datagrams; the source is not read past it |

`ValueError` for a `speed` that is not positive and finite, a `max_delay` or
`limit` below zero, a `port` outside 1-65535 or an empty `dst`; `TypeError`
for an option of the wrong type or a `deliver` that is not callable; all at
the call, before anything is read or sent.

## Capturing live

**Linux only**, through an `AF_PACKET` socket, and the process needs
`CAP_NET_RAW` (root, or that capability granted). Everywhere else, and
wherever a capture tool is preferred, pipe one in and read its output:

```text
tcpdump -i eth0 -U -w - udp | your-program     # read_datagrams(sys.stdin.buffer)
dumpcap -i Ethernet -w - -f udp | your-program
```

**`has_live_capture() -> bool`** — whether this platform has `AF_PACKET`. It
says nothing about permission.

**`LiveCapture(interface=None, *, timeout=1.0)`** — the IP packets on one
interface, or on all of them when `interface` is `None`. A context manager;
constructing one opens nothing.

- `interface` is `netimps.InterfaceLike`: a name, a `netimps.Interface`, or
  anything `netimps.get_interface` finds one by (an address, a MAC).
- **`LiveCapture.open() -> None`** — open the socket; `with` does it. Does
  nothing when already open. `LiveCaptureError` where the platform has no
  `AF_PACKET`, the kernel's `PermissionError` without the capability,
  `ValueError` when no interface matches.
- **`LiveCapture.read() -> Optional[CapturedFrame]`** — the next IP packet, or
  `None` when `timeout` seconds pass without one. Frames have link type 228
  (IPv4) or 229 (IPv6) and the time they were read, ready for
  `FrameDecoder.decode`. What is not IP is passed over.
- Iterating a capture yields frames until it is closed.
- **`LiveCapture.fileno() -> int`** — the socket's descriptor, for a caller's
  own selector or event loop. There is no asynchronous twin.
- **`LiveCapture.close() -> None`** — final, complete on return, harmless
  twice.
- On a loopback device every packet is seen leaving and arriving; only the
  arriving copy is returned. Loopback is told by the device type the kernel
  reports, not by the name `lo`.
- Live traffic is untrusted like a file: decode it with a `FrameDecoder`,
  whose ceilings then apply.

**`sniff(interface=None, *, stop=None, decoder=None) -> Iterator[CapturedDatagram]`**
— `LiveCapture` and `FrameDecoder` in one call: UDP datagrams as they arrive.
The socket is opened when the first datagram is asked for (which is when
`LiveCaptureError` or `PermissionError` is raised) and closed when the
iterator ends or is closed. `stop()` is called between packets, and at least
once a second on a quiet interface; returning true ends the iteration.

## The capture-filter expression

The grammar two protocol libraries share: clauses `key=value` or `key!=value`
joined by `and`. **What a key means, how a value converts and how a clause
matches are the caller's**; this library owns the split into clauses, the
negation and the conjunction.

```text
op=RRQ,WRQ and host=10.0.0.0/8
msg_type=DHCPDISCOVER and option.53!=DHCPOFFER
```

**`parse_capture_filter(text) -> Tuple[FilterClause, ...]`** — the clauses, in
order. `None`, empty or blank text is no clause.

**`compile_capture_filter(text, build) -> Callable[[T], bool]`** — one
predicate over the caller's own item type. `build(clause)` is called once per
clause, when the filter is compiled and never per item, and returns the test
for that clause's key and value; a `!=` clause is inverted for it; the
predicate is true when every clause holds. `None` or blank text matches
everything.

- `build` raises `ValueError` for a key it does not know or a value that does
  not convert. It is re-raised as `CaptureFilterError` naming the clause, the
  original chained: one error at start-up, not one per packet.
- A test may return anything truthy. Any other exception from `build`
  propagates, and a `build` that returns something not callable is a
  `TypeError`.

**`FilterClause(key, value, negated=False)`** — a named tuple. `key` is as
written (case kept), `value` the text after the operator with surrounding
space removed, `negated` whether the operator was `!=`.

- `FilterClause.values` — `value` split on commas, each item stripped and
  empty ones dropped, for a key that reads a comma as "any of". `value`
  itself is never split.
- `str(clause)` is the canonical text, `key=value` or `key!=value`, and
  parsing the clauses' texts joined by ` and ` gives the same clauses back.

The dialect:

- `and` joins clauses in any letter case and needs space on both sides.
  **There is no `or`**: the word alone, in any case, is refused by name, so a
  value cannot contain ` or ` or ` and `.
- A key is one or more of `A-Z a-z 0-9 _ . -`. The first `=` ends it; a `!`
  just before that `=` negates. Everything after is the value and must not be
  blank, so a value may itself contain `=`.
- An expression is at most 4,096 characters.
- Each of these raises `CaptureFilterError`; text that is not `str` or `None`
  is a `TypeError`.

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

| `LiveCaptureError` | `PktcapError`, `OSError` | a platform with no `AF_PACKET`, asked to capture live |

A format that exists and whose extra is not installed raises the builtin
`ImportError`, naming the extra. A process that may not open a packet socket
gets the kernel's `PermissionError`.

`CaptureFormatError.offset` is how many octets of the input had been read when
the problem was found, or `None`; the message ends with it and never quotes the
file.
