# `pktcap` output formats — public API header

Header-file-style reference for writing captures with the `pktcap` package:
`PcapWriter` and `PcapngWriter`, `CaptureWriter` in a named format, and what
each record format writes and `loads_record` reads, exactly, so the output can
be read back without reading the source. It ships inside the package and is
self-contained; the top header is `pktcap/AGENTS.md`. Development
documentation lives with the source at <https://github.com/jose-pr/pktcap>.

This directory (`pktcap/_formats/`) is private and not an import path: every
name below is imported from `pktcap`.

## Writing a capture

**`PcapWriter(target)`** and **`PcapngWriter(target)`** — write a capture that
tcpdump and Wireshark read. The same three methods; each is a context manager.

- `target` is a path or a binary stream. A stream stays the caller's to
  close; a path the writer opened is closed by `close()`.
- **Constructing a writer touches nothing.** A path is opened, an existing
  file replaced and the file's opening octets written by the first write; a
  writer that never writes creates no file. Each record is flushed, so a
  capture can be read while it grows.
- **`PcapWriter.write_frame(frame) -> None`** — append a `CapturedFrame` as it
  is: its octets, its link type, its time to the microsecond. A capture read
  with `read_frames` and written back holds the same frames, octet for octet.
  A frame is at most 262,144 octets.
- **`PcapWriter.write(time, source, destination, payload) -> None`** — append
  one UDP datagram seen at a socket, which has no link or IP header left: it
  is written as raw IP (link type 101) under synthesised IPv4 or IPv6 and UDP
  headers with valid checksums. `source` and `destination` are
  `netimps.SocketAddress` values: `(host, port)` or the four-item IPv6 form,
  the host as address text with or without a `%zone`. `time` is seconds since
  the epoch, from 0 up to 2**32. `payload` is at most 65,507 octets for IPv4
  and 65,527 for IPv6. A v4-mapped address is written as IPv4; a datagram
  with one IPv4 and one IPv6 end is written as IPv6, the IPv4 end mapped.
- **`PcapWriter.write_datagram(datagram) -> None`** — `write` for a
  `CapturedDatagram`. A partial one is written with the payload it has.
- **`PcapWriter.close() -> None`** — complete on return, harmless when
  repeated. A closed writer refuses to write.
- **A pcap file has one link type**, fixed by the first thing written (101 for
  a datagram, the frame's own for a frame); `PcapWriter` refuses a write of
  another with `ValueError`. **`PcapngWriter` holds any mix**: it describes
  one interface per link type, in the order they are first written, so a
  capture of several link types round-trips through it. A frame's `interface`
  number is not kept. It writes no option: nothing about the host, the tool
  or the interfaces beyond their link types.
- Raises `ValueError` for a host that is not an address (a name is not looked
  up), a port outside 0-65535, a payload or frame too long, a time out of
  range, a link type outside 0-65535 or a closed writer, and `TypeError` for
  an argument of the wrong type; in every case nothing is written. `OSError`
  when the path cannot be opened.

## One writer for every format

`OUTPUT_FORMATS` is `("pcap", "pcapng", "json", "yaml", "toml", "ini", "text")`:
two capture formats, which take the frame or datagram itself, the four
record formats of `RECORD_FORMATS`, and `text`, a line for a person.

**`CaptureWriter(target, format=None, *, per_record=False, append=False, fields=(), max_files=1000)`**
— writes frames or datagrams, or the records made of them, in one format. A
context manager.

- `target` is a path or a **binary** stream (`sys.stdout.buffer`, not
  `sys.stdout`); a stream stays the caller's to close.
- `format=None` takes the format from the ending of the target's name
  (`.pcap`, `.cap`, `.pcapng`, `.json`, `.jsonl`, `.ndjson`, `.yaml`, `.yml`,
  `.toml`, `.ini`, `.txt`, `.log`; letter case ignored, the longest ending wins). A name given
  wins over the ending. Content is never sniffed. `UnsupportedFormatError`,
  listing the formats, when neither says.
- **`CaptureWriter.write(item, record=None, *, text=None, names=None) -> None`** —
  `item` is a `CapturedDatagram` or a `DissectedFrame`. `pcap` and `pcapng`
  write it (a datagram under synthesised headers, a frame as captured) and
  ignore `record`. A record format writes `record`, or `datagram_record` or
  `frame_record` of `item` when it is `None`.
- **`text=`** is a record the caller rendered itself, for a record format:
  this library keeps the container (the growing file, the name pattern, the
  file budget, the refusal count) and the octets are the caller's, encoded as
  UTF-8 and written exactly as given, with no line feed, marker or
  normalisation added or removed. A growing file gets the format's separator
  before the text and nothing after it: none for `json`, `---` and a line feed
  for `yaml`; text that ends in a line feed gives a `json` line and a `yaml`
  document each. A per-record file is the text and nothing else. `item` still
  gives `{timestamp}`, and `names` the caller's fields. `ValueError` for
  `text` with `pcap` or `pcapng`, with a `record` (two sources for one
  record), or that UTF-8 cannot encode; `TypeError` for a `text` that is not
  a `str`. Nothing is written, and no index used, then.
- **Nothing is opened until the first `write`**, and each record is flushed.
  Without `append` an existing file is replaced then; `append=True` adds to
  it (`json` and `yaml` stay valid streams; a capture cannot be appended to).
  The directories above a growing file are made then, as for a per-record
  file; building the writer touches nothing.
- **`per_record=True`**: `target` is a file-name pattern in `str.format`
  syntax, and each record goes to its own file, directories created as
  needed. The writer fills `{timestamp}` (the item's time in UTC,
  `20231114T221320.500000Z`), `{index}` (an `int` counting from 0, so
  `{index:06d}` works) and `{format}`. The caller declares its own fields in
  `fields=("xid", "client_id")` and gives their values in
  `write(..., names={"xid": ..., "client_id": ...})`.
- **`CaptureWriter.close() -> None`** — complete on return, harmless twice.
  `.format` is the format's name; `.written` counts what was written and
  `.refused` the records a full budget turned away.
- The checks made when the writer is built, each a `ValueError` unless noted: a
  pattern that is malformed or uses anything but bare field names (`{}`, `{0}`,
  `{xid.real}`); a pattern field that is neither built in nor in `fields`; a
  `fields` entry that is built in; a stream of `toml` or `ini` (one record per
  file: they need `per_record=True`); `append` with a capture format or with
  `per_record`; `per_record` with a stream; a missing extra (`MissingExtraError`); a text
  stream (`TypeError`).
- `write` raises `ValueError` for a closed writer or a field with no value,
  `TypeError` for an item of another type, and what `dumps_record` or the
  capture writer raise; nothing is written.

Ceilings, for a pattern field whose value a peer chose (a client identifier):

| What the network states | Ceiling | At the ceiling |
| --- | --- | --- |
| distinct files one writer creates | `max_files` (1,000) | the record is not written, `refused`, one `WARNING` on the logger `pktcap._output` |
| characters one field value adds to a name | 64 | cut to its first 55 characters, `-` and 8 hex digits of a digest of the whole |

A field value has every run of characters outside `A-Z a-z 0-9 _ . -`
replaced by `_` and leading and trailing `.` and `_` removed (`unknown` when
nothing is left), so it cannot hold a path separator or be `..`; a part of
the path that a field value made a name Windows would open as a device (`NUL`,
`COM1.x`), a directory or the file, gets a leading `_` on every platform, and
a part the pattern spells out is kept as written. The cut keeps two long
values that start alike apart: the cleaned value is cut to its first 55
characters, trailing `.` and `_` removed, and followed by `-` and the first 8
hexadecimal digits of the SHA-256 of the value as given (UTF-8), 64 characters
at most; a value of 64 or fewer is untouched. A time outside any calendar is
written as `t<seconds>`.

## A line a person reads

**`frame_summary(frame) -> str`** — the `text` format's line for a
`DissectedFrame`: its time in UTC (`2023-11-14T22:13:20.500000Z`; a time
outside any calendar is `t<seconds>`, a NaN `unknown`), then its socket
addresses when it has them (`10.0.0.5:50000 > 10.0.0.1:69`, an IPv6 host in
brackets; hosts alone for an IP packet with no UDP or TCP; none without IP),
then the name of its innermost layer and that layer's summary
(`udp: 50000 > 69 length 13`). A frame no dissector read says its link type and
size. `TypeError` for a non-frame.

- **A layer record may have a method `summary() -> str`**: one line saying what
  it holds. Every built-in layer has one; a registered layer without one, or
  with a `summary` that is not callable, is described by its name. A
  `summary()` that raises an `Exception` or returns something that is not
  text does not stop anything: the layer is described by its name and the
  failure is logged once for its class, at `WARNING` on `pktcap._summary`.
- **Text from the wire is escaped**, as every format's is: the line is
  printable ASCII (`\x1b`, `\ud800`, `\xe9`, a backslash doubled), so a
  terminal or a log reads it safely whatever a layer's text held.
- **A line is cut at 512 characters**, after a whole escape, ending in `...`.
- **`CaptureWriter` with `text`** writes `frame_summary` of a frame and, for a
  `CapturedDatagram`, `2023-11-14T22:13:20.500000Z 10.0.0.5:68 > 10.0.0.1:67
  udp 2 octets` (`, fragmented` and `, truncated` when it is partial), each
  ending in a line feed: many lines to a file, or one file a line with
  `per_record=True`. It takes `append`, ignores a `record`, refuses `text=` and
  needs no extra.

## What a record is

A mapping of text keys to plain data: `dict`, `list`, `str`, `int`, `float`,
`bool`, `None`, made by a protocol library from one of its messages; this
library never looks inside. Any `Mapping` is accepted at the top level.

**`datagram_record(datagram) -> Dict[str, Any]`** — the record of a
`CapturedDatagram` for a caller with no protocol to decode it: `time`,
`source` and `destination` as `host:port` text (an IPv6 host in brackets),
`length`, `payload` as hex, and `fragmented` or `truncated` only when true.

**`frame_record(frame) -> Dict[str, Any]`** — the record of a
`DissectedFrame`: `time`, `linktype`, `length` (of the captured frame),
`layers` and `payload` (hex of what no dissector read); `interface`, `error`
and `reassembled` only when they say something. `layers` is a list, outermost
first, of one mapping per layer: `layer` is its name (the class name without
`Layer`, in lower case: `ethernet`, `ipv4`, `udp`) and the rest its fields,
octets as hex. A registered dissector's layer is written from its `_asdict()`
or, when it is a mapping, its items.

**`dumps_record(record, format="json") -> str`** — one record as text in the
named format, ending in a newline. `format` is one of `RECORD_FORMATS`
(`"json"`, `"yaml"`, `"toml"`, `"ini"`), matched whatever its letter case.

Raises, the same for every format:

- `UnsupportedFormatError` for a name that is no record format (`"pcap"` and
  `"pcapng"` included: `CaptureWriter`, `PcapWriter` and `PcapngWriter` write
  those);
- `MissingExtraError` (an `ImportError`, with `format` and `extra`) when the
  format's extra is not installed: `YAML output needs the 'yaml' extra: pip
  install "pktcap[yaml]"`;
- `TypeError` when `record` is not a mapping or holds a value the format
  cannot represent, `ValueError` for a value it must refuse. **The message
  never quotes the record**, and no exception of the library that does the
  writing reaches the caller.

**Every format writes printable ASCII.** Text from the wire may hold terminal
control sequences and octets that are no character in any encoding; each
format escapes them, so a console encoding never matters.

## Reading a record

**`loads_record(text, format="json") -> Dict[str, Any]`** — the one record
`text` holds, the inverse of `dumps_record`. `text` is the content, never a
file name (`TypeError` unless a `str`), and is untrusted: nothing but these
is raised.

- `UnsupportedFormatError` and `MissingExtraError` as for `dumps_record`; to
  *read*, `yaml` needs PyYAML and `toml` needs nothing from Python 3.11
  (`tomllib`) and `tomli`, in the `toml` extra, before it.
- **`RecordFormatError(message, *, format, lineno=None)`** for text that is
  not one record; `lineno` is the 1-based line, when known. **The message
  never quotes the text**; nothing is chained.

**One record** is one document with a mapping at the top. Empty text, a list,
a scalar and more than one document are refused (a leading `---` is not);
whitespace alone is the empty record in `toml` and `ini`, which write it.

**Refused though a looser reader takes it:** a key written twice; in JSON
`NaN` and the infinities (`1e999` too); in YAML a tag the safe loader does not
know, a merge key `<<`, a value that is not plain data (`!!set`, a date) or
that contains itself; in TOML a date or time; nesting past the recursion
limit; a number too long to convert; a YAML alias, which makes a short text
stand for a structure of any size (the writer writes none: an object a record
holds twice is written twice). `!!binary` reads as `bytes`.

**INI reading** inverts the layout of `ini` below: names are percent-decoded,
case is kept, nothing is interpolated, `[DEFAULT]` is ordinary, `=` or `:`
separates a value, `#` and `;` begin a comment. **A value that is not JSON is
its text** (`op = BOOTREQUEST`, `NaN`). No section, or text before the first,
is an error.

**The law** `loads_record(dumps_record(r, f), f) == r` holds except: a non-text
key comes back as text in `json` and `ini`; `ini` cannot read the empty name
and reads `{"record": {...}}` alone as its contents; `toml` writes a lone
surrogate as U+FFFD, so two names that differ only in those collide; `json` and
`ini` read a high surrogate followed by a low one as the character they spell;
a NaN is not equal to itself; a tuple is a list. `toml` and `ini` list mappings
after the other values.

## The formats

| Name | File endings | Extra | Several records in one file | Written by | Read by |
| --- | --- | --- | --- | --- | --- |
| `json` | `.json`, `.jsonl`, `.ndjson` | none | yes, one per line | the standard library | the standard library |
| `yaml` | `.yaml`, `.yml` | `yaml` | yes, one document each | PyYAML, `safe_dump` | PyYAML, `SafeLoader` |
| `toml` | `.toml` | `toml` | no | tomli-w | `tomllib`, else `tomli` |
| `ini` | `.ini` | none | no | this library | `configparser` |

### `json`

One line per record: `json.dumps` with its default separators, keys in the
record's order. Every character outside ASCII and every control character is a
`\u` escape. `NaN`, the infinities, a record that contains itself and one
nested past the recursion limit are a `ValueError`. A key that is not text
follows `json.dumps`: a number, `True`, `False` or `None` becomes its text,
anything else is a `TypeError`.

### `yaml`

One block-style document per record, keys in the record's order, non-ASCII
and control characters escaped inside double quotes. PyYAML's safe dumper is
the only one used: no Python tag is ever written. In a file of several
records each document is led by `---`, the first one included, so a file
that is appended to stays one valid stream; a file of one record has no
marker. `bytes` is `!!binary`.

### `toml`

One document per record. TOML has no null: a record holding `None` anywhere
is a `TypeError`. Keys must be text. Characters outside ASCII are written as
`\uXXXX` or `\UXXXXXXXX`; half of a surrogate pair, which is not a character,
is written as U+FFFD.

### `ini`

One file per record: a top-level key whose value is a mapping becomes a
section of that name, its items the options; every other top-level key becomes
an option of the section `[record]`, which comes first.

```python
record = {"op": "BOOTREQUEST", "xid": 305441741, "options": {"53": "DHCPDISCOVER"}}
text = pktcap.dumps_record(record, "ini")  # [record] op = ... [options] 53 = ...
assert pktcap.loads_record(text, "ini") == record
```

- **Each value is JSON on one line**, so it reads back with its type; a
  mapping below the second level is a JSON object.
- **A caller chooses its own sections** by passing a record whose top-level
  values are all mappings: `{"message": {...}, "options": {...}}` writes
  `[message]` and `[options]` and no `[record]`.
- A section or option name outside `A-Z a-z 0-9 _ . -` is percent-encoded
  (`a b` is written `a%20b`), so no bracket, separator, comment mark or line
  break from the wire reaches the file; `DEFAULT` in any case has its first
  letter encoded, since `configparser` reads that section as defaults. Names
  keep their case (`optionxform = str`), and the file is read without
  interpolation.
- `ValueError` for two names that would be one section or one option, and for
  a record that has both top-level values and a mapping named `record`.
