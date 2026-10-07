# `pktcap` output formats — public API header

Header-file-style reference for writing captures with the `pktcap` package:
`PcapWriter` and `PcapngWriter`, `CaptureWriter` in a named format, and what
each record format writes, exactly, so the output can be read back without
reading the source. It ships inside the
package and is self-contained; the top header is `pktcap/AGENTS.md`.
Development documentation lives with the source at
<https://github.com/jose-pr/pktcap>.

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

`OUTPUT_FORMATS` is `("pcap", "pcapng", "json", "yaml", "toml", "ini")`:
two capture formats, which take the frame or datagram itself, and the four
record formats of `RECORD_FORMATS`.

**`CaptureWriter(target, format=None, *, per_record=False, append=False, fields=(), max_files=1000)`**
— writes frames or datagrams, or the records made of them, in one format. A
context manager.

- `target` is a path or a **binary** stream (`sys.stdout.buffer`, not
  `sys.stdout`); a stream stays the caller's to close.
- `format=None` takes the format from the ending of the target's name
  (`.pcap`, `.cap`, `.pcapng`, `.json`, `.jsonl`, `.ndjson`, `.yaml`, `.yml`,
  `.toml`, `.ini`; letter case ignored, the longest ending wins). A name given
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
  document each. A per-record file is the text
  and nothing else. `item` still gives `{timestamp}`, and `names` the caller's
  fields. `ValueError` for `text` with `pcap` or `pcapng`, with a `record`
  (two sources for one record), or that UTF-8 cannot encode; `TypeError` for a
  `text` that is not a `str`. Nothing is written, and no index used, then.
- **Nothing is opened until the first `write`**, and each record is flushed.
  Without `append` an existing file is replaced then; `append=True` adds to
  it (`json` and `yaml` stay valid streams; a capture cannot be appended to).
  The directories above a growing file are made then, as for a per-record
  file; building the writer touches nothing.
- `toml` and `ini` hold one record per file, so they need `per_record=True`.
- **`per_record=True`**: `target` is a file-name pattern in `str.format`
  syntax, and each record goes to its own file, directories created as
  needed. The writer fills `{timestamp}` (the item's time in UTC,
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
  `append` with a capture format; `per_record` with a stream; a missing extra
  (`MissingExtraError`); a text stream (`TypeError`).
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
a part the pattern spells out is kept as written. The
cut keeps two long values that start alike apart: the cleaned value is cut to
its first 55 characters, trailing `.` and `_` removed, and followed by `-` and
the first 8 hexadecimal digits of the SHA-256 of the value as given (UTF-8),
64 characters at most; a value of 64 or fewer is untouched. A time
outside any calendar is written as `t<seconds>`.

## What a record is

A mapping of text keys to plain data: `dict`, `list`, `str`, `int`, `float`,
`bool`, `None`. A protocol library makes it from one of its messages; this
library never looks inside. Any `Mapping` is accepted at the top level.
`datagram_record` and `frame_record` make the record of a datagram or of a
dissected frame for a caller with no protocol of its own.

**`dumps_record(record, format="json") -> str`** — one record as text in the
named format, ending in a newline. `format` is one of `RECORD_FORMATS`
(`"json"`, `"yaml"`, `"toml"`, `"ini"`), matched whatever its letter case.

Raises, the same for every format:

- `UnsupportedFormatError` for a name that is no record format (`"pcap"`
  and `"pcapng"` included: they write frames and datagrams, through
  `CaptureWriter`, `PcapWriter` or `PcapngWriter`);
- `MissingExtraError` (an `ImportError`, with `format` and `extra`) when the
  format's extra is not installed, as
  `YAML output needs the 'yaml' extra: pip install "pktcap[yaml]"`;
- `TypeError` when `record` is not a mapping or holds a value the format
  cannot represent, `ValueError` for a value it must refuse. **The message
  never quotes the record**, and no exception of the library that does the
  writing reaches the caller.

**Every format writes printable ASCII.** Text from the wire may hold terminal
control sequences and octets that are no character in any encoding; each
format escapes them, so a record can be printed and a console encoding never
matters.

## The formats

| Name | File endings | Extra | Several records in one file | Written by |
| --- | --- | --- | --- | --- |
| `json` | `.json`, `.jsonl`, `.ndjson` | none | yes, one per line | the standard library |
| `yaml` | `.yaml`, `.yml` | `yaml` | yes, one document each | PyYAML, `safe_dump` |
| `toml` | `.toml` | `toml` | no | tomli-w |
| `ini` | `.ini` | none | no | this library |

### `json`

One line per record: `json.dumps` with its default separators, keys in the
record's order. Every character outside ASCII and every control character is a
`\u` escape. `NaN` and the infinities are a `ValueError`, as is a record that
contains itself or is nested past the interpreter's recursion limit. A key
that is not text follows `json.dumps`: a number, `True`, `False` or `None`
becomes its text, anything else is a `TypeError`.

### `yaml`

One block-style document per record, keys in the record's order, non-ASCII
and control characters escaped inside double quotes. PyYAML's safe dumper is
the only one used: no Python tag is ever written. In a file of several
records each document is led by `---`, the first one included, so a file
that is appended to stays one valid stream; a file of one record has no
marker. `bytes` is written as `!!binary`.

### `toml`

One document per record. TOML has no null: a record holding `None` anywhere
is a `TypeError`. Keys must be text. Characters outside ASCII are written as
`\uXXXX` or `\UXXXXXXXX`; half of a surrogate pair, which is not a character,
is written as U+FFFD. There is no separator between TOML documents, so a file
holds exactly one record.

### `ini`

One file per record, laid out by one rule:

- a top-level key whose value is a mapping becomes a section of that name, and
  the mapping's items its options;
- every other top-level key becomes an option of the section `[record]`, which
  comes first.

```ini
[record]
op = "BOOTREQUEST"
xid = 305441741

[options]
53 = "DHCPDISCOVER"
```

- **Each value is JSON on one line**, so it reads back with its type:
  `json.loads` of each value restores the record. A mapping below the second
  level is a JSON object.
- **A caller chooses its own sections** by passing a record whose top-level
  values are all mappings: `{"message": {...}, "options": {...}}` writes
  `[message]` and `[options]` and no `[record]`.
- A section or option name outside `A-Z a-z 0-9 _ . -` is percent-encoded
  (`a b` is written `a%20b`), so no bracket, separator, comment mark or line
  break from the wire reaches the file. A name spelling `DEFAULT` in any case
  has its first letter encoded, since `configparser` reads that section as
  defaults.
- Names keep their case: read the file with a reader that does too
  (`configparser` with `optionxform = str`) and without interpolation.
- `ValueError` for two names that would be one section or one option, and for
  a record that has both top-level values and a mapping named `record`.
