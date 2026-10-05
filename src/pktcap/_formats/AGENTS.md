# `pktcap` record formats — public API header

Header-file-style reference for the record formats of the `pktcap` package:
what each one writes, exactly, so the output can be read back without reading
the source. It ships inside the package and is self-contained; the top header
is `pktcap/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pktcap>.

This directory (`pktcap/_formats/`) is private and not an import path: every
name below is imported from `pktcap`.

## What a record is

A mapping of text keys to plain data: `dict`, `list`, `str`, `int`, `float`,
`bool`, `None`. A protocol library makes it from one of its messages; this
library never looks inside. Any `Mapping` is accepted at the top level.

**`dumps_record(record, format="json") -> str`** — one record as text in the
named format, ending in a newline. `format` is one of `RECORD_FORMATS`
(`"json"`, `"yaml"`, `"toml"`, `"ini"`), matched whatever its letter case.

Raises, the same for every format:

- `UnsupportedFormatError` for a name that is no record format (`"pcap"`
  included: it writes datagrams, through `CaptureWriter` or `PcapWriter`);
- `ImportError` when the format's extra is not installed, as
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
