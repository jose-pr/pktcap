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

## Exceptions

Every exception pktcap raises on its own account descends from
**`PktcapError(Exception)`**, and each one also inherits the builtin a caller
would already catch. A caller's own mistake (a bad option, a wrong argument
type) is a plain `ValueError` or `TypeError`, never a `PktcapError`.

| Class | Bases | Raised for |
| --- | --- | --- |
| `PktcapError` | `Exception` | the base; catch it for "anything pktcap reported" |
| `CaptureFormatError` | `PktcapError`, `ValueError` | input that is not a pcap or pcapng capture, or is a damaged one |

`CaptureFormatError.offset` is how many octets of the input had been read when
the problem was found, or `None`; the message ends with it and never quotes the
file.
