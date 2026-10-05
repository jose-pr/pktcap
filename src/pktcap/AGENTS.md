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
