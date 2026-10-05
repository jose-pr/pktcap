# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The package, with one exception base, `PktcapError`, and `__version__`.
- `read_frames(source, *, max_frame_size=262144)` reads a pcap or pcapng
  capture, from a path or from a stream that cannot seek, as `CapturedFrame`
  named tuples. Every length the file states is checked against a ceiling
  before it is read: a 48-octet file whose record claims 1 GiB raises
  `CaptureFormatError` having allocated under 1 MiB. Any damaged capture
  raises `CaptureFormatError`, a `ValueError`, with the octet offset.
- `FrameDecoder` and `read_datagrams(source, *, decoder=None)` decode frames
  to `CapturedDatagram` named tuples under ten link types, IPv4 and IPv6.
  IP reassembly is an option (`reassemble=False` keeps no state and marks the
  first fragment `fragmented`) and is bounded: 256 datagrams in flight, 65,535
  octets and 1,024 fragments each, 30 seconds of capture time. A fragment
  costs a binary search whatever the order of arrival. A frame that does not
  decode is counted in `FrameDecoder.stats` (`DecodeStats`: `ignored`,
  `malformed`, `unsupported`, `dropped`, `pending`) and never raised; a
  datagram cut by the snap length is marked `truncated`.
- `PcapWriter(target)` writes datagrams as pcap (link type RAW, IPv4 or IPv6
  and UDP headers with valid checksums). The file is opened by the first
  `write`, not by the constructor, so a writer that never writes creates no
  file and replaces none. A payload over 65,507 octets (IPv4) or 65,527
  (IPv6), a port outside 0-65535 and a time outside 0 to 2**32 raise
  `ValueError` and write nothing.
- `parse_capture_filter(text)` and `compile_capture_filter(text, build)` read
  the `key=value and key!=value` filter expression into `FilterClause` named
  tuples and one predicate. The caller's `build` gives each key its meaning
  and is called once per clause when the filter is compiled; its `ValueError`
  becomes a `CaptureFilterError` naming the clause. `or` is refused by name.
- `CaptureWriter(target, format=None, *, per_record=False, append=False,
  fields=(), max_files=1000)` writes datagrams as `pcap`, or the records a
  protocol library makes of them as `json` (one line each), `yaml` (one
  document each), `toml` or `ini` (one file each), into one growing file or
  one file per record under a name pattern. `dumps_record(record, format)`
  writes one record as text; `datagram_record(datagram)` is the record of a
  datagram with no protocol to decode it; `OUTPUT_FORMATS`, `RECORD_FORMATS`
  and `has_output_format(name)` say what can be written. `yaml` and `toml`
  need the extras of those names and raise `ImportError` naming the extra
  without them. Every record format writes printable ASCII. A per-record
  writer creates at most `max_files` files and makes each field value safe
  for a file name.
- `replay_schedule(source, *, speed=1.0, max_delay=5.0, limit=None)` yields
  `(delay, datagram)` for a capture or any iterable of datagrams and reads no
  clock; `replay(source, deliver)` sleeps each delay and calls `deliver`;
  `replay_to(source, dst, port, *, endpoint=None)` sends each payload to the
  one destination named, through a `netimps` socket, and returns
  `ReplayResult(sent, partial)`. The addresses in the capture are never sent
  to, the recorded timing is the default, each wait is capped at `max_delay`,
  and a `fragmented` or `truncated` datagram is counted and not sent.

[Unreleased]: https://github.com/jose-pr/pktcap/commits/main
