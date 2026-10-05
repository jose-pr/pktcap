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

[Unreleased]: https://github.com/jose-pr/pktcap/commits/main
