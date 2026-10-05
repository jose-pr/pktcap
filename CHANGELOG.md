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

[Unreleased]: https://github.com/jose-pr/pktcap/commits/main
