"""``pktcap convert``: a capture into another capture format, or into records."""

from __future__ import annotations

import sys
from typing import BinaryIO, Iterator, Optional, Union

from .._dissect import DissectedFrame, FrameDissector, read_dissected
from .._exceptions import CaptureFormatError
from ._writing import Writing

__all__ = ["Convert"]


class Convert(Writing):
    """Copy a pcap or pcapng capture, filtered, into pcap, pcapng or records (json, yaml, toml, ini) or lines of text."""

    _parsername_ = "convert"

    input: str
    "The pcap or pcapng capture to read, or - for standard input"
    ("--input", "-i")

    limit: Optional[int] = None
    "Write at most this many frames, then stop reading. Omitted: all of them"
    ("--limit",)

    def _source(self) -> Union[str, BinaryIO]:
        if self.input != "-":
            return self.input
        buffer = getattr(sys.stdin, "buffer", None)
        if buffer is None:
            raise ValueError("--input - needs a standard input: name a file")
        return buffer  # type: ignore[no-any-return]

    def _name(self) -> str:
        return "standard input" if self.input == "-" else self.input

    def _limit(self) -> Optional[int]:
        return self.limit

    def _frames(self, dissector: FrameDissector) -> Iterator[DissectedFrame]:
        return self._named(read_dissected(self._source(), dissector=dissector))

    def _named(self, frames: Iterator[DissectedFrame]) -> Iterator[DissectedFrame]:
        try:
            yield from frames
        except CaptureFormatError as exc:
            # The records before the damage are written; the exception never
            # names the file, so this does.
            raise ValueError(
                "%s: %s (%d written before it)"
                % (self._name(), exc, self._open.written)
            ) from exc
