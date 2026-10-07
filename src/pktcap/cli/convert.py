"""``pktcap convert``: a capture into another capture format, or into records."""

from __future__ import annotations

import sys
from typing import BinaryIO, Optional, Union

from .._copy import copy_frames
from .._dissect import FrameDissector, read_dissected
from .._exceptions import CaptureFormatError
from ._common import Writing

__all__ = ["Convert"]


class Convert(Writing):
    """Copy a pcap or pcapng capture, filtered, into pcap, pcapng or records (json, yaml, toml, ini)."""

    _parsername_ = "convert"

    input: str
    "The pcap or pcapng capture to read, or - for standard input"
    ("--input", "-i")

    limit: Optional[int] = None
    "Write at most this many frames, then stop reading. Omitted: all of them"
    ("--limit",)

    def _source(self) -> Union[str, BinaryIO]:
        return sys.stdin.buffer if self.input == "-" else self.input

    def _name(self) -> str:
        return "standard input" if self.input == "-" else self.input

    def __call__(self) -> Optional[int]:
        select = self._select()
        dissector = FrameDissector()
        with self._writer() as writer:
            try:
                result = copy_frames(
                    read_dissected(self._source(), dissector=dissector),
                    writer,
                    select=select,
                    datagrams=self.datagrams,
                    limit=self.limit,
                )
            except CaptureFormatError as exc:
                # The records before the damage are written; the exception
                # never names the file, so this does.
                raise ValueError(
                    "%s: %s (%d written before it)"
                    % (self._name(), exc, writer.written)
                ) from exc
        return self._report(result, dissector.stats, dissector)
