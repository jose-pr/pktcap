"""The options of a command that writes what it reads, and the summary line."""

from __future__ import annotations

import sys
from typing import Annotated, Optional

from duho import Choice

from .._copy import CopyResult
from .._dissect import DissectStats, FrameDissector
from .._formats import CAPTURE_FORMATS, OUTPUT_FORMATS
from .._output import CaptureWriter
from ._common import Base

__all__ = ["Writing"]

#: Link-type numbers named in the summary before it says "and more".
_LISTED_LINKTYPES = 8


class _TextSink:
    """A binary stream over the text stdout, for records, which are ASCII."""

    def write(self, data: bytes) -> int:
        sys.stdout.write(data.decode("utf-8"))
        return len(data)

    def flush(self) -> None:
        sys.stdout.flush()


class Writing(Base):
    """The options of a command that writes what it reads."""

    output: str = "-"
    "Where to write: a file, a file-name pattern with --per-record, or - for standard output, which a tool call returns as its result"
    ("--output", "-o")

    format: Annotated[Optional[str], Choice(*OUTPUT_FORMATS)] = None
    "How to write it. Omitted: from the ending of --output, json for -"
    ("--format",)

    per_record: bool = False
    "Write one file per record, --output being the name pattern ({index}, {timestamp}, {format}). Omitted: one growing file"
    ("--per-record",)

    max_files: int = 1000
    "With --per-record, the most files created; further records are counted and not written"
    ("--max-files",)

    datagrams: bool = False
    "Write each frame's UDP datagram, IP fragments reassembled, and pass over frames with none. Omitted: write the frames"
    ("--datagrams",)

    def _writer(self) -> CaptureWriter:
        """The writer ``--output`` and ``--format`` name; nothing is opened
        until the first record. Capture octets are never sent to a terminal."""
        name = self.format or ("json" if self.output == "-" else None)
        if self.output != "-":
            return self._built(self.output, name)
        if name in CAPTURE_FORMATS and sys.stdout.isatty():
            raise ValueError(
                "refusing to write a %s capture to a terminal: name a file with "
                "--output" % name
            )
        if not self.served():
            return self._built(sys.stdout.buffer, name)
        # A tool call replaces stdout with a text stream and returns what was
        # written to it as the result: records are ASCII text, a capture is not.
        if name in CAPTURE_FORMATS:
            raise ValueError(
                "a %s capture cannot be returned as text: name a file with --output"
                % name
            )
        return self._built(_TextSink(), name)

    def _built(self, target: object, name: Optional[str]) -> CaptureWriter:
        return CaptureWriter(
            target,  # type: ignore[arg-type]
            name,
            per_record=self.per_record,
            max_files=self.max_files,
        )

    def _report(
        self, result: CopyResult, stats: DissectStats, dissector: FrameDissector
    ) -> int:
        """The summary on stderr, because stdout may be the capture; status 1
        when the file budget turned records away."""
        parts = ["%d frames read" % result.read, "%d written" % result.written]
        if result.skipped:
            parts.append("%d skipped" % result.skipped)
        if result.refused:
            parts.append(
                "%d refused, %d files already (--max-files)"
                % (result.refused, self.max_files)
            )
        if stats.malformed:
            parts.append("%d malformed" % stats.malformed)
        if stats.unsupported:
            numbers = sorted(dissector.unsupported_linktypes)
            parts.append(
                "%d of an unsupported link type (%s%s)"
                % (
                    stats.unsupported,
                    ", ".join(str(n) for n in numbers[:_LISTED_LINKTYPES]),
                    ", ..." if len(numbers) > _LISTED_LINKTYPES else "",
                )
            )
        if self.quiet <= 0 or result.refused:
            print(", ".join(parts), file=sys.stderr)
        return 1 if result.refused else 0
