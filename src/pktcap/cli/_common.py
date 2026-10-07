"""What the commands share: the filter, the output options and the summary line."""

from __future__ import annotations

import sys
from typing import Annotated, Callable, Generator, Iterable, List, Optional

from duho import Choice, Cmd, LoggingArgs

from .._copy import CopyResult
from .._dissect import DissectedFrame, DissectStats, FrameDissector
from .._filter import compile_capture_filter
from .._formats import CAPTURE_FORMATS, OUTPUT_FORMATS
from .._frame_filter import frame_filter
from .._output import CaptureWriter

__all__ = ["Base", "Writing", "counted", "error"]

#: Link-type numbers named in the summary before it says "and more".
_LISTED_LINKTYPES = 8


def error(text: str) -> None:
    """One diagnostic line on stderr; a control character in it is escaped."""
    safe = "".join(c if c.isprintable() else repr(c)[1:-1] for c in text)
    print("pktcap: error: %s" % safe, file=sys.stderr)


def counted(
    frames: Iterable[DissectedFrame], tally: List[int]
) -> Generator[DissectedFrame, None, None]:
    """``frames`` as they are, ``tally[0]`` counting each one taken, so a copy
    that ends by an exception still knows how far it got."""
    try:
        for frame in frames:
            tally[0] += 1
            yield frame
    finally:
        close = getattr(frames, "close", None)
        if close is not None:
            close()


class Base(LoggingArgs, Cmd):
    """The options every command has."""

    _logger_name_ = "pktcap"

    filter: Optional[str] = None
    "Keep only frames matching `key=value and key!=value` clauses over src, dst, host, sport, dport, port, proto, vlan, linktype. Omitted: every frame"
    ("--filter", "-f")

    def _select(self) -> Callable[[DissectedFrame], bool]:
        """The compiled ``--filter``; a bad expression is a usage error."""
        return compile_capture_filter(self.filter, frame_filter)


class Writing(Base):
    """The options of a command that writes what it reads."""

    output: str = "-"
    "Where to write: a file, a file-name pattern with --per-record, or - for standard output"
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
        return self._built(sys.stdout.buffer, name)

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
