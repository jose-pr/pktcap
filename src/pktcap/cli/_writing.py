"""The options of a command that writes what it reads, and the one loop."""

from __future__ import annotations

import sys
from typing import (
    Annotated,
    Callable,
    ClassVar,
    Iterator,
    List,
    Mapping,
    Optional,
    Tuple,
)

from duho import Choice

from .._copy import CopyResult, copy_frames
from .._dissect import DissectedFrame, FrameDissector
from .._exceptions import UnsupportedFormatError
from .._formats import CAPTURE_FORMATS, OUTPUT_FORMATS, infer_format
from .._output import CaptureWriter
from ._common import Counted, Selecting
from ._line import TextSink, summary_parts

__all__ = ["Writing"]


class Writing(Selecting):
    """The options of a command that writes what it reads, and the loop that
    does it: ``_frames`` is the source, the writer is ``--output``."""

    #: Pattern fields beyond ``timestamp``, ``index`` and ``format`` that
    #: ``_names`` supplies for ``--per-record``.
    _fields_: ClassVar[Tuple[str, ...]] = ()
    #: Whether Ctrl-C ends the run with the summary and status 0.
    _interruptible_: ClassVar[bool] = False
    #: The format used when neither ``--format`` nor the ending of ``--output``
    #: names one; ``None`` is ``json``.
    _format_: ClassVar[Optional[str]] = None

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

    append: bool = False
    "Add to a record file that exists instead of replacing it; a capture format cannot be appended to. Omitted: replace"
    ("--append",)

    # -- the points a subclass overrides ---------------------------------

    def _frames(self, dissector: FrameDissector) -> Iterator[DissectedFrame]:
        """The dissected frames to copy: the command's source. Called once,
        after the filter compiled and the writer was made, so a bad
        expression or output fails before anything is opened. The loop closes
        the iterator."""
        raise NotImplementedError("a command that writes names its source")

    def _names(self, frame: DissectedFrame) -> Mapping[str, object]:
        """The values of ``_fields_`` for a frame the filter kept; the same
        values reach a hook's environment."""
        return {}

    def _limit(self) -> Optional[int]:
        """The most items to write; ``None`` for all."""
        return None

    def _hook(self) -> Optional[Callable[[DissectedFrame], object]]:
        """What is called with each frame after it is written; ``None`` for
        nothing."""
        return None

    def _report(self, result: CopyResult, dissector: FrameDissector) -> int:
        """The summary on stderr, because stdout may be the capture; status 1
        when the file budget turned records away. Runs once, after Ctrl-C in
        a command that is ``_interruptible_`` as well."""
        parts = summary_parts(result, dissector, self.max_files)
        parts.extend(self._noted())
        if self.quiet <= 0 or result.refused:
            print(", ".join(parts), file=sys.stderr)
        return 1 if result.refused else 0

    # -- the loop ---------------------------------------------------------

    def _noted(self) -> List[str]:
        """Parts a command adds to the summary line."""
        return []

    def _chosen(self) -> Optional[str]:
        """The format name to give the writer: ``--format``, else, for
        standard output, ``_format_`` or json, else, for a file whose ending
        names none, ``_format_``. ``None`` leaves a file's ending to decide."""
        if self.format:
            return self.format
        if self.output == "-":
            return self._format_ or "json"
        try:
            infer_format(self.output, None)
        except UnsupportedFormatError:
            return self._format_
        return None

    def _writer(self) -> CaptureWriter:
        """The writer ``--output`` and ``--format`` name; nothing is opened
        until the first record. Capture octets are never sent to a terminal."""
        name = self._chosen()
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
        return self._built(TextSink(), name)

    def _built(self, target: object, name: Optional[str]) -> CaptureWriter:
        return CaptureWriter(
            target,  # type: ignore[arg-type]
            name,
            per_record=self.per_record,
            append=self.append,
            fields=self._fields_,
            max_files=self.max_files,
        )

    def __call__(self) -> Optional[int]:
        registry = self._registry()
        select = self._select(registry)
        dissector = FrameDissector(registry)
        hook = self._hook()
        with self._writer() as writer:
            self._open = writer
            frames = Counted(self._frames(dissector))
            before = writer.written
            try:
                result = copy_frames(
                    frames,
                    writer,
                    select=select,
                    datagrams=self.datagrams,
                    limit=self._limit(),
                    names=self._names,
                    each=hook,
                )
            except KeyboardInterrupt:
                if not self._interruptible_:
                    raise
                # The copy's own counts are lost with the exception; the
                # tally and the writer say how far it got.
                written = writer.written - before
                result = CopyResult(
                    frames.count,
                    written,
                    frames.count - written - writer.refused,
                    writer.refused,
                )
            finally:
                frames.close()
        return self._report(result, dissector)
