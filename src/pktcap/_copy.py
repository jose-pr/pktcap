"""Copying frames into a writer (internal).

What a command that converts or captures does between its source and its
output, as one call a library user can make as well.
"""

from __future__ import annotations

from typing import Callable, Iterable, NamedTuple, Optional

from ._dissect import DissectedFrame
from ._output import CaptureWriter

__all__ = ["CopyResult", "copy_frames"]


class CopyResult(NamedTuple):
    """What :func:`copy_frames` did.

    :ivar read: items taken from the source.
    :ivar written: items the writer wrote.
    :ivar skipped: items ``select`` refused, or that had no datagram when
        ``datagrams`` was asked for.
    :ivar refused: items the writer turned away for its file budget during
        this call.
    """

    read: int
    written: int
    skipped: int
    refused: int


def copy_frames(
    frames: Iterable[DissectedFrame],
    writer: CaptureWriter,
    *,
    select: Optional[Callable[[DissectedFrame], bool]] = None,
    datagrams: bool = False,
    limit: Optional[int] = None,
) -> CopyResult:
    """Write the frames ``select`` accepts to ``writer``, in order.

    ``frames`` is any iterable of :class:`DissectedFrame`: a file through
    :func:`read_dissected`, a live source through :func:`sniff_frames`. The
    writer is the caller's: it is neither opened nor closed here.

    :param select: a predicate over a frame, such as
        ``compile_capture_filter(text, frame_filter)``; ``None`` accepts all.
    :param datagrams: write each frame's UDP datagram (reassembled) and skip
        a frame that has none, instead of the frame.
    :param limit: stop once this many items are written; the source is not
        read past that. A refused item does not count.
    :raises TypeError: ``writer`` is not a :class:`CaptureWriter`, ``select``
        is not callable, ``limit`` is not an ``int``, or ``frames`` yields
        something that is not a :class:`DissectedFrame`.
    :raises ValueError: ``limit`` is below zero.
    :raises OSError: the writer could not write. What was written before it
        stays written; the counts of the call are lost with the exception, so
        read ``writer.written`` for them.
    """
    if not isinstance(writer, CaptureWriter):
        raise TypeError("writer must be a CaptureWriter")
    if select is not None and not callable(select):
        raise TypeError("select must be callable")
    if limit is not None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an int")
        if limit < 0:
            raise ValueError("limit must not be below zero")
    source = iter(frames)
    read = written = skipped = refused = 0
    while limit is None or written < limit:
        try:
            frame = next(source)
        except StopIteration:
            break
        if not isinstance(frame, DissectedFrame):
            raise TypeError("frames must yield DissectedFrame values")
        read += 1
        if select is not None and not select(frame):
            skipped += 1
            continue
        item = frame.datagram() if datagrams else frame
        if item is None:
            skipped += 1
            continue
        turned_away = writer.refused
        writer.write(item)
        if writer.refused > turned_away:
            refused += 1
        else:
            written += 1
    return CopyResult(read, written, skipped, refused)
