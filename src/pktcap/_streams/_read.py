"""Reading TCP streams from a capture in one call (internal)."""

from __future__ import annotations

from typing import Iterator, Optional

from .._container import CaptureSource
from .._dissect import DissectedFrame, FrameDissector, read_dissected
from .._exceptions import CaptureFormatError
from ._tcp import TCPReassembler
from ._types import TCPStreamData

__all__ = ["read_tcp_streams"]


def read_tcp_streams(
    source: CaptureSource,
    *,
    reassembler: Optional[TCPReassembler] = None,
    dissector: Optional[FrameDissector] = None,
    max_frame_size: int = 262144,
) -> Iterator[TCPStreamData]:
    """The TCP streams of a pcap or pcapng capture, in the order they become
    deliverable.

    :func:`read_dissected` through :meth:`TCPReassembler.add`, then
    :meth:`TCPReassembler.flush` when the capture ends. Nothing is read
    before the first item is asked for, and a caller that stops early leaves
    the rest unread. A damaged container gives every item the frames before
    the damage made deliverable and what was still held, then raises.

    :param source: a path, or a binary stream, which need not be seekable.
    :param reassembler: the reassembler to use, for its options and its
        :attr:`~TCPReassembler.stats`; a new ``TCPReassembler()`` by default.
    :param dissector: the frame dissector to use, as for
        :func:`read_dissected`.
    :param max_frame_size: as for :func:`read_frames`.
    :raises TypeError: a ``reassembler`` or ``dissector`` of the wrong type,
        before anything is read.
    :raises CaptureFormatError: the container is not a capture or is damaged.
    """
    if reassembler is None:
        reassembler = TCPReassembler()
    elif not isinstance(reassembler, TCPReassembler):
        raise TypeError("reassembler must be a TCPReassembler")
    frames = read_dissected(source, dissector=dissector, max_frame_size=max_frame_size)
    return _streams(frames, reassembler)


def _streams(
    frames: Iterator[DissectedFrame], reassembler: TCPReassembler
) -> Iterator[TCPStreamData]:
    try:
        for frame in frames:
            yield from reassembler.add(frame)
    except CaptureFormatError:
        yield from reassembler.flush()
        raise
    yield from reassembler.flush()
