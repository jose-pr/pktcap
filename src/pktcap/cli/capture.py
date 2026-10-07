"""``pktcap capture``: frames seen live on Linux, written as they arrive."""

from __future__ import annotations

import time
from typing import List, Optional

from .._copy import CopyResult, copy_frames
from .._dissect import FrameDissector
from .._exceptions import LiveCaptureError
from .._live import has_live_capture, sniff_frames
from ._common import Writing, counted

__all__ = ["Capture"]

_NOT_LINUX = (
    "live capture needs Linux (AF_PACKET); pipe a capture tool's output in "
    "instead: tcpdump -w - | pktcap convert --input -"
)
_NO_PERMISSION = (
    "opening a packet socket needs the CAP_NET_RAW capability: run as root, or "
    "grant it to the interpreter (setcap cap_net_raw+ep)"
)


class Capture(Writing):
    """Capture frames live from an interface (Linux, needs CAP_NET_RAW) and write them; Ctrl-C ends it with status 0. It sends nothing."""

    _parsername_ = "capture"

    interface: Optional[str] = None
    "The interface to capture on, by name, address or MAC. Omitted: every interface"
    ("--interface",)

    count: Optional[int] = None
    "Stop once this many records are written. Omitted: run until stopped"
    ("--count", "-c")

    duration: Optional[float] = None
    "Stop after this many seconds, within a second of it. Omitted: run until stopped"
    ("--duration", "-d")

    def _deadline(self) -> Optional[float]:
        if self.duration is None:
            return None
        if not self.duration >= 0:
            raise ValueError("--duration must not be below zero")
        return time.monotonic() + self.duration

    def __call__(self) -> Optional[int]:
        if not has_live_capture():
            raise LiveCaptureError(_NOT_LINUX)
        select = self._select()
        deadline = self._deadline()
        dissector = FrameDissector()
        tally: List[int] = [0]
        frames = counted(
            sniff_frames(
                self.interface,
                stop=None if deadline is None else lambda: time.monotonic() >= deadline,
                dissector=dissector,
            ),
            tally,
        )
        with self._writer() as writer:
            before = writer.written
            try:
                result = copy_frames(
                    frames,
                    writer,
                    select=select,
                    datagrams=self.datagrams,
                    limit=self.count,
                )
            except PermissionError:
                raise PermissionError(_NO_PERMISSION) from None
            except KeyboardInterrupt:
                # The copy's own counts are lost with the exception; the tally
                # and the writer say how far it got.
                written = writer.written - before
                result = CopyResult(
                    tally[0],
                    written,
                    tally[0] - written - writer.refused,
                    writer.refused,
                )
            finally:
                frames.close()
        return self._report(result, dissector.stats, dissector)
