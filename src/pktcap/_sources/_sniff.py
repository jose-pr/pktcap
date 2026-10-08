"""The iterators over a :class:`UDPCapture` (internal)."""

from __future__ import annotations

from typing import AsyncIterator, Callable, Iterable, Iterator, Optional

from netimps import UDPEndpoint

from .._dissect import DissectedFrame, FrameDissector
from .._live import _checked
from ._udp import UDPCapture

__all__ = ["asniff_udp", "sniff_udp"]


class _Frames:
    """The dissected frames of a :class:`UDPCapture`: an iterator that closes
    the capture when it ends, fails, is closed or is dropped, started or not."""

    def __init__(
        self,
        capture: UDPCapture,
        stop: Optional[Callable[[], bool]],
        dissector: FrameDissector,
    ) -> None:
        self._capture = capture
        self._stop = stop
        self._dissector = dissector
        self._done = False

    def __iter__(self) -> "_Frames":
        return self

    def __next__(self) -> DissectedFrame:
        try:
            while not self._done:
                if self._stop is not None and self._stop():
                    break
                frame = self._capture.read()
                if frame is not None:
                    return self._dissector.dissect(frame)
        except BaseException:
            self.close()
            raise
        self.close()
        raise StopIteration

    def close(self) -> None:
        """End the iteration and close the sockets. Harmless when repeated."""
        self._done = True
        self._capture.close()

    def __del__(self) -> None:
        capture = getattr(self, "_capture", None)
        if capture is not None:
            capture.close()


class _AsyncFrames:
    """The asynchronous twin of :class:`_Frames`."""

    def __init__(self, capture: UDPCapture, dissector: FrameDissector) -> None:
        self._capture = capture
        self._dissector = dissector
        self._done = False

    def __aiter__(self) -> "_AsyncFrames":
        return self

    async def __anext__(self) -> DissectedFrame:
        try:
            while not self._done:
                frame = await self._capture.aread()
                if frame is not None:
                    return self._dissector.dissect(frame)
        except BaseException:  # a cancel included: the sockets go with the task
            await self.aclose()
            raise
        await self.aclose()
        raise StopAsyncIteration

    async def aclose(self) -> None:
        """End the iteration; every task has left and every socket is closed
        when it returns. Harmless when repeated."""
        self._done = True
        await self._capture.aclose()

    def __del__(self) -> None:
        capture = getattr(self, "_capture", None)
        if capture is not None:
            capture.close()


def sniff_udp(
    endpoints: Iterable[UDPEndpoint],
    *,
    stop: Optional[Callable[[], bool]] = None,
    dissector: Optional[FrameDissector] = None,
) -> Iterator[DissectedFrame]:
    """Every datagram that reaches the endpoints, as a dissected raw-IP frame.

    :class:`UDPCapture` and a :class:`FrameDissector` in one call, as
    :func:`sniff_frames` is for an interface. The endpoints are the iterator's
    from the call: it closes them when it ends, fails, is closed or is
    dropped. ``stop()`` is called between datagrams, and at least once a
    second on a quiet socket; returning true ends the iteration.

    :raises TypeError: ``stop`` is not callable, ``dissector`` is not a
        :class:`FrameDissector`, or an item of ``endpoints`` is not a
        :class:`netimps.UDPEndpoint`; the endpoints are then still the caller's.
    :raises ValueError: no endpoint, or more than 256.
    :raises OSError: a socket failed, while iterating.
    """
    checked = _checked(stop, dissector)
    return _Frames(UDPCapture(endpoints), stop, checked)


def asniff_udp(
    endpoints: Iterable[UDPEndpoint], *, dissector: Optional[FrameDissector] = None
) -> AsyncIterator[DissectedFrame]:
    """:func:`sniff_udp` for an event loop, on ``UDPEndpoint.arecv``.

    One task for each endpoint feeds one bounded queue. When the iterator
    ends, fails, is cancelled or its ``aclose()`` is awaited, every task has
    been cancelled and every socket closed; ``aclose()`` is what a loop that
    stops early (``break``) awaits. Python imports ``asyncio`` only when the
    first frame is asked for.

    :raises TypeError: ``dissector`` is not a :class:`FrameDissector`, or an
        item of ``endpoints`` is not a :class:`netimps.UDPEndpoint`.
    :raises ValueError: no endpoint, or more than 256.
    :raises OSError: a socket failed, while iterating.
    """
    checked = _checked(None, dissector)
    return _AsyncFrames(UDPCapture(endpoints), checked)
