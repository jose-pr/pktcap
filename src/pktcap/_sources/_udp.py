"""A UDP socket as a capture source (internal).

Binding a port and reading what arrives needs no privilege and works where
live capture does not. Each datagram becomes the raw-IP frame
:func:`datagram_frame` builds, so the dissectors, the filter and the writers
treat it as any captured frame. What a socket never sees is not here: other
hosts' traffic, the link layer, the real IP header (it is made up) and IP
fragments, which the kernel has put together already.
"""

from __future__ import annotations

import itertools
import selectors
import socket
import time
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Iterable,
    Iterator,
    List,
    Optional,
    Type,
)

from netimps import Datagram, UDPEndpoint

from .._captured import CapturedDatagram, CapturedFrame
from .._writer import datagram_frame

if TYPE_CHECKING:
    import asyncio

__all__ = ["MAX_ENDPOINTS", "UDPCapture"]

#: Endpoints one capture reads: the number a command line or a caller names,
#: and below the descriptor limit of ``select`` on every platform.
MAX_ENDPOINTS = 256
#: The largest UDP payload a socket can deliver is 65,507 octets; the
#: datagram of a larger IPv6 jumbogram does not fit a 16-bit length either.
_MAX_SIZE = 65535
#: Frames the asynchronous readers hold between them and a slow consumer.
#: Each reader holds one datagram more, so the memory is bounded by about
#: ``(_QUEUE + endpoints) * (max_size + 1)`` octets; the kernel drops the rest.
_QUEUE = 64


def _number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("%s must be a number" % name)
    return float(value)


class UDPCapture:
    """Datagrams arriving at sockets the caller bound, read as raw-IP frames.

    The twin of :class:`LiveCapture` on every platform and with no privilege.
    The frames have link type 101 and a made-up IP header: the addresses are
    the sender's and the receiver's as the socket reports them (the
    destination is the address the datagram was sent to when the host says so,
    else the address the socket is bound to, which may be a wildcard), the
    time is when it was read and ``interface`` the arrival interface when the
    host reports one. The capture owns the endpoints from construction: it
    closes them, once, in :meth:`close`. Not safe to share between threads.

    :param endpoints: bound :class:`netimps.UDPEndpoint` objects, at most 256.
        An endpoint limited to interfaces (``UDPEndpoint(interfaces=)``) is
        asked about every datagram: one it does not admit is counted in
        :attr:`not_admitted` and dropped before a frame is built.
    :param timeout: how many seconds :meth:`read` waits for a datagram.
    :param max_size: the largest payload returned; a bigger datagram is
        counted in :attr:`truncated` and dropped, since what a socket returns
        of it is only its start.
    :raises TypeError: an endpoint that is not a ``UDPEndpoint``, or an option
        of the wrong type. The endpoints are then still the caller's.
    :raises ValueError: no endpoint, more than 256, an endpoint given twice, a
        ``timeout`` that is not positive or a ``max_size`` outside 1 to 65535.
    """

    def __init__(
        self,
        endpoints: Iterable[UDPEndpoint],
        *,
        timeout: float = 1.0,
        max_size: int = _MAX_SIZE,
    ) -> None:
        held = tuple(itertools.islice(endpoints, MAX_ENDPOINTS + 1))
        if not held:
            raise ValueError("a UDP capture needs at least one endpoint")
        if len(held) > MAX_ENDPOINTS:
            raise ValueError("a UDP capture reads at most %d endpoints" % MAX_ENDPOINTS)
        for endpoint in held:
            if not isinstance(endpoint, UDPEndpoint):
                raise TypeError("endpoints must be netimps.UDPEndpoint objects")
        if len({id(endpoint.socket) for endpoint in held}) != len(held):
            raise ValueError("an endpoint is given twice")
        if not _number(timeout, "timeout") > 0:
            raise ValueError("timeout must be positive")
        if isinstance(max_size, bool) or not isinstance(max_size, int):
            raise TypeError("max_size must be an int")
        if not 1 <= max_size <= _MAX_SIZE:
            raise ValueError("max_size must be from 1 to %d" % _MAX_SIZE)
        self._endpoints = held
        self._timeout = float(timeout)
        self._max_size = max_size
        self._closed = False
        self._cursor = 0
        self._selector: Optional[selectors.BaseSelector] = None
        self._queue: Optional["asyncio.Queue[object]"] = None
        self._readers: List["asyncio.Future[None]"] = []
        #: Datagrams over ``max_size`` (or that no frame can hold), read and
        #: dropped.
        self.truncated = 0
        #: Datagrams an endpoint does not admit (``UDPEndpoint.admits``: they
        #: arrived on an interface it does not serve), read and dropped.
        self.not_admitted = 0

    def _frame(
        self, endpoint: UDPEndpoint, datagram: Datagram
    ) -> Optional[CapturedFrame]:
        """The frame of one received datagram; ``None`` and counted when its
        endpoint does not admit it, or when it is too big, which a read of
        ``max_size + 1`` octets tells. The length, not the receive flag,
        decides: the flag is wrong on some paths."""
        if not endpoint.admits(datagram):
            self.not_admitted += 1
            return None
        if len(datagram.data) > self._max_size:
            self.truncated += 1
            return None
        local = endpoint.socket.getsockname()
        destination = datagram.destination
        host = str(destination) if destination is not None else local[0]
        try:
            return datagram_frame(
                CapturedDatagram(
                    time.time(),
                    (datagram.sender[0], datagram.sender[1]),
                    (host, local[1]),
                    datagram.data,
                ),
                interface=datagram.interface_index or None,
            )
        except ValueError:
            self.truncated += 1
            return None

    # -- blocking ---------------------------------------------------------

    def _select(self, wait: float) -> List[UDPEndpoint]:
        """The endpoints holding a datagram, the one after the last served
        first, so a busy endpoint does not starve the others."""
        if self._selector is None:
            self._selector = selectors.DefaultSelector()
            for endpoint in self._endpoints:
                self._selector.register(endpoint.socket, selectors.EVENT_READ, endpoint)
        ready = [key.data for key, _ in self._selector.select(wait)]
        ready.sort(
            key=lambda e: (self._endpoints.index(e) - self._cursor)
            % len(self._endpoints)
        )
        return ready

    def _receive(self, endpoint: UDPEndpoint) -> Optional[Datagram]:
        """One datagram from a socket reported readable, without ever waiting:
        a wake-up with nothing to read (a datagram dropped for its checksum)
        must not hold the capture. The socket's own timeout is restored."""
        sock = endpoint.socket
        previous = sock.gettimeout()
        sock.settimeout(0.0)
        try:
            return endpoint.recv(self._max_size + 1, resolve_interface=False)
        except (BlockingIOError, TimeoutError, socket.timeout):
            return None
        finally:
            try:
                sock.settimeout(previous)
            except OSError:  # closed while receiving
                pass

    def read(self) -> Optional[CapturedFrame]:
        """The next frame, or ``None`` when ``timeout`` seconds pass without
        one. A datagram over ``max_size`` is counted and skipped.

        :raises ValueError: the capture is closed.
        :raises OSError: a socket failed.
        """
        if self._closed:
            raise ValueError("the capture is closed")
        deadline = time.monotonic() + self._timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            for endpoint in self._select(remaining):
                datagram = self._receive(endpoint)
                if datagram is None:
                    continue
                self._cursor = (self._endpoints.index(endpoint) + 1) % len(
                    self._endpoints
                )
                frame = self._frame(endpoint, datagram)
                if frame is not None:
                    return frame
                break

    def __iter__(self) -> Iterator[CapturedFrame]:
        """Frames until the capture is closed; a quiet socket is waited on."""
        while not self._closed:
            frame = self.read()
            if frame is not None:
                yield frame

    # -- asynchronous -----------------------------------------------------

    async def aread(self) -> Optional[CapturedFrame]:
        """:meth:`read`, awaited: one task for each endpoint feeds a bounded
        queue, started by the first call, and the next frame is taken from it.

        Use one event loop for a capture's life, and :meth:`aclose` from a
        coroutine. Do not mix it with :meth:`read`.

        :raises ValueError: the capture is closed.
        :raises OSError: a socket failed.
        """
        import asyncio

        if self._closed:
            raise ValueError("the capture is closed")
        if self._queue is None:
            queue: "asyncio.Queue[object]" = asyncio.Queue(_QUEUE)
            self._queue = queue
            self._readers = [
                asyncio.ensure_future(self._pump(endpoint, queue))
                for endpoint in self._endpoints
            ]
        item = await self._next(self._queue)
        if isinstance(item, BaseException):
            raise item
        return item if isinstance(item, CapturedFrame) else None

    async def _next(self, queue: "asyncio.Queue[object]") -> object:
        """The next item of the queue, or ``None`` after ``timeout``. Nothing
        taken from the queue is lost to the timeout."""
        import asyncio

        if not queue.empty():
            return queue.get_nowait()
        getter = asyncio.ensure_future(queue.get())
        try:
            done, _ = await asyncio.wait({getter}, timeout=self._timeout)
        except BaseException:
            getter.cancel()
            raise
        if getter in done:
            return getter.result()
        if not getter.cancel():  # it finished as the wait ended
            return getter.result()
        return None

    async def _pump(
        self, endpoint: UDPEndpoint, queue: "asyncio.Queue[object]"
    ) -> None:
        try:
            while True:
                datagram = await endpoint.arecv(
                    self._max_size + 1, resolve_interface=False
                )
                frame = self._frame(endpoint, datagram)
                if frame is not None:
                    await queue.put(frame)
        except Exception as exc:  # BaseException (a cancel) ends the task as it is
            if not self._closed:
                await queue.put(exc)

    def _stop_readers(self) -> List["asyncio.Future[None]"]:
        readers, self._readers = self._readers, []
        for reader in readers:
            try:
                reader.cancel()
            except RuntimeError:  # the loop is gone, and the task with it
                pass
        return readers

    # -- closing ----------------------------------------------------------

    def close(self) -> None:
        """Close every endpoint. Final, and harmless when repeated.

        From a coroutine use :meth:`aclose`: this waits for netimps' reader
        thread, if the asynchronous read started one.
        """
        self._closed = True
        self._stop_readers()
        selector, self._selector = self._selector, None
        if selector is not None:
            selector.close()
        for endpoint in self._endpoints:
            endpoint.close()

    async def aclose(self) -> None:
        """:meth:`close`, awaited: the readers are cancelled and have left, and
        the endpoints are closed, when it returns. Harmless when repeated."""
        import asyncio

        self._closed = True
        try:
            readers = self._stop_readers()
            if readers:
                await asyncio.gather(*readers, return_exceptions=True)
            for endpoint in self._endpoints:
                await endpoint.aclose()
        finally:
            self.close()

    def __enter__(self) -> "UDPCapture":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()
