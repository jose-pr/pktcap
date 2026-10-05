"""Capturing live, on Linux, without a capture tool (internal).

An ``AF_PACKET`` socket: Linux only, and it needs ``CAP_NET_RAW`` (root, or a
process granted that capability). Everywhere else a capture tool is piped in
and read with :func:`pktcap.read_datagrams`::

    tcpdump -i eth0 -U -w - udp | your-program
    dumpcap -i Ethernet -w - -f udp | your-program
"""

from __future__ import annotations

import socket
import time
from types import TracebackType
from typing import Callable, Iterator, Optional, Tuple, Type

from netimps import Interface, InterfaceLike, get_interface

from ._captured import CapturedDatagram, CapturedFrame
from ._exceptions import LiveCaptureError
from ._frames import FrameDecoder

__all__ = ["LiveCapture", "has_live_capture", "sniff"]

#: Absent from the ``socket`` module on every platform but Linux.
_AF_PACKET: Optional[int] = getattr(socket, "AF_PACKET", None)
_ETH_P_ALL = 0x0003
_PACKET_OUTGOING = 4
_ARPHRD_LOOPBACK = 772
#: The protocol a cooked socket reports, to the link type of what it hands on.
_LINKTYPES = {0x0800: 228, 0x86DD: 229}
#: An IP packet is at most 65,535 octets; one more tells a longer read apart.
_READ_SIZE = 65536


def has_live_capture() -> bool:
    """Whether this platform can capture live: whether it has ``AF_PACKET``.

    It says nothing about permission: opening the socket still needs
    ``CAP_NET_RAW``.
    """
    return _AF_PACKET is not None


def _open_socket(name: Optional[str]) -> socket.socket:
    """A cooked packet socket on the named interface, or on all of them."""
    if _AF_PACKET is None:
        raise LiveCaptureError(
            "live capture needs Linux (AF_PACKET); pipe a capture tool's output "
            "to read_datagrams() here"
        )
    # SOCK_DGRAM is the cooked mode: the kernel removes the link-layer header
    # and reports the protocol, so every device type reads the same.
    sock = socket.socket(_AF_PACKET, socket.SOCK_DGRAM, socket.htons(_ETH_P_ALL))
    try:
        if name is not None:
            sock.bind((name, 0))
    except BaseException:
        sock.close()
        raise
    return sock


class LiveCapture:
    """A live capture of the IP packets on one interface, or on all of them.

    Linux only. A context manager: constructing one opens nothing; ``open()``
    or ``with`` opens the socket, which needs ``CAP_NET_RAW``. Each packet
    comes back as a :class:`CapturedFrame` of link type 228 (IPv4) or 229
    (IPv6), stamped with the time it was read, ready for a
    :class:`FrameDecoder`. On a loopback device, where every packet is seen
    leaving and arriving, only the arriving copy is returned.

    :param interface: the interface to capture on: a name, a
        :class:`netimps.Interface`, or anything ``netimps.get_interface``
        finds one by (an address, a MAC). ``None`` is every interface.
    :param timeout: how many seconds :meth:`read` waits for a packet.
    :raises ValueError: a ``timeout`` that is not positive.
    """

    def __init__(
        self, interface: InterfaceLike = None, *, timeout: float = 1.0
    ) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("timeout must be a number of seconds")
        if not timeout > 0:
            raise ValueError("timeout must be positive")
        self._interface = interface
        self._timeout = float(timeout)
        self._socket: Optional[socket.socket] = None
        self._closed = False

    def open(self) -> None:
        """Open the socket. Does nothing when it is already open.

        :raises LiveCaptureError: this platform has no ``AF_PACKET``.
        :raises PermissionError: the process lacks ``CAP_NET_RAW``.
        :raises ValueError: no interface matches ``interface``, or the capture
            was closed.
        :raises OSError: the kernel refused the interface.
        """
        if self._closed:
            raise ValueError("the capture is closed")
        if self._socket is not None:
            return
        name: Optional[str] = None
        if isinstance(self._interface, Interface):
            name = self._interface.name
        elif self._interface is not None:
            found = get_interface(self._interface)
            if found is None:
                raise ValueError("no interface matches %r" % (self._interface,))
            name = found.name
        self._socket = _open_socket(name)

    def read(self) -> Optional[CapturedFrame]:
        """The next IP packet, or ``None`` when ``timeout`` passes without one.

        :raises ValueError: the capture is not open.
        """
        sock = self._socket
        if sock is None:
            raise ValueError("the capture is not open")
        deadline = time.monotonic() + self._timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, address = sock.recvfrom(_READ_SIZE)
            except socket.timeout:  # not the builtin TimeoutError before 3.10
                return None
            frame = _frame(data, address, time.time())
            if frame is not None:
                return frame

    def fileno(self) -> int:
        """The socket's descriptor, for a caller's own event loop or selector.

        :raises ValueError: the capture is not open.
        """
        if self._socket is None:
            raise ValueError("the capture is not open")
        return self._socket.fileno()

    def close(self) -> None:
        """Close the socket. Final, and harmless when repeated."""
        self._closed = True
        sock, self._socket = self._socket, None
        if sock is not None:
            sock.close()

    def __iter__(self) -> Iterator[CapturedFrame]:
        """Frames until the capture is closed; a quiet interface is waited on."""
        while self._socket is not None:
            frame = self.read()
            if frame is not None:
                yield frame

    def __enter__(self) -> "LiveCapture":
        self.open()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()


def _frame(
    data: bytes, address: Tuple[object, ...], when: float
) -> Optional[CapturedFrame]:
    """What one read of a cooked packet socket is worth: the frame, or ``None``
    for a packet that is not IP or is the outgoing copy on loopback."""
    if len(address) < 4:
        return None
    protocol, kind, device = address[1], address[2], address[3]
    linktype = _LINKTYPES.get(protocol) if isinstance(protocol, int) else None
    if linktype is None:
        return None
    # The device type, never the name "lo": a loopback device can be renamed.
    if kind == _PACKET_OUTGOING and device == _ARPHRD_LOOPBACK:
        return None
    return CapturedFrame(when, linktype, data)


def sniff(
    interface: InterfaceLike = None,
    *,
    stop: Optional[Callable[[], bool]] = None,
    decoder: Optional[FrameDecoder] = None,
) -> Iterator[CapturedDatagram]:
    """UDP datagrams seen on ``interface``, as they arrive. Linux only.

    :class:`LiveCapture` and :class:`FrameDecoder` in one call. The socket is
    opened when the first datagram is asked for and closed when the iterator
    ends or is closed.

    :param interface: as for :class:`LiveCapture`; ``None`` is every one.
    :param stop: called between packets, and at least once a second on a
        quiet interface; returning true ends the iteration.
    :param decoder: the decoder to use; a new ``FrameDecoder()`` by default.
    :raises LiveCaptureError: when the first datagram is asked for, where the
        platform cannot capture; ask :func:`has_live_capture` beforehand.
    :raises PermissionError: at the same point, without ``CAP_NET_RAW``.
    """
    if stop is not None and not callable(stop):
        raise TypeError("stop must be callable")
    if decoder is None:
        decoder = FrameDecoder()
    elif not isinstance(decoder, FrameDecoder):
        raise TypeError("decoder must be a FrameDecoder")
    return _sniff(LiveCapture(interface), stop, decoder)


def _sniff(
    capture: LiveCapture, stop: Optional[Callable[[], bool]], decoder: FrameDecoder
) -> Iterator[CapturedDatagram]:
    with capture:
        while stop is None or not stop():
            frame = capture.read()
            if frame is not None:
                yield from decoder.decode(frame)
