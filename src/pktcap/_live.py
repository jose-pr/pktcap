"""Capturing live, on Linux, without a capture tool (internal).

An ``AF_PACKET`` socket: Linux only, and it needs ``CAP_NET_RAW`` (root, or a
process granted that capability). Everywhere else a capture tool is piped in
and read with :func:`pktcap.read_frames`::

    tcpdump -i eth0 -U -w - | your-program
    dumpcap -i Ethernet -w - | your-program

Receiving only: nothing here sends a frame.
"""

from __future__ import annotations

import socket
import struct
import time
from types import TracebackType
from typing import Callable, Dict, Iterator, Optional, Tuple, Type

from netimps import Interface, InterfaceLike, get_interface

from ._captured import CapturedDatagram, CapturedFrame
from ._dissect import FrameDissector
from ._exceptions import LiveCaptureError

__all__ = ["LiveCapture", "has_live_capture", "sniff"]

#: Absent from the ``socket`` module on every platform but Linux.
_AF_PACKET: Optional[int] = getattr(socket, "AF_PACKET", None)
_ETH_P_ALL = 0x0003
_PACKET_OUTGOING = 4
_ARPHRD_LOOPBACK = 772
_LINKTYPE_LINUX_SLL2 = 276
#: The largest frame asked of the socket: an IP packet is at most 65,535
#: octets, and a cooked socket hands back nothing below it.
_READ_SIZE = 65536
#: Interface names remembered with their index, before the table is emptied.
_MAX_INDEX_CACHE = 1024


def has_live_capture() -> bool:
    """Whether this platform can capture live: whether it has ``AF_PACKET``.

    It says nothing about permission: opening the socket still needs
    ``CAP_NET_RAW``.
    """
    return _AF_PACKET is not None


def _packet_family() -> int:
    """``AF_PACKET``; ``LiveCaptureError`` where the platform has none."""
    if _AF_PACKET is None:
        raise LiveCaptureError(
            "live capture needs Linux (AF_PACKET); pipe a capture tool's output "
            "to read_frames() here"
        )
    return _AF_PACKET


def _open_socket(name: Optional[str]) -> socket.socket:
    """A cooked packet socket on the named interface, or on all of them."""
    family = _packet_family()
    # SOCK_DGRAM is the cooked mode: the kernel removes the link-layer header
    # and reports the protocol, so every device type reads the same.
    sock = socket.socket(family, socket.SOCK_DGRAM, socket.htons(_ETH_P_ALL))
    try:
        if name is not None:
            sock.bind((name, 0))
    except BaseException:
        sock.close()
        raise
    return sock


class LiveCapture:
    """A live capture of every packet on one interface, or on all of them.

    Linux only. A context manager: constructing one opens nothing; ``open()``
    or ``with`` opens the socket, which needs ``CAP_NET_RAW``. Each packet
    comes back as a :class:`CapturedFrame` of link type 276 (Linux cooked
    capture v2, what tcpdump writes for its ``any`` device), stamped with the
    time it was read: ready for a :class:`FrameDissector`, and for a writer,
    whose output tcpdump and Wireshark read. On a loopback device, where every
    packet is seen leaving and arriving, only the arriving copy is returned.

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
        self._indexes: Dict[str, int] = {}

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
        # Before the interface is looked up: a platform with no capture says so
        # whatever name was given.
        _packet_family()
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
        """The next packet, or ``None`` when ``timeout`` passes without one.

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
            frame = self._frame(data, address, time.time())
            if frame is not None:
                return frame

    def _frame(
        self, data: bytes, address: Tuple[object, ...], when: float
    ) -> Optional[CapturedFrame]:
        """One read of a cooked packet socket as a cooked-capture frame:
        ``None`` for the outgoing copy of a packet on a loopback device."""
        if len(address) < 5:
            return None
        name, protocol, kind, device, sender = address[:5]
        if not (
            isinstance(protocol, int)
            and isinstance(kind, int)
            and isinstance(device, int)
            and isinstance(sender, bytes)
        ):
            return None
        # The device type, never the name "lo": a loopback device can be renamed.
        if kind == _PACKET_OUTGOING and device == _ARPHRD_LOOPBACK:
            return None
        index = self._index(name) if isinstance(name, str) else 0
        header = struct.pack(
            "!HHIHBB8s",
            protocol & 0xFFFF,
            0,
            index,
            device & 0xFFFF,
            kind & 0xFF,
            min(len(sender), 8),
            sender[:8],
        )
        return CapturedFrame(when, _LINKTYPE_LINUX_SLL2, header + data, index)

    def _index(self, name: str) -> int:
        index = self._indexes.get(name)
        if index is None:
            # Enumerating the interfaces is a system call: once for each name.
            found = get_interface(name)
            # An interface that has gone since the packet arrived has no index.
            index = found.index if found is not None and found.index else 0
            if len(self._indexes) >= _MAX_INDEX_CACHE:
                self._indexes.clear()
            self._indexes[name] = index
        return index

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


def sniff(
    interface: InterfaceLike = None,
    *,
    stop: Optional[Callable[[], bool]] = None,
    dissector: Optional[FrameDissector] = None,
) -> Iterator[CapturedDatagram]:
    """UDP datagrams seen on ``interface``, as they arrive. Linux only.

    :class:`LiveCapture`, :class:`FrameDissector` and the datagram view in one
    call, for a UDP protocol library; for every packet, iterate a
    :class:`LiveCapture`. The socket is opened when the first datagram is
    asked for and closed when the iterator ends or is closed.

    :param interface: as for :class:`LiveCapture`; ``None`` is every one.
    :param stop: called between packets, and at least once a second on a
        quiet interface; returning true ends the iteration.
    :param dissector: the frame dissector to use; a new ``FrameDissector()``
        by default.
    :raises LiveCaptureError: when the first datagram is asked for, where the
        platform cannot capture; ask :func:`has_live_capture` beforehand.
    :raises PermissionError: at the same point, without ``CAP_NET_RAW``.
    """
    if stop is not None and not callable(stop):
        raise TypeError("stop must be callable")
    if dissector is None:
        dissector = FrameDissector()
    elif not isinstance(dissector, FrameDissector):
        raise TypeError("dissector must be a FrameDissector")
    return _sniff(LiveCapture(interface), stop, dissector)


def _sniff(
    capture: LiveCapture, stop: Optional[Callable[[], bool]], dissector: FrameDissector
) -> Iterator[CapturedDatagram]:
    with capture:
        while stop is None or not stop():
            frame = capture.read()
            if frame is not None:
                datagram = dissector.dissect(frame).datagram()
                if datagram is not None:
                    yield datagram
