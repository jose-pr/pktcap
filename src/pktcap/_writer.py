"""Writing captures: pcap and pcapng (internal).

A captured frame is written back as it is, with its link type. A UDP datagram
seen at a socket has no link or IP header left, so it is written under
synthesised IPv4 or IPv6 and UDP headers, their checksums valid, as raw IP
(link type 101): tcpdump and Wireshark then decode the payload as the protocol
on that port.

The layouts are those of draft-ietf-opsawg-pcap and draft-ietf-opsawg-pcapng.
"""

from __future__ import annotations

import math
import os
import struct
from types import TracebackType
from typing import BinaryIO, Dict, Optional, Tuple, Type, TypeVar, Union

from netimps import IPAddress, SocketAddress, split_zone, unmap

from ._captured import CapturedDatagram, CapturedFrame

__all__ = ["PcapWriter", "PcapngWriter"]

_Self = TypeVar("_Self", bound="_CaptureFileWriter")

_LINKTYPE_RAW = 101
#: libpcap's MAXIMUM_SNAPLEN: the most octets of one frame a reader accepts.
_SNAPLEN = 262144
_MAX_IPV4_PAYLOAD = 65535 - 20 - 8
_MAX_IPV6_PAYLOAD = 65535 - 8
_MAX_SECONDS = 1 << 32
_MAPPED = bytes(10) + b"\xff\xff"


def _checksum(data: bytes) -> int:
    """The Internet checksum (RFC 1071) of ``data``."""
    if len(data) % 2:
        data += b"\0"
    total: int = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _endpoint(address: SocketAddress, what: str) -> Tuple[IPAddress, int]:
    if not isinstance(address, tuple) or len(address) < 2:
        raise TypeError("%s must be a (host, port) socket address" % what)
    host, port = address[0], address[1]
    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError("%s port must be an int" % what)
    if not 0 <= port <= 65535:
        raise ValueError("%s port %d is outside 0-65535" % (what, port))
    if not isinstance(host, str):
        raise TypeError("%s host must be address text" % what)
    # A scoped address carries its zone in the text; the wire does not.
    return unmap(split_zone(host)[0]), port


def _stamp(time: float) -> Tuple[int, int]:
    """``time`` as whole seconds and microseconds, both in range."""
    if isinstance(time, bool) or not isinstance(time, (int, float)):
        raise TypeError("time must be a number of seconds")
    if not (math.isfinite(time) and 0 <= time < _MAX_SECONDS):
        raise ValueError("time is outside what a capture record can hold")
    seconds = int(time)
    micros = int(round((time - seconds) * 1e6))
    if micros >= 1_000_000:
        if seconds + 1 < _MAX_SECONDS:
            seconds, micros = seconds + 1, 0
        else:  # the last microsecond a 32-bit count of seconds can hold
            micros = 999_999
    return seconds, micros


def _ip_packet(
    source: SocketAddress, destination: SocketAddress, payload: bytes, ident: int
) -> bytes:
    """The datagram under the IP and UDP headers it never had at a socket."""
    src, sport = _endpoint(source, "source")
    dst, dport = _endpoint(destination, "destination")
    data = bytes(payload)
    both_v4 = src.version == 4 and dst.version == 4
    limit = _MAX_IPV4_PAYLOAD if both_v4 else _MAX_IPV6_PAYLOAD
    if len(data) > limit:
        raise ValueError(
            "a payload of %d octets does not fit an IPv%d datagram (%d at most)"
            % (len(data), 4 if both_v4 else 6, limit)
        )
    length = 8 + len(data)
    udp = struct.pack("!HHHH", sport, dport, length, 0) + data
    if both_v4:
        pseudo = src.packed + dst.packed + struct.pack("!BBH", 0, 17, length)
        # A computed zero is sent as all ones: zero means "no checksum".
        udp = udp[:6] + struct.pack("!H", _checksum(pseudo + udp) or 0xFFFF) + udp[8:]
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + length,
            ident & 0xFFFF,
            0,
            64,
            17,
            0,
            src.packed,
            dst.packed,
        )
        return header[:10] + struct.pack("!H", _checksum(header)) + header[12:] + udp
    # One end is IPv6: the other is written in its v4-mapped form.
    packed_src = src.packed if src.version == 6 else _MAPPED + src.packed
    packed_dst = dst.packed if dst.version == 6 else _MAPPED + dst.packed
    pseudo = packed_src + packed_dst + struct.pack("!I3xB", length, 17)
    udp = udp[:6] + struct.pack("!H", _checksum(pseudo + udp) or 0xFFFF) + udp[8:]
    return (
        struct.pack("!IHBB", 0x60000000, length, 17, 64) + packed_src + packed_dst + udp
    )


def _frame_octets(frame: CapturedFrame) -> bytes:
    if isinstance(frame.linktype, bool) or not isinstance(frame.linktype, int):
        raise TypeError("a frame's link type is an int")
    if not 0 <= frame.linktype <= 0xFFFF:
        raise ValueError("link type %d is outside 0-65535" % frame.linktype)
    data = bytes(frame.data)
    if len(data) > _SNAPLEN:
        raise ValueError(
            "a frame of %d octets is over the %d a capture record holds"
            % (len(data), _SNAPLEN)
        )
    return data


class _CaptureFileWriter:
    """What the two writers share: the target, opened at the first write."""

    def __init__(self, target: Union[str, "os.PathLike[str]", BinaryIO]) -> None:
        if not isinstance(target, (str, os.PathLike)) and not hasattr(target, "write"):
            raise TypeError("target must be a path or a binary stream")
        self._target = target
        self._file: Optional[BinaryIO] = None
        self._closed = False
        self._ident = 0

    def _emit(self, linktype: int, time: float, data: bytes) -> None:
        raise NotImplementedError

    def _start(self) -> bytes:
        raise NotImplementedError

    def _put(self, octets: bytes) -> None:
        """Write to the target, opening it and writing the file's opening
        octets when this is the first write."""
        if self._file is None:
            if isinstance(self._target, (str, os.PathLike)):
                self._file = open(self._target, "wb")
            else:
                self._file = self._target
            self._file.write(self._start())
        self._file.write(octets)
        self._file.flush()

    def write(
        self,
        time: float,
        source: SocketAddress,
        destination: SocketAddress,
        payload: bytes,
    ) -> None:
        """Append one UDP datagram, under synthesised IP and UDP headers.

        :param time: seconds since the epoch, from 0 up to 2**32.
        :param source: ``(host, port)``, or the four-item IPv6 form; the host
            is address text, with or without a ``%zone``.
        :param destination: the same, for the receiver.
        :param payload: the octets after the UDP header: at most 65,507 for
            IPv4 and 65,527 for IPv6.
        :raises ValueError: a host that is not an address, a port outside
            0-65535, a payload too long, a time out of range, a closed
            writer, or a pcap file of another link type. Nothing is written.
        :raises OSError: the path cannot be opened or the stream written.
        """
        if self._closed:
            raise ValueError("the writer is closed")
        packet = _ip_packet(source, destination, payload, self._ident + 1)
        self._emit(_LINKTYPE_RAW, time, packet)
        self._ident = (self._ident + 1) & 0xFFFF

    def write_datagram(self, datagram: CapturedDatagram) -> None:
        """Append a :class:`CapturedDatagram`, as :meth:`write` would. A
        partial one is written with the payload it has."""
        self.write(
            datagram.time, datagram.source, datagram.destination, datagram.payload
        )

    def write_frame(self, frame: CapturedFrame) -> None:
        """Append a captured frame as it is: its octets, its link type, its
        time to the microsecond.

        :raises ValueError: a time out of range, a frame over 262,144 octets,
            a closed writer, or a pcap file of another link type. Nothing is
            written.
        """
        if self._closed:
            raise ValueError("the writer is closed")
        self._emit(frame.linktype, frame.time, _frame_octets(frame))

    def close(self) -> None:
        """Close the file if this writer opened it. Harmless when repeated."""
        self._closed = True
        opened = self._file
        self._file = None
        if opened is not None and isinstance(self._target, (str, os.PathLike)):
            opened.close()

    def __enter__(self: _Self) -> _Self:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()


class PcapWriter(_CaptureFileWriter):
    """Writes a pcap file that tcpdump and Wireshark read.

    Little-endian, microsecond pcap. **A pcap file has one link type**, fixed
    by the first thing written: raw IP (101) for a datagram, the frame's own
    for a frame. A later write of another link type is refused; a capture of
    several link types is written with :class:`PcapngWriter`.

    For a datagram, a v4-mapped IPv6 address is written as IPv4, which is what
    was on the wire when a dual-stack socket reported it; a datagram with one
    IPv4 and one IPv6 end is written as IPv6.

    Constructing a writer touches nothing: a path is opened (and an existing
    file replaced), and the file header written, by the first write. A writer
    that never writes creates no file. Each record is flushed, so a capture
    can be followed while it grows. Not safe to share between threads.

    :param target: a path, or a binary stream. A stream stays the caller's to
        close; a path this writer opened is closed by :meth:`close`.
    """

    def __init__(self, target: Union[str, "os.PathLike[str]", BinaryIO]) -> None:
        super().__init__(target)
        self._linktype: Optional[int] = None

    def _start(self) -> bytes:
        return struct.pack(
            "<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, _SNAPLEN, self._linktype or 0
        )

    def _emit(self, linktype: int, time: float, data: bytes) -> None:
        seconds, micros = _stamp(time)
        if self._linktype is None:
            self._linktype = linktype
        elif linktype != self._linktype:
            raise ValueError(
                "this pcap file has link type %d and cannot take %d; a capture "
                "of several link types is written as pcapng"
                % (self._linktype, linktype)
            )
        self._put(struct.pack("<IIII", seconds, micros, len(data), len(data)) + data)


def _block(kind: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    length = struct.pack("<I", 12 + len(body))
    return struct.pack("<I", kind) + length + body + length


class PcapngWriter(_CaptureFileWriter):
    """Writes a pcapng file that tcpdump and Wireshark read.

    One section, little-endian, microsecond timestamps, one interface
    description for each link type in the order they are first written, and an
    enhanced packet block for each frame or datagram. Unlike pcap, one file
    holds frames of any mix of link types, so any capture can be written back.
    No option is written: nothing about the host, the tool or the interfaces
    beyond their link types.

    The lifecycle is :class:`PcapWriter`'s: nothing is opened until the first
    write, each block is flushed, a stream stays the caller's.

    :param target: a path, or a binary stream.
    """

    def __init__(self, target: Union[str, "os.PathLike[str]", BinaryIO]) -> None:
        super().__init__(target)
        self._interfaces: Dict[int, int] = {}

    def _start(self) -> bytes:
        return _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))

    def _emit(self, linktype: int, time: float, data: bytes) -> None:
        seconds, micros = _stamp(time)
        stamp = seconds * 1_000_000 + micros
        blocks = b""
        interface = self._interfaces.get(linktype)
        if interface is None:
            interface = len(self._interfaces)
            blocks = _block(1, struct.pack("<HHI", linktype, 0, _SNAPLEN))
        head = struct.pack(
            "<IIIII", interface, stamp >> 32, stamp & 0xFFFFFFFF, len(data), len(data)
        )
        self._put(blocks + _block(6, head + data))
        self._interfaces[linktype] = interface
