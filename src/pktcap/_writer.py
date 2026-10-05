"""Writing UDP datagrams as a pcap capture (internal).

A datagram seen at a socket has no link or IP header left, so each one is
written with synthesised IPv4 or IPv6 and UDP headers, their checksums valid,
under link type RAW (101): tcpdump and Wireshark then decode the payload as
the protocol on that port.
"""

from __future__ import annotations

import math
import os
import struct
from types import TracebackType
from typing import BinaryIO, Optional, Tuple, Type, Union

from netimps import IPAddress, SocketAddress, split_zone, unmap

from ._captured import CapturedDatagram

__all__ = ["PcapWriter", "pcap_file_header", "pcap_record"]

_LINKTYPE_RAW = 101
#: libpcap's MAXIMUM_SNAPLEN: the largest packet written here is 65,575 octets.
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


def pcap_file_header() -> bytes:
    """The 24 octets that open a little-endian, microsecond, RAW pcap file."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, _SNAPLEN, _LINKTYPE_RAW)


def pcap_record(
    time: float,
    source: SocketAddress,
    destination: SocketAddress,
    payload: bytes,
    ident: int = 0,
) -> bytes:
    """One pcap record: the datagram under IP and UDP headers it never had.

    ``ident`` is the IPv4 identification field. Everything is checked before a
    single octet is produced, so a refused datagram writes nothing.
    """
    if isinstance(time, bool) or not isinstance(time, (int, float)):
        raise TypeError("time must be a number of seconds")
    if not (math.isfinite(time) and 0 <= time < _MAX_SECONDS):
        raise ValueError("time is outside what a pcap record can hold")
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
        header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
        packet = header + udp
    else:
        # One end is IPv6: the other is written in its v4-mapped form.
        packed_src = src.packed if src.version == 6 else _MAPPED + src.packed
        packed_dst = dst.packed if dst.version == 6 else _MAPPED + dst.packed
        pseudo = packed_src + packed_dst + struct.pack("!I3xB", length, 17)
        udp = udp[:6] + struct.pack("!H", _checksum(pseudo + udp) or 0xFFFF) + udp[8:]
        packet = (
            struct.pack("!IHBB", 0x60000000, length, 17, 64)
            + packed_src
            + packed_dst
            + udp
        )
    seconds = int(time)
    micros = int(round((time - seconds) * 1e6))
    if micros >= 1_000_000:
        if seconds + 1 < _MAX_SECONDS:
            seconds, micros = seconds + 1, 0
        else:  # the last microsecond a 32-bit count of seconds can hold
            micros = 999_999
    return struct.pack("<IIII", seconds, micros, len(packet), len(packet)) + packet


class PcapWriter:
    """Writes UDP datagrams as a pcap file that tcpdump and Wireshark read.

    Little-endian, microsecond pcap, link type RAW. A v4-mapped IPv6 address
    is written as IPv4, which is what was on the wire when a dual-stack socket
    reported it; a datagram with one IPv4 and one IPv6 end is written as IPv6.

    Constructing a writer touches nothing: a path is opened (and an existing
    file replaced), and the file header written, by the first ``write``. A
    writer that never writes creates no file. Each record is flushed, so a
    capture can be followed while it grows. Not safe to share between threads.

    :param target: a path, or a binary stream. A stream stays the caller's to
        close; a path this writer opened is closed by :meth:`close`.
    """

    def __init__(self, target: Union[str, "os.PathLike[str]", BinaryIO]) -> None:
        if not isinstance(target, (str, os.PathLike)) and not hasattr(target, "write"):
            raise TypeError("target must be a path or a binary stream")
        self._target = target
        self._file: Optional[BinaryIO] = None
        self._closed = False
        self._ident = 0

    def write(
        self,
        time: float,
        source: SocketAddress,
        destination: SocketAddress,
        payload: bytes,
    ) -> None:
        """Append one datagram.

        :param time: seconds since the epoch, from 0 up to 2**32.
        :param source: ``(host, port)``, or the four-item IPv6 form; the host
            is address text, with or without a ``%zone``.
        :param destination: the same, for the receiver.
        :param payload: the octets after the UDP header: at most 65,507 for
            IPv4 and 65,527 for IPv6.
        :raises ValueError: a host that is not an address, a port outside
            0-65535, a payload too long, a time out of range, or a closed
            writer. Nothing is written.
        :raises OSError: the path cannot be opened or the stream written.
        """
        if self._closed:
            raise ValueError("the writer is closed")
        record = pcap_record(time, source, destination, payload, self._ident + 1)
        if self._file is None:
            if isinstance(self._target, (str, os.PathLike)):
                self._file = open(self._target, "wb")
            else:
                self._file = self._target
            self._file.write(pcap_file_header())
        self._ident = (self._ident + 1) & 0xFFFF
        self._file.write(record)
        self._file.flush()

    def write_datagram(self, datagram: CapturedDatagram) -> None:
        """Append a :class:`CapturedDatagram`, as :meth:`write` would."""
        self.write(
            datagram.time, datagram.source, datagram.destination, datagram.payload
        )

    def close(self) -> None:
        """Close the file if this writer opened it. Harmless when repeated."""
        self._closed = True
        opened = self._file
        self._file = None
        if opened is not None and isinstance(self._target, (str, os.PathLike)):
            opened.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()
