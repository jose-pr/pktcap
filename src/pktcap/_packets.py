"""IP packets synthesised around a transport segment (internal).

A datagram or segment seen at a socket has no IP header left; these build
the IPv4 or IPv6 and UDP or TCP headers a capture needs, with valid
checksums (RFC 1071), so tcpdump and Wireshark decode what they carry.
"""

from __future__ import annotations

import struct
from typing import Tuple, Union

from netimps import IPAddress, SocketAddress, split_zone, unmap

__all__ = ["checksum", "ip_packet", "tcp_packet"]

_MAPPED = bytes(10) + b"\xff\xff"


def checksum(data: bytes) -> int:
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


def _wrap(
    src: IPAddress,
    dst: IPAddress,
    protocol: int,
    segment: bytes,
    checksum_at: int,
    ident: int,
    zero_as_ones: bool,
) -> bytes:
    """``segment`` (its checksum field zero) under an IPv4 or IPv6 header,
    with the transport checksum filled in at ``checksum_at``.

    ``zero_as_ones`` writes a computed zero as all ones, as UDP requires (a
    zero there means "no checksum"); TCP has no such rule.
    """
    length = len(segment)

    def filled(pseudo: bytes) -> bytes:
        value = checksum(pseudo + segment)
        if zero_as_ones and not value:
            value = 0xFFFF
        return (
            segment[:checksum_at]
            + struct.pack("!H", value)
            + segment[checksum_at + 2 :]
        )

    if src.version == 4 and dst.version == 4:
        transport = filled(
            src.packed + dst.packed + struct.pack("!BBH", 0, protocol, length)
        )
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + length,
            ident & 0xFFFF,
            0,
            64,
            protocol,
            0,
            src.packed,
            dst.packed,
        )
        return (
            header[:10] + struct.pack("!H", checksum(header)) + header[12:] + transport
        )
    # One end is IPv6: the other is written in its v4-mapped form.
    packed_src = src.packed if src.version == 6 else _MAPPED + src.packed
    packed_dst = dst.packed if dst.version == 6 else _MAPPED + dst.packed
    transport = filled(packed_src + packed_dst + struct.pack("!I3xB", length, protocol))
    return (
        struct.pack("!IHBB", 0x60000000, length, protocol, 64)
        + packed_src
        + packed_dst
        + transport
    )


def _payload(payload: object, src: IPAddress, dst: IPAddress, header: int) -> bytes:
    """``payload`` as bytes, refused when it cannot fit one IP packet after a
    transport header of ``header`` octets."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")
    data = bytes(payload)
    both_v4 = src.version == 4 and dst.version == 4
    limit = 65535 - header - (20 if both_v4 else 0)
    if len(data) > limit:
        raise ValueError(
            "a payload of %d octets does not fit an IPv%d packet (%d at most)"
            % (len(data), 4 if both_v4 else 6, limit)
        )
    return data


def ip_packet(
    source: SocketAddress, destination: SocketAddress, payload: bytes, ident: int
) -> bytes:
    """The datagram under the IP and UDP headers it never had at a socket."""
    src, sport = _endpoint(source, "source")
    dst, dport = _endpoint(destination, "destination")
    data = _payload(payload, src, dst, 8)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    return _wrap(src, dst, _PROTO_UDP, udp, 6, ident, True)


_PROTO_TCP, _PROTO_UDP = 6, 17
_TCP_FLAG_BITS = {
    "F": 0x01,
    "S": 0x02,
    "R": 0x04,
    "P": 0x08,
    "A": 0x10,
    "U": 0x20,
    "E": 0x40,
    "C": 0x80,
}
_UINT32 = 1 << 32


def _tcp_flags(flags: Union[str, int]) -> int:
    if isinstance(flags, bool):
        raise TypeError("flags must be letters or an int")
    if isinstance(flags, int):
        if not 0 <= flags <= 0xFF:
            raise ValueError("flags %d is outside 0-255" % flags)
        return flags
    if not isinstance(flags, str):
        raise TypeError("flags must be letters or an int")
    bits = 0
    for letter in flags.upper():
        if letter not in _TCP_FLAG_BITS:
            raise ValueError("unknown TCP flag %r; use letters of FSRPAUEC" % letter)
        bits |= _TCP_FLAG_BITS[letter]
    return bits


def _uint(value: object, name: str, top: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an int" % name)
    if not 0 <= value < top:
        raise ValueError("%s %d is outside 0 to %d" % (name, value, top - 1))
    return value


def tcp_packet(
    source: SocketAddress,
    destination: SocketAddress,
    payload: bytes,
    *,
    seq: int,
    ack: int,
    flags: Union[str, int],
    window: int,
    ident: int,
) -> bytes:
    """One TCP segment under synthesised IP and TCP headers, checksums valid."""
    src, sport = _endpoint(source, "source")
    dst, dport = _endpoint(destination, "destination")
    data = _payload(payload, src, dst, 20)
    tcp = (
        struct.pack(
            "!HHIIBBHHH",
            sport,
            dport,
            _uint(seq, "seq", _UINT32),
            _uint(ack, "ack", _UINT32),
            5 << 4,
            _tcp_flags(flags),
            _uint(window, "window", 1 << 16),
            0,
            0,
        )
        + data
    )
    return _wrap(src, dst, _PROTO_TCP, tcp, 16, ident, False)
