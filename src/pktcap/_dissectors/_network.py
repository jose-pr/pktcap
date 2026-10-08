"""The network-layer dissectors (internal): IPv4, IPv6 and its extension and
fragment headers.

The layouts are those of RFC 791 and RFC 8200. Every length a header states
is checked against the octets present before anything is read by it, and each
dissector reads one header: a chain of extension headers is a chain of layers,
which the frame dissector cuts off at its own ceiling.
"""

from __future__ import annotations

import functools
import ipaddress
import socket
import struct
from typing import Dict

from .._exceptions import DissectError
from .._layers import IPv4Layer, IPv6ExtensionLayer, IPv6FragmentLayer, IPv6Layer
from ._contract import Dissected, Dissector, Fragment, Selector

__all__ = ["NETWORK_DISSECTORS"]

_MAPPED_PREFIX = bytes(10) + b"\xff\xff"

#: How many IPv6 addresses keep their text. A capture names few hosts and
#: every frame names two, and writing one costs about 2.5 microseconds against
#: 0.1 for finding it (CPython 3.14 on Windows ARM64, 2026-10-08). The bound is
#: what a capture of addresses that never repeat can make this hold.
_IPV6_TEXTS = 1024


@functools.lru_cache(maxsize=_IPV6_TEXTS)
def _ipv6_text(packed: bytes) -> str:
    # The rule of netimps.format_address, kept here for speed: a v4-mapped
    # address is written ::ffff:1.2.3.4 on every Python (str() writes the hex
    # form before 3.13). Through netimps this costs 160 ns more for a plain
    # address and 1.1 microseconds (eight times) more for a mapped one, twice a
    # frame (CPython 3.14 on Windows ARM64).
    if packed[:12] == _MAPPED_PREFIX:
        return "::ffff:" + socket.inet_ntoa(packed[12:])
    return str(ipaddress.IPv6Address(packed))


def dissect_ipv4(data: bytes) -> Dissected:
    if len(data) < 20:
        raise DissectError("an IPv4 header is at least 20 octets")
    if data[0] >> 4 != 4:
        raise DissectError("an IPv4 header starts with version %d" % (data[0] >> 4))
    header = (data[0] & 0x0F) * 4
    if header < 20 or header > len(data):
        raise DissectError("an IPv4 header states a length it does not have")
    total, identification, flags_offset = struct.unpack_from("!HHH", data, 2)
    # A network card that segments the send leaves the total length zero.
    stated = total or len(data)
    if stated < header:
        raise DissectError("an IPv4 packet is shorter than its own header")
    more = bool(flags_offset & 0x2000)
    offset = (flags_offset & 0x1FFF) * 8
    protocol = data[9]
    layer = IPv4Layer(
        socket.inet_ntoa(data[12:16]),
        socket.inet_ntoa(data[16:20]),
        protocol,
        data[8],
        identification,
        bool(flags_offset & 0x4000),
        more,
        offset,
        total,
    )
    # Octets after the stated length are link-layer padding, not payload.
    payload = data[header : min(stated, len(data))]
    fragment = None
    if more or offset:
        fragment = Fragment((4, identification, protocol), offset, not more)
    return Dissected(layer, payload, (("ip", protocol),), fragment)


def dissect_ipv6(data: bytes) -> Dissected:
    if len(data) < 40:
        raise DissectError("an IPv6 header is 40 octets")
    if data[0] >> 4 != 6:
        raise DissectError("an IPv6 header starts with version %d" % (data[0] >> 4))
    first, length = struct.unpack_from("!IH", data, 0)
    next_header = data[6]
    layer = IPv6Layer(
        _ipv6_text(data[8:24]),
        _ipv6_text(data[24:40]),
        next_header,
        data[7],
        length,
        (first >> 20) & 0xFF,
        first & 0xFFFFF,
    )
    # A zero length is a jumbogram, or a send the network card segmented.
    payload = data[40 : 40 + length] if length else data[40:]
    return Dissected(layer, payload, (("ip", next_header),))


def dissect_ipv6_extension(data: bytes) -> Dissected:
    """A hop-by-hop, routing or destination-options header: skipped whole."""
    if len(data) < 2:
        raise DissectError("an IPv6 extension header is at least 2 octets")
    size = (data[1] + 1) * 8
    if size > len(data):
        raise DissectError("an IPv6 extension header states a length it does not have")
    layer = IPv6ExtensionLayer(data[0], data[2:size])
    return Dissected(layer, data[size:], (("ip", data[0]),))


def dissect_ipv6_fragment(data: bytes) -> Dissected:
    if len(data) < 8:
        raise DissectError("an IPv6 fragment header is 8 octets")
    field, identification = struct.unpack_from("!HI", data, 2)
    more, offset = bool(field & 1), (field >> 3) * 8
    layer = IPv6FragmentLayer(data[0], offset, more, identification)
    fragment = None
    if more or offset:  # otherwise "atomic": a whole datagram in one piece
        fragment = Fragment((6, identification, data[0]), offset, not more)
    return Dissected(layer, data[8:], (("ip", data[0]),), fragment)


NETWORK_DISSECTORS: Dict[Selector, Dissector] = {
    ("ethertype", 0x0800): dissect_ipv4,
    ("ethertype", 0x86DD): dissect_ipv6,
    ("ip", 0): dissect_ipv6_extension,  # hop-by-hop options
    ("ip", 43): dissect_ipv6_extension,  # routing
    ("ip", 60): dissect_ipv6_extension,  # destination options
    ("ip", 44): dissect_ipv6_fragment,
}
