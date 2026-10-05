"""The transport-layer dissectors (internal): UDP and TCP.

The layouts are those of RFC 768 and RFC 9293. TCP is read a segment at a
time: its header and the octets after it. Streams are not put back together.
"""

from __future__ import annotations

import struct
from typing import Dict

from .._exceptions import DissectError
from .._layers import TCPLayer, UDPLayer
from ._contract import Dissected, Dissector, Selector

__all__ = ["TRANSPORT_DISSECTORS"]


def dissect_udp(data: bytes) -> Dissected:
    if len(data) < 8:
        raise DissectError("a UDP header is 8 octets")
    source, destination, length, checksum = struct.unpack_from("!HHHH", data, 0)
    # Zero is a jumbogram, or a send the network card segmented: all that is left.
    end = length if length else len(data)
    if end < 8:
        raise DissectError("a UDP datagram states a length under its header")
    layer = UDPLayer(source, destination, length, checksum)
    # The service is whichever end has a dissector: the destination first.
    return Dissected(layer, data[8:end], (("udp", destination), ("udp", source)))


def dissect_tcp(data: bytes) -> Dissected:
    if len(data) < 20:
        raise DissectError("a TCP header is at least 20 octets")
    header = (data[12] >> 4) * 4
    if header < 20 or header > len(data):
        raise DissectError("a TCP header states a length it does not have")
    source, destination, sequence, acknowledgment = struct.unpack_from("!HHII", data, 0)
    window, checksum, urgent = struct.unpack_from("!HHH", data, 14)
    layer = TCPLayer(
        source,
        destination,
        sequence,
        acknowledgment,
        ((data[12] & 0x01) << 8) | data[13],
        window,
        checksum,
        urgent,
        data[20:header],
    )
    return Dissected(layer, data[header:], (("tcp", destination), ("tcp", source)))


TRANSPORT_DISSECTORS: Dict[Selector, Dissector] = {
    ("ip", 17): dissect_udp,
    ("ip", 6): dissect_tcp,
}
