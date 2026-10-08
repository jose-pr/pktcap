"""Builders for the captures the tests read: headers, frames and containers.

Not a test module. Each function returns octets and takes the fields a test
needs to get wrong on purpose, so a malformed capture is built the same way a
well-formed one is.
"""

import ipaddress
import struct

ETHERNET, RAW, LINUX_SLL, LINUX_SLL2, NULL, LOOP = 1, 101, 113, 276, 0, 108


def udp(sport, dport, payload, *, length=None):
    """A UDP header and payload; ``length`` overrides the stated length."""
    stated = 8 + len(payload) if length is None else length
    return struct.pack("!HHHH", sport, dport, stated, 0) + payload


def tcp(
    sport,
    dport,
    payload=b"",
    *,
    flags=0x18,
    sequence=1000,
    acknowledgment=2000,
    window=4096,
    options=b"",
    offset=None,
):
    """A TCP header and payload; ``offset`` overrides the stated header
    length, in 32-bit words. ``options`` must be a multiple of 4 octets."""
    words = (20 + len(options)) // 4 if offset is None else offset
    return (
        struct.pack(
            "!HHIIBBHHH",
            sport,
            dport,
            sequence,
            acknowledgment,
            words << 4,
            flags,
            window,
            0,
            0,
        )
        + options
        + payload
    )


def tcp_frame(
    src,
    dst,
    sport,
    dport,
    sequence,
    payload=b"",
    *,
    flags=0x18,
    acknowledgment=0,
    ident=1,
):
    """An Ethernet frame holding one TCP segment over IPv4, or over IPv6 when
    ``src`` is an IPv6 address."""
    segment = tcp(
        sport,
        dport,
        payload,
        flags=flags,
        sequence=sequence,
        acknowledgment=acknowledgment,
    )
    if ":" in src:
        return ethernet(ipv6(src, dst, segment, next_header=6), v6=True)
    return ethernet(ipv4(src, dst, segment, protocol=6, ident=ident))


def ipv4(
    src, dst, body, *, ident=1, offset=0, more=False, protocol=17, total=None, ihl=5
):
    """An IPv4 packet. ``offset`` is in octets and must be a multiple of 8.

    The header checksum is valid: a reference tool that checks it does not
    reassemble a fragment whose checksum is wrong.
    """
    flags = (0x2000 if more else 0) | (offset // 8)
    stated = ihl * 4 + len(body) if total is None else total
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl,
        0,
        stated,
        ident,
        flags,
        64,
        protocol,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    ) + b"\0" * (ihl * 4 - 20)
    total_sum = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    while total_sum >> 16:
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16)
    return header[:10] + struct.pack("!H", ~total_sum & 0xFFFF) + header[12:] + body


def ipv6(src, dst, body, *, next_header=17, length=None):
    stated = len(body) if length is None else length
    return (
        struct.pack("!IHBB", 0x60000000, stated, next_header, 64)
        + ipaddress.IPv6Address(src).packed
        + ipaddress.IPv6Address(dst).packed
        + body
    )


def ipv6_fragment(chunk, *, offset=0, more=False, ident=77, next_header=17):
    """A fragment extension header followed by ``chunk``."""
    return (
        struct.pack("!BBHI", next_header, 0, (offset // 8) << 3 | int(more), ident)
        + chunk
    )


def ipv6_extension(body, *, next_header=17, kind_length=0):
    """One 8-octet hop-by-hop, routing or destination header before ``body``."""
    return struct.pack("!BB6x", next_header, kind_length) + body


def ethernet(ip, *, vlans=0, v6=False, ethertype=None, tags=()):
    """An Ethernet frame. ``vlans`` is how many 802.1Q tags for VLAN 5 come
    before the payload; ``tags`` spells a tag stack out instead, as
    ``(tag protocol identifier, tag control)`` pairs, outermost first."""
    kind = ethertype if ethertype is not None else (0x86DD if v6 else 0x0800)
    stack = b"\x81\x00\x00\x05" * vlans
    for identifier, control in tags:
        stack += struct.pack("!HH", identifier, control)
    return b"\x02" * 6 + b"\x04" * 6 + stack + struct.pack("!H", kind) + ip


def linux_sll(ip, *, v6=False):
    return struct.pack("!HHH8sH", 0, 772, 0, b"", 0x86DD if v6 else 0x0800) + ip


def linux_sll2(ip, *, v6=False):
    return struct.pack("!HHIHBB8s", 0x86DD if v6 else 0x0800, 0, 1, 772, 0, 0, b"") + ip


def pcap(frames, *, linktype=ETHERNET, endian="<", nanoseconds=False, start=1_000_000):
    """A pcap file; frame ``i`` is stamped ``start + i`` seconds."""
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype)
    for index, frame in enumerate(frames):
        out += pcap_record(frame, endian=endian, seconds=start + index)
    return out


def pcap_record(frame, *, endian="<", seconds=0, fraction=0, captured=None):
    stated = len(frame) if captured is None else captured
    return struct.pack(endian + "IIII", seconds, fraction, stated, stated) + frame


def block(kind, body, *, endian="<", length=None, trailer=None):
    """One pcapng block; ``length`` and ``trailer`` override the two lengths."""
    body += b"\0" * (-len(body) % 4)
    stated = 12 + len(body) if length is None else length
    closing = stated if trailer is None else trailer
    return (
        struct.pack(endian + "II", kind, stated)
        + body
        + struct.pack(endian + "I", closing)
    )


def section(*, endian="<", length=None):
    body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    return block(0x0A0D0D0A, body, endian=endian, length=length)


def interface(linktype=ETHERNET, *, endian="<", tsresol=None, tsoffset=None):
    options = b""
    if tsresol is not None:
        options += struct.pack(endian + "HHB3x", 9, 1, tsresol)
    if tsoffset is not None:
        options += struct.pack(endian + "HHq", 14, 8, tsoffset)
    if options:
        options += struct.pack(endian + "HH", 0, 0)
    return block(
        1, struct.pack(endian + "HHI", linktype, 0, 262144) + options, endian=endian
    )


def packet(frame, *, endian="<", stamp=0, iface=0, captured=None, **overrides):
    """An enhanced packet block. ``stamp`` is in the interface's units."""
    stated = len(frame) if captured is None else captured
    body = struct.pack(
        endian + "IIIII", iface, stamp >> 32, stamp & 0xFFFFFFFF, stated, len(frame)
    )
    return block(6, body + frame, endian=endian, **overrides)


def pcapng(
    frames, *, linktype=ETHERNET, endian="<", nanoseconds=False, start=1_000_000
):
    """A one-interface pcapng file; frame ``i`` is stamped ``start + i`` seconds."""
    unit = 1_000_000_000 if nanoseconds else 1_000_000
    out = section(endian=endian) + interface(
        linktype, endian=endian, tsresol=9 if nanoseconds else None
    )
    for index, frame in enumerate(frames):
        out += packet(frame, endian=endian, stamp=(start + index) * unit)
    return out


class Pipe:
    """A stream that cannot seek and hands out a few octets at a time, as a
    pipe from a capture tool does."""

    def __init__(self, data, chunk=7):
        self._data = memoryview(data)
        self._position = 0
        self._chunk = chunk
        self.largest_request = 0

    def read(self, count=-1):
        self.largest_request = max(self.largest_request, count)
        take = self._chunk if count < 0 else min(count, self._chunk)
        piece = bytes(self._data[self._position : self._position + take])
        self._position += len(piece)
        return piece
