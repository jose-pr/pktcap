"""The records the built-in dissectors make, one per layer (internal).

Each is a named tuple of plain values: addresses are text, flags are numbers
or booleans, so a layer is immutable, hashable, and ``layer._asdict()`` is a
record ready for any output format. Each has a ``summary()``: one line saying
what the header holds, for a person. Re-exported from :mod:`pktcap`.
"""

from __future__ import annotations

from typing import Dict, NamedTuple, Optional

__all__ = [
    "EthernetLayer",
    "IPv4Layer",
    "IPv6ExtensionLayer",
    "IPv6FragmentLayer",
    "IPv6Layer",
    "LinuxCookedLayer",
    "LoopbackLayer",
    "TCPLayer",
    "UDPLayer",
    "VLANLayer",
]


def layer_name(layer: object) -> str:
    """The name a layer goes by in a record and in a summary: its class name
    without a trailing ``Layer``, in lower case."""
    name = type(layer).__name__
    if name.endswith("Layer") and len(name) > 5:
        name = name[:-5]
    return name.lower()


#: How the cooked-capture header names the direction of a packet.
_PACKET_TYPES = {
    0: "host",
    1: "broadcast",
    2: "multicast",
    3: "other host",
    4: "outgoing",
}
#: The TCP flag bits, lowest first.
_TCP_FLAGS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
    (0x100, "AE"),
)


def _more(more_fragments: bool) -> str:
    return ", more follow" if more_fragments else ""


class EthernetLayer(NamedTuple):
    """An Ethernet II header.

    :ivar destination: the destination MAC, as ``aa:bb:cc:dd:ee:ff``.
    :ivar source: the source MAC, in the same form.
    :ivar ethertype: what follows: ``0x0800`` IPv4, ``0x86DD`` IPv6,
        ``0x8100`` a VLAN tag. Below 1,536 it is an 802.3 length, and nothing
        is selected to follow.
    """

    destination: str
    source: str
    ethertype: int

    def summary(self) -> str:
        """The addresses and what follows: ``aa:.. > bb:.. ethertype 0x0800``."""
        return "%s > %s ethertype 0x%04x" % (
            self.source,
            self.destination,
            self.ethertype,
        )


class VLANLayer(NamedTuple):
    """One 802.1Q or 802.1ad tag. A QinQ frame has two of these in a row.

    :ivar id: the VLAN identifier, 0 to 4095.
    :ivar priority: the priority code point, 0 to 7.
    :ivar drop_eligible: the drop-eligible indicator.
    :ivar ethertype: what follows the tag.
    """

    id: int
    priority: int
    drop_eligible: bool
    ethertype: int

    def summary(self) -> str:
        """The tag: ``vlan 5 priority 0 ethertype 0x0800``."""
        return "vlan %d priority %d%s ethertype 0x%04x" % (
            self.id,
            self.priority,
            " drop-eligible" if self.drop_eligible else "",
            self.ethertype,
        )


class LinuxCookedLayer(NamedTuple):
    """A Linux cooked-capture header, version 1 or 2: what the ``any`` device
    records in place of a link-layer header.

    :ivar packet_type: 0 to this host, 1 broadcast, 2 multicast, 3 to another
        host, 4 sent by this host.
    :ivar hardware_type: the ``ARPHRD_`` number of the device (1 Ethernet,
        772 loopback).
    :ivar address: the sender's link-layer address as hex text, as many
        octets as the header says are valid (at most eight).
    :ivar ethertype: what follows.
    :ivar interface: the interface index; ``None`` in version 1, which has
        none.
    """

    packet_type: int
    hardware_type: int
    address: str
    ethertype: int
    interface: Optional[int] = None

    def summary(self) -> str:
        """Direction, device type, sender address when there is one, and what
        follows: ``host, hardware type 772, ethertype 0x0800``."""
        kind = _PACKET_TYPES.get(self.packet_type, "type %d" % self.packet_type)
        address = ", address %s" % self.address if self.address else ""
        return "%s, hardware type %d%s, ethertype 0x%04x" % (
            kind,
            self.hardware_type,
            address,
            self.ethertype,
        )


class LoopbackLayer(NamedTuple):
    """The four-octet header of a BSD loopback capture.

    :ivar family: the address family as the capturing host numbered it: 2 is
        IPv4 everywhere; IPv6 is 10, 24, 28 or 30 by operating system.
    """

    family: int

    def summary(self) -> str:
        """The address family: ``family 2``."""
        return "family %d" % self.family


class IPv4Layer(NamedTuple):
    """An IPv4 header. Options are skipped.

    :ivar source: the source address, dotted.
    :ivar destination: the destination address.
    :ivar protocol: the protocol number of what follows (6 TCP, 17 UDP).
    :ivar ttl: the time to live.
    :ivar identification: the identification field, shared by the fragments
        of one datagram.
    :ivar dont_fragment: the DF flag.
    :ivar more_fragments: the MF flag: more fragments follow this one.
    :ivar fragment_offset: where this fragment's octets start in the
        datagram; 0 for a whole datagram and for a first fragment.
    :ivar length: the total length the header states, 0 when a network card
        that segments the send left it unset.
    """

    source: str
    destination: str
    protocol: int
    ttl: int
    identification: int
    dont_fragment: bool
    more_fragments: bool
    fragment_offset: int
    length: int

    @property
    def is_fragment(self) -> bool:
        """Whether this packet is one piece of a fragmented datagram."""
        return self.more_fragments or self.fragment_offset != 0

    def summary(self) -> str:
        """Addresses, protocol, time to live and identification, and where a
        fragment starts: ``10.0.0.5 > 10.0.0.1 protocol 17 ttl 64 id 1``."""
        text = "%s > %s protocol %d ttl %d id %d" % (
            self.source,
            self.destination,
            self.protocol,
            self.ttl,
            self.identification,
        )
        if self.is_fragment:
            text += ", fragment at %d%s" % (
                self.fragment_offset,
                _more(self.more_fragments),
            )
        return text


class IPv6Layer(NamedTuple):
    """An IPv6 fixed header. Extension headers are layers of their own.

    :ivar source: the source address. A v4-mapped address is written
        ``::ffff:10.0.0.5`` on every Python.
    :ivar destination: the destination address.
    :ivar next_header: the protocol number of what follows.
    :ivar hop_limit: the hop limit.
    :ivar payload_length: the payload length the header states.
    :ivar traffic_class: the traffic class octet.
    :ivar flow_label: the 20-bit flow label.
    """

    source: str
    destination: str
    next_header: int
    hop_limit: int
    payload_length: int
    traffic_class: int
    flow_label: int

    def summary(self) -> str:
        """Addresses, what follows and the hop limit."""
        return "%s > %s next header %d hop limit %d" % (
            self.source,
            self.destination,
            self.next_header,
            self.hop_limit,
        )


class IPv6ExtensionLayer(NamedTuple):
    """A hop-by-hop (0), routing (43) or destination-options (60) header.

    :ivar next_header: the protocol number of what follows.
    :ivar data: the header's octets after its first two.
    """

    next_header: int
    data: bytes

    def summary(self) -> str:
        """What follows and how many octets the header holds past its first two."""
        return "next header %d, %d octets" % (self.next_header, len(self.data))


class IPv6FragmentLayer(NamedTuple):
    """An IPv6 fragment header.

    :ivar next_header: the protocol number of the reassembled payload.
    :ivar fragment_offset: where this fragment's octets start, in octets.
    :ivar more_fragments: more fragments follow this one.
    :ivar identification: shared by the fragments of one datagram.
    """

    next_header: int
    fragment_offset: int
    more_fragments: bool
    identification: int

    @property
    def is_fragment(self) -> bool:
        """False for an "atomic" fragment: a whole datagram in one piece."""
        return self.more_fragments or self.fragment_offset != 0

    def summary(self) -> str:
        """What follows, the identification and where this piece starts."""
        return "next header %d, id %d, offset %d%s" % (
            self.next_header,
            self.identification,
            self.fragment_offset,
            _more(self.more_fragments),
        )


class UDPLayer(NamedTuple):
    """A UDP header.

    :ivar source_port: the source port.
    :ivar destination_port: the destination port.
    :ivar length: the length the header states, header included; 0 for a
        jumbogram or a send the network card segmented. More than the octets
        that follow means the capture cut the datagram short.
    :ivar checksum: the checksum field, not verified.
    """

    source_port: int
    destination_port: int
    length: int
    checksum: int

    def summary(self) -> str:
        """The ports and the stated length: ``50000 > 69 length 13``."""
        return "%d > %d length %d" % (
            self.source_port,
            self.destination_port,
            self.length,
        )


class TCPLayer(NamedTuple):
    """A TCP header. The segment's payload follows it; :class:`TCPReassembler`
    puts the streams back together.

    :ivar source_port: the source port.
    :ivar destination_port: the destination port.
    :ivar sequence: the sequence number, as on the wire.
    :ivar acknowledgment: the acknowledgment number, as on the wire.
    :ivar flags: the flag bits: ``0x01`` FIN, ``0x02`` SYN, ``0x04`` RST,
        ``0x08`` PSH, ``0x10`` ACK, ``0x20`` URG, ``0x40`` ECE, ``0x80`` CWR,
        ``0x100`` the accurate-ECN bit.
    :ivar window: the window field, unscaled.
    :ivar checksum: the checksum field, not verified.
    :ivar urgent: the urgent pointer.
    :ivar options: the option octets, undecoded.
    """

    source_port: int
    destination_port: int
    sequence: int
    acknowledgment: int
    flags: int
    window: int
    checksum: int
    urgent: int
    options: bytes

    @property
    def syn(self) -> bool:
        """The SYN flag: the segment opens a connection."""
        return bool(self.flags & 0x02)

    @property
    def ack(self) -> bool:
        """The ACK flag: the acknowledgment number means something."""
        return bool(self.flags & 0x10)

    @property
    def fin(self) -> bool:
        """The FIN flag: the sender has no more to send."""
        return bool(self.flags & 0x01)

    @property
    def rst(self) -> bool:
        """The RST flag: the connection is reset."""
        return bool(self.flags & 0x04)

    def summary(self) -> str:
        """The ports, the flags that are set, the sequence and acknowledgment
        numbers and the window: ``40000 > 80 [SYN,ACK] seq 100 ack 7 window 4096``."""
        names = [name for bit, name in _TCP_FLAGS if self.flags & bit]
        return "%d > %d [%s] seq %d ack %d window %d" % (
            self.source_port,
            self.destination_port,
            ",".join(names) or "none",
            self.sequence,
            self.acknowledgment,
            self.window,
        )


#: The built-in layers by the name a filter calls them: the class name without
#: ``Layer``, in lower case.
BUILTIN_LAYERS: Dict[str, type] = {
    "ethernet": EthernetLayer,
    "vlan": VLANLayer,
    "linuxcooked": LinuxCookedLayer,
    "loopback": LoopbackLayer,
    "ipv4": IPv4Layer,
    "ipv6": IPv6Layer,
    "ipv6extension": IPv6ExtensionLayer,
    "ipv6fragment": IPv6FragmentLayer,
    "udp": UDPLayer,
    "tcp": TCPLayer,
}
