"""The link-layer dissectors (internal): Ethernet, the VLAN tag, Linux cooked
capture, BSD loopback and raw IP.

The layouts are those of IEEE 802.3 and 802.1Q and of the tcpdump.org link-type
pages (LINKTYPE_NULL, LINKTYPE_LOOP, LINKTYPE_RAW, LINKTYPE_LINUX_SLL and
LINKTYPE_LINUX_SLL2).
"""

from __future__ import annotations

from typing import Dict, Tuple

from .._exceptions import DissectError
from .._layers import EthernetLayer, LinuxCookedLayer, LoopbackLayer, VLANLayer
from ._contract import Dissected, Dissector, Selector

__all__ = ["LINK_DISSECTORS", "LINKTYPE_NAMES"]

_FAMILY_IPV4 = 2
_FAMILIES_IPV6 = frozenset({10, 24, 28, 30})  # AF_INET6 on Linux, the BSDs, macOS
_ETHERTYPE_IPV4, _ETHERTYPE_IPV6 = 0x0800, 0x86DD
#: Below this an "ethertype" is an 802.3 length, and selects nothing.
_FIRST_ETHERTYPE = 0x0600


def _mac(octets: bytes) -> str:
    return octets.hex(":")


def _ethertype(value: int) -> Tuple[Selector, ...]:
    return (("ethertype", value),) if value >= _FIRST_ETHERTYPE else ()


def dissect_ethernet(data: bytes) -> Dissected:
    if len(data) < 14:
        raise DissectError("an Ethernet header is 14 octets")
    ethertype = (data[12] << 8) | data[13]
    layer = EthernetLayer(_mac(data[0:6]), _mac(data[6:12]), ethertype)
    return Dissected(layer, data[14:], _ethertype(ethertype))


def dissect_vlan(data: bytes) -> Dissected:
    if len(data) < 4:
        raise DissectError("a VLAN tag is 4 octets")
    control = (data[0] << 8) | data[1]
    ethertype = (data[2] << 8) | data[3]
    layer = VLANLayer(
        control & 0x0FFF, control >> 13, bool(control & 0x1000), ethertype
    )
    return Dissected(layer, data[4:], _ethertype(ethertype))


def dissect_linux_cooked(data: bytes) -> Dissected:
    if len(data) < 16:
        raise DissectError("a Linux cooked header is 16 octets")
    length = min((data[4] << 8) | data[5], 8)
    ethertype = (data[14] << 8) | data[15]
    layer = LinuxCookedLayer(
        (data[0] << 8) | data[1],
        (data[2] << 8) | data[3],
        data[6 : 6 + length].hex(),
        ethertype,
    )
    return Dissected(layer, data[16:], _ethertype(ethertype))


def dissect_linux_cooked_v2(data: bytes) -> Dissected:
    if len(data) < 20:
        raise DissectError("a Linux cooked v2 header is 20 octets")
    ethertype = (data[0] << 8) | data[1]
    layer = LinuxCookedLayer(
        data[10],
        (data[8] << 8) | data[9],
        data[12 : 12 + min(data[11], 8)].hex(),
        ethertype,
        int.from_bytes(data[4:8], "big"),
    )
    return Dissected(layer, data[20:], _ethertype(ethertype))


def _family(family: int) -> Tuple[Selector, ...]:
    if family == _FAMILY_IPV4:
        return (("ethertype", _ETHERTYPE_IPV4),)
    if family in _FAMILIES_IPV6:
        return (("ethertype", _ETHERTYPE_IPV6),)
    return ()


def dissect_null(data: bytes) -> Dissected:
    """BSD loopback: the family in the byte order of the capturing host."""
    if len(data) < 4:
        raise DissectError("a loopback header is 4 octets")
    family = int.from_bytes(data[:4], "big")
    if family > 0xFFFF:  # written by a little-endian host
        family = int.from_bytes(data[:4], "little")
    return Dissected(LoopbackLayer(family), data[4:], _family(family))


def dissect_loop(data: bytes) -> Dissected:
    """OpenBSD loopback: the family in network byte order."""
    if len(data) < 4:
        raise DissectError("a loopback header is 4 octets")
    family = int.from_bytes(data[:4], "big")
    return Dissected(LoopbackLayer(family), data[4:], _family(family))


def dissect_raw(data: bytes) -> Dissected:
    """Raw IP: no link header, the version nibble says which IP follows."""
    if not data:
        raise DissectError("a raw IP frame is empty")
    version = data[0] >> 4
    if version == 4:
        return Dissected(None, data, (("ethertype", _ETHERTYPE_IPV4),))
    if version == 6:
        return Dissected(None, data, (("ethertype", _ETHERTYPE_IPV6),))
    raise DissectError("a raw IP frame starts with version %d" % version)


#: The link types with a built-in dissector, by ``LINKTYPE_`` number.
LINKTYPE_NAMES: Dict[int, str] = {
    0: "NULL",  # BSD loopback, host-order family
    1: "ETHERNET",
    12: "RAW",  # some BSDs
    14: "RAW",
    101: "RAW",
    108: "LOOP",  # OpenBSD loopback, network-order family
    113: "LINUX_SLL",
    228: "IPV4",
    229: "IPV6",
    276: "LINUX_SLL2",
}

LINK_DISSECTORS: Dict[Selector, Dissector] = {
    ("linktype", 0): dissect_null,
    ("linktype", 1): dissect_ethernet,
    ("linktype", 12): dissect_raw,
    ("linktype", 14): dissect_raw,
    ("linktype", 101): dissect_raw,
    ("linktype", 108): dissect_loop,
    ("linktype", 113): dissect_linux_cooked,
    ("linktype", 228): dissect_raw,
    ("linktype", 229): dissect_raw,
    ("linktype", 276): dissect_linux_cooked_v2,
    ("ethertype", 0x8100): dissect_vlan,  # 802.1Q
    ("ethertype", 0x88A8): dissect_vlan,  # 802.1ad, the outer tag of QinQ
    ("ethertype", 0x9100): dissect_vlan,  # the outer tag of QinQ before 802.1ad
}
