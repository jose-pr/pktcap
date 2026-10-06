"""Each built-in dissector, on its own: what it reads, what it refuses, and
that nothing else ever comes out of it."""

import ipaddress
import struct

import netimps
import pytest

import captures as build
from pktcap import (
    DissectError,
    DissectorRegistry,
    EthernetLayer,
    IPv4Layer,
    IPv6ExtensionLayer,
    IPv6FragmentLayer,
    IPv6Layer,
    LinuxCookedLayer,
    LoopbackLayer,
    TCPLayer,
    UDPLayer,
    VLANLayer,
    check_dissector,
)

REGISTRY = DissectorRegistry()
UDP = build.udp(50000, 69, b"request")
V4 = build.ipv4("10.0.0.5", "10.0.0.1", UDP)
V6 = build.ipv6("2001:db8::5", "2001:db8::1", UDP)


def tcp(
    sport=50000, dport=80, payload=b"GET /", *, flags=0x18, options=b"", offset=None
):
    words = (20 + len(options)) // 4 if offset is None else offset
    return (
        struct.pack(
            "!HHIIBBHHH", sport, dport, 1000, 2000, words << 4, flags, 4096, 0xABCD, 7
        )
        + options
        + payload
    )


def run(kind, value, data):
    return REGISTRY.get(kind, value)(data)


# -- link -----------------------------------------------------------------


def test_ethernet():
    layer, payload, following, fragment = run("linktype", 1, build.ethernet(V4))
    assert layer == EthernetLayer("02:02:02:02:02:02", "04:04:04:04:04:04", 0x0800)
    assert payload == V4 and following == (("ethertype", 0x0800),) and fragment is None


def test_an_802_3_length_selects_nothing():
    frame = b"\x02" * 6 + b"\x04" * 6 + struct.pack("!H", 46) + bytes(46)
    assert run("linktype", 1, frame).next == ()


@pytest.mark.parametrize("ethertype", [0x8100, 0x88A8, 0x9100])
def test_a_vlan_tag_is_a_layer_of_its_own(ethertype):
    tag = struct.pack("!HH", (5 << 13) | 0x1000 | 100, 0x86DD) + V6
    layer, payload, following, _fragment = run("ethertype", ethertype, tag)
    assert layer == VLANLayer(id=100, priority=5, drop_eligible=True, ethertype=0x86DD)
    assert payload == V6 and following == (("ethertype", 0x86DD),)


def test_linux_cooked_version_1():
    frame = (
        struct.pack("!HHH8sH", 4, 772, 6, b"\x01\x02\x03\x04\x05\x06\0\0", 0x0800) + V4
    )
    layer, payload, following, _ = run("linktype", 113, frame)
    assert layer == LinuxCookedLayer(4, 772, "010203040506", 0x0800, None)
    assert payload == V4 and following == (("ethertype", 0x0800),)


def test_linux_cooked_version_2():
    frame = struct.pack("!HHIHBB8s", 0x86DD, 0, 3, 1, 0, 6, b"\xaa" * 6 + b"\0\0") + V6
    layer, payload, following, _ = run("linktype", 276, frame)
    assert layer == LinuxCookedLayer(0, 1, "aa" * 6, 0x86DD, 3)
    assert payload == V6 and following == (("ethertype", 0x86DD),)


def test_a_cooked_header_cannot_state_an_address_longer_than_its_eight_octets():
    """The field is eight octets wide; a length over that would take the
    packet that follows for the address."""
    one = struct.pack("!HHH8sH", 0, 1, 0xFFFF, b"\xaa" * 8, 0x0800) + V4
    two = struct.pack("!HHIHBB8s", 0x0800, 0, 3, 1, 0, 255, b"\xbb" * 8) + V4
    assert run("linktype", 113, one).layer.address == "aa" * 8
    assert run("linktype", 276, two).layer.address == "bb" * 8


@pytest.mark.parametrize(
    "linktype, header, family, ethertype",
    [
        (0, struct.pack("<I", 2), 2, 0x0800),
        (0, struct.pack(">I", 2), 2, 0x0800),
        (0, struct.pack("<I", 30), 30, 0x86DD),
        (0, struct.pack("<I", 24), 24, 0x86DD),
        (108, struct.pack(">I", 2), 2, 0x0800),
        (108, struct.pack(">I", 28), 28, 0x86DD),
    ],
)
def test_bsd_loopback_in_either_byte_order(linktype, header, family, ethertype):
    layer, payload, following, _ = run("linktype", linktype, header + V4)
    assert layer == LoopbackLayer(family) and payload == V4
    assert following == (("ethertype", ethertype),)


def test_a_loopback_family_that_is_not_ip_selects_nothing():
    assert run("linktype", 0, struct.pack("<I", 7) + V4).next == ()


@pytest.mark.parametrize("linktype", [12, 14, 101, 228, 229])
def test_raw_ip_has_no_layer_and_chooses_by_the_version(linktype):
    assert run("linktype", linktype, V4) == (None, V4, (("ethertype", 0x0800),), None)
    assert run("linktype", linktype, V6).next == (("ethertype", 0x86DD),)
    with pytest.raises(DissectError, match="version 0"):
        run("linktype", linktype, b"\x05" + V4[1:])


# -- network --------------------------------------------------------------


def test_ipv4():
    layer, payload, following, fragment = run("ethertype", 0x0800, V4)
    assert layer == IPv4Layer(
        source="10.0.0.5",
        destination="10.0.0.1",
        protocol=17,
        ttl=64,
        identification=1,
        dont_fragment=False,
        more_fragments=False,
        fragment_offset=0,
        length=len(V4),
    )
    assert payload == UDP and following == (("ip", 17),) and fragment is None
    assert not layer.is_fragment


def test_ipv4_options_are_skipped_and_padding_is_not_payload():
    packet = build.ipv4("10.0.0.5", "10.0.0.1", UDP, ihl=7)
    assert run("ethertype", 0x0800, packet + bytes(18)).payload == UDP


def test_an_ipv4_fragment_says_which_piece_it_is():
    first = build.ipv4("10.0.0.5", "10.0.0.1", bytes(16), ident=9, more=True)
    last = build.ipv4("10.0.0.5", "10.0.0.1", bytes(8), ident=9, offset=16)
    layer, _payload, _next, fragment = run("ethertype", 0x0800, first)
    assert layer.is_fragment and layer.more_fragments and fragment.offset == 0
    assert not fragment.last
    again = run("ethertype", 0x0800, last).fragment
    assert (again.offset, again.last) == (16, True) and again.key == fragment.key
    other = build.ipv4("10.0.0.5", "10.0.0.1", bytes(8), ident=10, offset=16)
    assert run("ethertype", 0x0800, other).fragment.key != fragment.key


def test_a_zero_ipv4_length_means_the_rest():
    packet = V4[:2] + b"\0\0" + V4[4:]
    layer, payload, _next, _fragment = run("ethertype", 0x0800, packet)
    assert layer.length == 0 and payload == UDP


def test_ipv6():
    packet = build.ipv6("2001:db8::5", "::ffff:10.0.0.1", UDP)
    layer, payload, following, fragment = run("ethertype", 0x86DD, packet)
    assert layer == IPv6Layer(
        source="2001:db8::5",
        destination="::ffff:10.0.0.1",
        next_header=17,
        hop_limit=64,
        payload_length=len(UDP),
        traffic_class=0,
        flow_label=0,
    )
    assert payload == UDP and following == (("ip", 17),) and fragment is None
    assert run("ethertype", 0x86DD, packet + bytes(9)).payload == UDP


@pytest.mark.parametrize(
    "address",
    [
        "2001:db8::5",
        "::ffff:10.0.0.1",
        "::ffff:a00:1",
        "::ffff:0.0.0.0",
        "fe80::1",
        "::",
        "::1",
    ],
)
def test_an_address_is_written_as_netimps_writes_it(address):
    """The dissector keeps its own copy of the rule for speed; the two agree."""
    expected = netimps.format_address(ipaddress.IPv6Address(address))
    packet = build.ipv6(address, address, UDP)
    layer = run("ethertype", 0x86DD, packet).layer
    assert layer.source == layer.destination == expected


@pytest.mark.parametrize("header", [0, 43, 60])
def test_an_ipv6_extension_header_is_skipped_whole(header):
    data = build.ipv6_extension(UDP, next_header=17, kind_length=1)
    data = data[:8] + bytes(8) + data[8:]
    layer, payload, following, _ = run("ip", header, data)
    assert layer == IPv6ExtensionLayer(17, bytes(14))
    assert payload == UDP and following == (("ip", 17),)


def test_an_ipv6_fragment_header():
    data = build.ipv6_fragment(bytes(16), offset=1232, more=True, ident=77)
    layer, payload, following, fragment = run("ip", 44, data)
    assert layer == IPv6FragmentLayer(17, 1232, True, 77) and layer.is_fragment
    assert payload == bytes(16) and following == (("ip", 17),)
    assert (fragment.offset, fragment.last) == (1232, False)
    atomic = run("ip", 44, build.ipv6_fragment(UDP))
    assert atomic.fragment is None and not atomic.layer.is_fragment


# -- transport ------------------------------------------------------------


def test_udp_tries_the_destination_port_then_the_source():
    layer, payload, following, _ = run("ip", 17, UDP)
    assert layer == UDPLayer(50000, 69, 8 + len(b"request"), 0)
    assert payload == b"request" and following == (("udp", 69), ("udp", 50000))


def test_udp_lengths():
    assert run("ip", 17, UDP + b"trailing").payload == b"request"
    assert run("ip", 17, build.udp(1, 2, b"abcdef", length=0)).payload == b"abcdef"
    cut = run("ip", 17, build.udp(1, 2, b"abc", length=500))
    assert cut.payload == b"abc" and cut.layer.length == 500


def test_tcp():
    options = bytes([2, 4, 5, 180, 1, 1, 1, 0])
    layer, payload, following, fragment = run(
        "ip", 6, tcp(payload=b"GET /", flags=0x12, options=options)
    )
    assert layer == TCPLayer(
        source_port=50000,
        destination_port=80,
        sequence=1000,
        acknowledgment=2000,
        flags=0x12,
        window=4096,
        checksum=0xABCD,
        urgent=7,
        options=options,
    )
    assert payload == b"GET /" and following == (("tcp", 80), ("tcp", 50000))
    assert fragment is None
    assert (layer.syn, layer.ack, layer.fin, layer.rst) == (True, True, False, False)


def test_tcp_flags_and_an_empty_segment():
    layer = run("ip", 6, tcp(payload=b"", flags=0x05)).layer
    assert (layer.fin, layer.rst, layer.syn, layer.ack) == (True, True, False, False)
    assert run("ip", 6, tcp(payload=b"")).payload == b""
    nine = bytearray(tcp())
    nine[12] |= 0x01  # the bit above CWR
    assert run("ip", 6, bytes(nine)).layer.flags == 0x118


# -- what is refused ------------------------------------------------------

LYING = [
    ("linktype", 1, build.ethernet(V4)[:13], "14 octets"),
    ("ethertype", 0x8100, b"\x00\x05\x08", "4 octets"),
    ("linktype", 113, bytes(15), "16 octets"),
    ("linktype", 276, bytes(19), "20 octets"),
    ("linktype", 0, bytes(3), "4 octets"),
    ("linktype", 108, bytes(3), "4 octets"),
    ("linktype", 101, b"", "empty"),
    ("ethertype", 0x0800, V4[:19], "at least 20"),
    ("ethertype", 0x0800, b"\x65" + V4[1:], "version 6"),
    ("ethertype", 0x0800, b"\x44" + V4[1:], "states a length"),
    ("ethertype", 0x0800, b"\x4f" + V4[1:], "states a length"),
    (
        "ethertype",
        0x0800,
        build.ipv4("10.0.0.5", "10.0.0.1", UDP, total=12),
        "shorter than",
    ),
    ("ethertype", 0x86DD, V6[:39], "40 octets"),
    ("ethertype", 0x86DD, b"\x45" + V6[1:], "version 4"),
    ("ip", 0, b"\x11", "at least 2"),
    ("ip", 60, b"\x11\x05" + bytes(6), "states a length"),
    ("ip", 44, bytes(7), "8 octets"),
    ("ip", 17, UDP[:7], "8 octets"),
    ("ip", 17, build.udp(1, 2, b"x", length=5), "under its header"),
    ("ip", 6, tcp()[:19], "at least 20"),
    ("ip", 6, tcp(offset=4), "states a length"),
    ("ip", 6, tcp(offset=15), "states a length"),
]


@pytest.mark.parametrize(
    "kind, value, data, problem",
    LYING,
    ids=["%s-%d-%d" % (k, v, i) for i, (k, v, _d, _p) in enumerate(LYING)],
)
def test_a_header_cut_short_or_lying_about_its_length_is_a_dissect_error(
    kind, value, data, problem
):
    with pytest.raises(DissectError, match=problem):
        run(kind, value, data)


# -- nothing else ever comes out ------------------------------------------

SAMPLES = {
    ("linktype", 0): [struct.pack("<I", 2) + V4, struct.pack(">I", 30) + V6],
    ("linktype", 1): [build.ethernet(V4), build.ethernet(V6, v6=True, vlans=2)],
    ("linktype", 108): [struct.pack(">I", 2) + V4],
    ("linktype", 113): [build.linux_sll(V4), build.linux_sll(V6, v6=True)],
    ("linktype", 276): [build.linux_sll2(V4), build.linux_sll2(V6, v6=True)],
    ("ethertype", 0x8100): [struct.pack("!HH", 100, 0x0800) + V4],
    ("ethertype", 0x0800): [
        V4,
        build.ipv4("10.0.0.5", "10.0.0.1", UDP, ihl=15),
        build.ipv4("10.0.0.5", "10.0.0.1", bytes(64), offset=64, more=True),
    ],
    ("ethertype", 0x86DD): [V6, build.ipv6("::1", "::2", bytes(64), next_header=44)],
    ("ip", 0): [
        build.ipv6_extension(UDP),
        build.ipv6_extension(bytes(64), kind_length=3),
    ],
    ("ip", 44): [build.ipv6_fragment(bytes(64), offset=64, more=True)],
    ("ip", 17): [UDP, build.udp(1, 2, bytes(64), length=0)],
    ("ip", 6): [tcp(), tcp(options=bytes(40), payload=bytes(64))],
}
RAW = [("linktype", n) for n in (12, 14, 101, 228, 229)]
ALIASES = {
    ("ethertype", 0x88A8): 0x8100,
    ("ethertype", 0x9100): 0x8100,
    ("ip", 43): 0,
    ("ip", 60): 0,
}


def _samples(selector):
    if selector in RAW:
        return [V4, V6]
    if selector in ALIASES:
        return SAMPLES[(selector[0], ALIASES[selector])]
    return SAMPLES[selector]


@pytest.mark.parametrize("selector", REGISTRY.selectors(), ids=lambda s: "%s-%d" % s)
def test_every_built_in_dissector_keeps_the_contract_whatever_it_is_given(selector):
    """The seeded fuzz: each returns a `Dissected` or raises `ValueError`."""
    check_dissector(
        REGISTRY.get(*selector), _samples(selector), rounds=5000, seed=20261005
    )


@pytest.mark.parametrize("selector", REGISTRY.selectors(), ids=lambda s: "%s-%d" % s)
def test_every_built_in_dissector_refuses_with_its_own_error(selector):
    dissector = REGISTRY.get(*selector)
    for size in range(0, 8):
        try:
            dissector(bytes(size))
        except DissectError:
            continue
