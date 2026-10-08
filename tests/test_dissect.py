"""The frame dissector: every frame comes back, with the layers that were
read and the rest as octets, and nothing a frame holds makes it raise."""

import io
import logging
import random
import struct

import pytest

import captures as build
from pktcap import (
    LINKTYPES,
    CapturedDatagram,
    CapturedFrame,
    Dissected,
    DissectedFrame,
    DissectorRegistry,
    DissectStats,
    EthernetLayer,
    FrameDissector,
    IPv4Layer,
    IPv6ExtensionLayer,
    IPv6Layer,
    LinuxCookedLayer,
    LoopbackLayer,
    TCPLayer,
    UDPLayer,
    VLANLayer,
    default_registry,
    read_datagrams,
    read_dissected,
)

UDP = build.udp(50000, 69, b"request")
V4 = build.ipv4("10.0.0.5", "10.0.0.1", UDP)
V6 = build.ipv6("2001:db8::5", "2001:db8::1", UDP)
WANT_V4 = CapturedDatagram(1.5, ("10.0.0.5", 50000), ("10.0.0.1", 69), b"request")
WANT_V6 = CapturedDatagram(1.5, ("2001:db8::5", 50000), ("2001:db8::1", 69), b"request")
TCP = struct.pack("!HHIIBBHHH", 50000, 80, 1, 2, 5 << 4, 0x18, 512, 0, 0) + b"GET /"


def dissect(linktype, data, registry=None, **options):
    dissector = FrameDissector(registry, **options)
    return dissector.dissect(CapturedFrame(1.5, linktype, data)), dissector.stats


def kinds(frame):
    return [type(layer) for layer in frame.layers]


# -- the layers of a frame ------------------------------------------------


def test_a_frame_is_walked_layer_by_layer():
    frame, stats = dissect(1, build.ethernet(V4, vlans=1))
    assert isinstance(frame, DissectedFrame)
    assert kinds(frame) == [EthernetLayer, VLANLayer, IPv4Layer, UDPLayer]
    assert frame.payloads[2] == UDP and frame.payload == b"request"
    assert frame.error is None and not frame.reassembled and frame.time == 1.5
    assert frame.layer(VLANLayer).id == 5
    assert frame.layer(IPv4Layer).source == "10.0.0.5"
    assert frame.layer(TCPLayer) is None
    assert frame.payload_of(IPv4Layer) == UDP and frame.payload_of(TCPLayer) is None
    assert stats == DissectStats(1, 0, 0, 0, 0, 0, 0)


@pytest.mark.parametrize(
    "linktype, data, link",
    [
        (1, build.ethernet(V4), [EthernetLayer]),
        (1, build.ethernet(V4, vlans=2), [EthernetLayer, VLANLayer, VLANLayer]),
        (12, V4, []),
        (14, V4, []),
        (101, V4, []),
        (228, V4, []),
        (113, build.linux_sll(V4), [LinuxCookedLayer]),
        (276, build.linux_sll2(V4), [LinuxCookedLayer]),
        (0, struct.pack("<I", 2) + V4, [LoopbackLayer]),
        (0, struct.pack(">I", 2) + V4, [LoopbackLayer]),
        (108, struct.pack(">I", 2) + V4, [LoopbackLayer]),
    ],
)
def test_ipv4_udp_is_found_under_every_link_type(linktype, data, link):
    frame, _stats = dissect(linktype, data)
    assert kinds(frame) == link + [IPv4Layer, UDPLayer]
    assert frame.datagram() == WANT_V4


@pytest.mark.parametrize(
    "linktype, data",
    [
        (1, build.ethernet(V6, v6=True)),
        (101, V6),
        (229, V6),
        (113, build.linux_sll(V6, v6=True)),
        (276, build.linux_sll2(V6, v6=True)),
        (0, struct.pack("<I", 30) + V6),
        (0, struct.pack("<I", 10) + V6),
        (108, struct.pack(">I", 24) + V6),
    ],
)
def test_ipv6_udp_is_found_under_every_link_type(linktype, data):
    frame, _stats = dissect(linktype, data)
    assert kinds(frame)[-2:] == [IPv6Layer, UDPLayer]
    assert frame.datagram() == WANT_V6


def test_tcp_is_a_header_and_the_segment_after_it():
    frame, _stats = dissect(
        1, build.ethernet(build.ipv4("10.0.0.5", "10.0.0.1", TCP, protocol=6))
    )
    assert kinds(frame) == [EthernetLayer, IPv4Layer, TCPLayer]
    segment = frame.layer(TCPLayer)
    assert (segment.source_port, segment.destination_port) == (50000, 80)
    assert segment.ack and not segment.syn and frame.payload == b"GET /"
    assert frame.datagram() is None


def test_ipv6_extension_headers_are_layers():
    body = build.ipv6_extension(
        build.ipv6_extension(UDP, next_header=17), next_header=60
    )
    frame, _stats = dissect(
        101, build.ipv6("2001:db8::5", "2001:db8::1", body, next_header=0)
    )
    assert kinds(frame) == [IPv6Layer, IPv6ExtensionLayer, IPv6ExtensionLayer, UDPLayer]
    assert frame.datagram() == WANT_V6


def test_the_table_of_link_types_matches_the_built_ins_and_cannot_be_changed():
    assert set(LINKTYPES) == {0, 1, 12, 14, 101, 108, 113, 228, 229, 276}
    with pytest.raises(TypeError):
        LINKTYPES[105] = "IEEE802_11"


# -- what is not known comes back undecoded -------------------------------

ARP = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x06" + bytes(range(28))


@pytest.mark.parametrize(
    "linktype, data, layers, payload",
    [
        (1, ARP, [EthernetLayer], bytes(range(28))),
        (
            1,
            build.ethernet(build.ipv4("10.0.0.5", "10.0.0.1", b"icmp....", protocol=1)),
            [EthernetLayer, IPv4Layer],
            b"icmp....",
        ),
        (
            101,
            build.ipv6("::1", "::2", b"icmpv6..", next_header=58),
            [IPv6Layer],
            b"icmpv6..",
        ),
        (0, struct.pack("<I", 7) + b"appletalk", [LoopbackLayer], b"appletalk"),
        (
            113,
            struct.pack("!HHH8sH", 0, 1, 6, b"", 0x0806) + b"arp",
            [LinuxCookedLayer],
            b"arp",
        ),
    ],
)
def test_an_unknown_ethertype_or_protocol_ends_the_walk_without_an_error(
    linktype, data, layers, payload
):
    frame, stats = dissect(linktype, data)
    assert kinds(frame) == layers and frame.payload == payload
    assert frame.error is None and frame.datagram() is None
    assert stats == DissectStats(1, 0, 0, 0, 0, 0, 0)


def test_an_unknown_link_type_comes_back_whole_and_is_counted():
    frame, stats = dissect(105, b"radiotap and 802.11")
    assert frame.layers == () and frame.payloads == ()
    assert frame.payload == b"radiotap and 802.11" and frame.error is None
    assert stats.unsupported == 1 and stats.malformed == 0


def test_udp_to_a_port_nobody_registered_leaves_the_payload():
    frame, _stats = dissect(101, V4)
    assert frame.payload == b"request" and frame.layer(UDPLayer).destination_port == 69


# -- what a dissector cannot read ----------------------------------------


@pytest.mark.parametrize(
    "linktype, data, read, problem",
    [
        (1, b"\x02" * 13, [], "linktype 1: an Ethernet header is 14 octets"),
        (1, build.ethernet(V4[:19]), [EthernetLayer], "ethertype 2048: an IPv4 header"),
        (1, build.ethernet(V4[:24]), [EthernetLayer, IPv4Layer], "ip 17: a UDP header"),
        (101, b"\x44" + V4[1:], [], "ethertype 2048: an IPv4 header states"),
        (
            101,
            b"\x05" + V4[1:],
            [],
            "linktype 101: a raw IP frame starts with version 0",
        ),
        (101, V6[:39], [], "ethertype 34525: an IPv6 header is 40 octets"),
        (
            101,
            build.ipv4("10.0.0.5", "10.0.0.1", build.udp(1, 2, b"x", length=5)),
            [IPv4Layer],
            "ip 17: a UDP datagram states a length under its header",
        ),
        (276, bytes(19), [], "linktype 276"),
    ],
)
def test_a_layer_cut_short_or_lying_is_left_undecoded_and_counted(
    linktype, data, read, problem
):
    frame, stats = dissect(linktype, data)
    assert kinds(frame) == read
    assert frame.error is not None and frame.error.startswith(problem)
    assert (stats.malformed, stats.failed, stats.unsupported) == (1, 0, 0)


def test_the_octets_a_dissector_could_not_read_are_the_frames_payload():
    frame, _stats = dissect(1, build.ethernet(V4[:19]))
    assert frame.payload == V4[:19]
    whole, _stats = dissect(1, b"\x02" * 13)
    assert whole.payload == b"\x02" * 13


def test_a_datagram_cut_by_the_snap_length_is_marked_truncated():
    v4 = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"p" * 200))
    v6 = build.ipv6("::1", "::2", build.udp(1, 2, b"p" * 200))
    for packet, kept in ((v4[:96], 96 - 28), (v6[:96], 96 - 48)):
        frame, stats = dissect(101, packet)
        datagram = frame.datagram()
        assert datagram.truncated and not datagram.fragmented
        assert datagram.payload == b"p" * kept and stats.malformed == 0
    assert not dissect(101, v4)[0].datagram().truncated


def test_a_mapped_address_reads_the_same_on_every_python():
    packet = build.ipv6("::ffff:10.0.0.5", "::ffff:10.0.0.1", build.udp(1, 2, b"x"))
    datagram = dissect(101, packet)[0].datagram()
    assert datagram.source == ("::ffff:10.0.0.5", 1)
    assert datagram.destination == ("::ffff:10.0.0.1", 2)


# -- what a hostile frame can cost ----------------------------------------


def _tagged(count):
    return b"\x02" * 12 + b"\x81\x00\x00\x05" * count + b"\x08\x00" + V4


def _chained(count):
    body = UDP
    for index in range(count):
        body = build.ipv6_extension(body, next_header=17 if index == 0 else 60)
    return build.ipv6("::1", "::2", body, next_header=60)


def test_a_frame_is_dissected_at_most_thirty_two_deep():
    """A tag stack or a chain of extension headers is cut off at the ceiling,
    however long the frame says it is."""
    deepest, _ = dissect(1, _tagged(29))  # Ethernet, 29 tags, IPv4, UDP
    assert len(deepest.layers) == 32 and deepest.datagram() == WANT_V4
    # Raw IP spends one of the 32 on choosing between IPv4 and IPv6.
    for linktype, data, layers in ((1, _tagged(40), 32), (101, _chained(40), 31)):
        frame, stats = dissect(linktype, data)
        assert len(frame.layers) == layers
        assert frame.error == "more than 32 dissectors deep"
        assert stats.malformed == 1 and frame.datagram() is None


def test_a_frame_of_nothing_but_headers_costs_what_the_ceiling_costs():
    huge = build.ipv6(
        "::1", "::2", bytes([60, 0, 0, 0, 0, 0, 0, 0]) * 32000, next_header=60, length=0
    )
    frame, stats = dissect(101, huge)
    assert len(frame.layers) == 31 and stats.malformed == 1


def test_addresses_that_never_repeat_cannot_make_the_kept_texts_grow_without_end():
    """An IPv6 address keeps its text, since a capture names few hosts. A capture
    whose every frame names two new ones stops at the bound, and each is still
    written as it would have been."""
    import importlib
    import ipaddress

    # The one private name here: the count of kept texts is not public.
    kept = importlib.import_module("pktcap._dissectors._network")._ipv6_text
    dissector = FrameDissector()
    for number in range(1500):
        source = ipaddress.IPv6Address((0x20010DB8 << 96) | (number * 2 + 1))
        target = ipaddress.IPv6Address((0x20010DB8 << 96) | (number * 2 + 2))
        frame = dissector.dissect(
            CapturedFrame(0.0, 101, build.ipv6(str(source), str(target), UDP))
        )
        assert frame.datagram().source == (str(source), 50000)
        assert frame.datagram().destination == (str(target), 69)
    assert kept.cache_info().maxsize == 1024
    assert kept.cache_info().currsize <= 1024


def test_a_registry_that_answers_get_itself_is_the_one_the_walk_asks():
    """A subclass that answers ``get`` is asked for every layer: a walk that
    read the registry's table directly, to save the call, would pass it by."""
    asked = []

    class Recording(DissectorRegistry):
        def get(self, kind, value):
            asked.append((kind, value))
            if (kind, value) == ("udp", 69):
                return _tftp
            return super().get(kind, value)

    frame, _ = dissect(101, V4, Recording())
    assert kinds(frame)[-1] is dict
    assert asked[0] == ("linktype", 101) and ("udp", 69) in asked


@pytest.mark.parametrize("linktype", sorted(LINKTYPES) + [105])
def test_a_mutated_frame_never_raises(linktype):
    """Seeded fuzz: whatever a frame holds, `dissect` returns the frame."""
    random.seed(20261005 + linktype)
    first = build.udp(7, 9, b"f" * 64)
    seeds = [
        build.ethernet(V4, vlans=1),
        build.ethernet(V6, v6=True),
        build.ethernet(build.ipv4("10.0.0.5", "10.0.0.1", TCP, protocol=6)),
        build.linux_sll(V4),
        build.linux_sll2(V6, v6=True),
        struct.pack("<I", 2) + V4,
        V4,
        V6,
        _chained(3),
        build.ipv4("10.0.0.5", "10.0.0.1", first[:32], more=True),
        build.ipv4("10.0.0.5", "10.0.0.1", first[32:], offset=32),
        build.ipv6(
            "::1", "::2", build.ipv6_fragment(first[:32], more=True), next_header=44
        ),
        build.ipv6(
            "::1", "::2", build.ipv6_fragment(first[32:], offset=32), next_header=44
        ),
    ]
    dissector = FrameDissector(max_reassemblies=16)
    for index in range(5000):
        data = bytearray(random.choice(seeds))
        for _ in range(random.randint(0, 3)):
            position = random.randrange(len(data))
            if random.random() < 0.7:
                data[position] = random.randrange(256)
            else:
                data = data[:position] or bytearray(1)
        raw = bytes(data)
        frame = dissector.dissect(CapturedFrame(index * 0.001, linktype, raw))
        assert isinstance(frame, DissectedFrame) and frame.frame.data == raw
        assert len(frame.layers) == len(frame.payloads) <= 32
        assert all(isinstance(p, bytes) for p in frame.payloads)
    stats = dissector.stats
    assert stats.frames == 5000 and stats.failed == 0 and stats.pending <= 16


# -- a registered dissector ----------------------------------------------


def _tftp(data):
    if len(data) < 2:
        raise ValueError("a TFTP packet is at least 2 octets")
    return Dissected({"opcode": (data[0] << 8) | data[1]}, data[2:])


def test_a_protocol_registers_its_own_dissector_and_the_datagram_view_keeps_its_payload():
    registry = DissectorRegistry()
    registry.register("udp", 69, _tftp)
    packet = build.ipv4(
        "10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"\x00\x01file\x00")
    )
    frame, _stats = dissect(101, packet, registry)
    assert frame.layers[-1] == {"opcode": 1} and frame.payload == b"file\x00"
    assert frame.layer(dict) == {"opcode": 1}
    assert frame.datagram().payload == b"\x00\x01file\x00"
    reply = build.ipv4(
        "10.0.0.1", "10.0.0.5", build.udp(69, 50000, b"\x00\x04\x00\x01")
    )
    assert dissect(101, reply, registry)[0].layers[-1] == {
        "opcode": 4
    }  # by source port


def test_udp_that_is_not_over_ip_has_no_datagram_view():
    """A datagram has two socket addresses, and only an IP layer gives them."""
    registry = DissectorRegistry()
    registry.register("linktype", 147, registry.get("ip", 17))
    frame = FrameDissector(registry).dissect(CapturedFrame(0.0, 147, UDP))
    assert [type(layer) for layer in frame.layers] == [UDPLayer]
    assert frame.datagram() is None and frame.payload == b"request"


def test_a_registry_is_private_to_the_dissector_it_was_given_to():
    registry = DissectorRegistry()
    registry.register("udp", 69, _tftp)
    assert kinds(dissect(101, V4, registry)[0])[-1] is dict
    assert kinds(dissect(101, V4)[0])[-1] is UDPLayer
    assert default_registry().get("udp", 69) is None
    assert FrameDissector(registry).registry is registry
    assert FrameDissector().registry is default_registry()


def test_a_dissector_registered_later_is_used_from_then_on():
    registry = DissectorRegistry()
    dissector = FrameDissector(registry)
    frame = CapturedFrame(0.0, 101, V4)
    assert kinds(dissector.dissect(frame))[-1] is UDPLayer
    registry.register("udp", 69, _tftp)
    assert kinds(dissector.dissect(frame))[-1] is dict


def test_an_empty_registry_decodes_nothing_and_says_so():
    frame, stats = dissect(1, build.ethernet(V4), DissectorRegistry(builtins=False))
    assert frame.layers == () and stats.unsupported == 1


def test_a_registered_dissector_that_cannot_read_its_octets_is_malformed():
    registry = DissectorRegistry()
    registry.register("udp", 69, _tftp)
    packet = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"\x00"))
    frame, stats = dissect(101, packet, registry)
    assert kinds(frame) == [IPv4Layer, UDPLayer] and frame.payload == b"\x00"
    assert frame.error == "udp 69: a TFTP packet is at least 2 octets"
    assert (stats.malformed, stats.failed) == (1, 0)
    assert frame.datagram().payload == b"\x00"


def _broken(data):
    return Dissected({}, data[{}["missing"] :])


@pytest.mark.parametrize(
    "dissector, raised",
    [
        (_broken, "KeyError"),
        (lambda data: ({}, data), "TypeError"),
        (lambda data: Dissected({}, "text"), "TypeError"),
        (lambda data: 1 // 0, "ZeroDivisionError"),
    ],
)
def test_a_registered_dissector_that_fails_does_not_take_the_reader_down(
    dissector, raised, caplog
):
    registry = DissectorRegistry()
    registry.register("udp", 69, dissector)
    frames = FrameDissector(registry)
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        results = [frames.dissect(CapturedFrame(0.0, 101, V4)) for _ in range(3)]
    for frame in results:
        assert kinds(frame) == [IPv4Layer, UDPLayer] and frame.payload == b"request"
        assert frame.error == "udp 69: the dissector raised %s" % raised
        assert frame.datagram() == WANT_V4._replace(time=0.0)
    assert frames.stats.failed == 3 and frames.stats.malformed == 0
    assert [r.getMessage() for r in caplog.records] == [
        "the dissector for udp 69 raised %s; frames it fails on keep that "
        "layer undecoded and are counted" % raised
    ]


def test_failing_dissectors_cannot_make_the_log_grow_without_end(caplog):
    registry = DissectorRegistry()
    for port in range(1000, 1100):
        registry.register("udp", port, _broken)
    frames = FrameDissector(registry)
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        for port in range(1000, 1100):
            packet = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(1, port, b"x"))
            frames.dissect(CapturedFrame(0.0, 101, packet))
    assert frames.stats.failed == 100 and len(caplog.records) == 8


# -- reading a capture ----------------------------------------------------


def test_every_frame_of_a_capture_comes_back_dissected():
    data = build.pcapng([build.ethernet(V4), ARP, build.ethernet(V4)[:20]])
    frames = list(read_dissected(io.BytesIO(data)))
    assert [len(f.layers) for f in frames] == [3, 1, 1]
    assert [f.error is None for f in frames] == [True, True, False]
    assert all(f.frame.interface == 0 for f in frames)
    assert frames[0].time == pytest.approx(1_000_000)


def test_read_datagrams_is_the_udp_view_of_the_same_walk():
    data = build.pcapng([build.ethernet(V4), ARP])
    dissector = FrameDissector()
    (datagram,) = list(read_datagrams(io.BytesIO(data), dissector=dissector))
    assert datagram == WANT_V4._replace(time=datagram.time)
    assert dissector.stats.frames == 2


def test_a_capture_of_another_link_type_is_told_from_an_empty_one():
    dissector = FrameDissector()
    data = build.pcap([build.ethernet(V4)], linktype=105) + build.pcap_record(b"x")
    assert list(read_datagrams(io.BytesIO(data), dissector=dissector)) == []
    assert dissector.stats.unsupported == 2 and dissector.stats.frames == 2
    assert dissector.unsupported_linktypes == {105: 2}
    assert len(list(read_dissected(io.BytesIO(data)))) == 2


def test_the_link_types_with_no_dissector_are_counted_by_number():
    dissector = FrameDissector()
    assert dissector.unsupported_linktypes == {}
    for linktype in (105, 1, 105, 127):
        dissector.dissect(CapturedFrame(1.0, linktype, build.ethernet(V4)))
    counted = dissector.unsupported_linktypes
    assert counted == {105: 2, 127: 1} and dissector.stats.unsupported == 3
    with pytest.raises(TypeError):
        counted[1] = 1
    dissector.dissect(CapturedFrame(1.0, 105, b""))
    assert counted == {105: 2, 127: 1}
    assert dissector.unsupported_linktypes == {105: 3, 127: 1}


def test_only_so_many_distinct_link_types_are_told_apart():
    dissector = FrameDissector()
    for linktype in range(1000, 1100):
        dissector.dissect(CapturedFrame(1.0, linktype, b"x"))
    dissector.dissect(CapturedFrame(1.0, 1000, b"x"))
    counted = dissector.unsupported_linktypes
    assert len(counted) == 64 and counted[1000] == 2 and 1099 not in counted
    assert dissector.stats.unsupported == 101


def test_a_pcap_frame_has_no_interface_number():
    (frame,) = read_dissected(io.BytesIO(build.pcap([build.ethernet(V4)])))
    assert frame.frame.interface is None


def test_the_readers_check_their_arguments_at_the_call():
    with pytest.raises(TypeError):
        read_datagrams(None)
    for reader in (read_datagrams, read_dissected):
        with pytest.raises(TypeError, match="FrameDissector"):
            reader(io.BytesIO(b""), dissector=object())
        with pytest.raises(ValueError):
            reader(io.BytesIO(b""), max_frame_size=0)


@pytest.mark.parametrize(
    "options, error",
    [
        ({"max_reassemblies": 0}, ValueError),
        ({"max_reassemblies": 1.5}, TypeError),
        ({"max_reassemblies": True}, TypeError),
        ({"reassembly_timeout": 0}, ValueError),
        ({"reassembly_timeout": float("nan")}, ValueError),
        ({"registry": {}}, TypeError),
    ],
)
def test_a_frame_dissector_refuses_a_bad_option(options, error):
    with pytest.raises(error):
        FrameDissector(**options)
