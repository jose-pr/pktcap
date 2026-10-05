"""The filter keys the built-in layers answer, through the shared grammar."""

import struct

import pytest

import captures as build
from pktcap import (
    FRAME_FILTER_KEYS,
    CapturedFrame,
    CaptureFilterError,
    Dissected,
    DissectorRegistry,
    FilterClause,
    FrameDissector,
    compile_capture_filter,
    frame_filter,
)

UDP = build.udp(50000, 69, b"request")
TCP = struct.pack("!HHIIBBHHH", 40000, 443, 1, 2, 5 << 4, 0x18, 512, 0, 0) + b"hello"
DISSECTOR = FrameDissector()


def frame(linktype, data):
    return DISSECTOR.dissect(CapturedFrame(0.0, linktype, data))


UDP4 = frame(1, build.ethernet(build.ipv4("10.0.0.5", "192.0.2.1", UDP), vlans=1))
TCP6 = frame(101, build.ipv6("2001:db8::5", "2001:db8::1", TCP, next_header=6))
MAPPED = frame(101, build.ipv6("::ffff:10.0.0.9", "::ffff:10.0.0.1", UDP))
ARP = frame(1, b"\x02" * 12 + b"\x08\x06" + bytes(28))
QINQ = frame(1, b"\x02" * 12 + b"\x88\xa8\x00\x64\x81\x00\x00\xc8\x08\x00" + bytes(20))


def matches(text, item):
    return compile_capture_filter(text, frame_filter)(item)


def test_the_keys_are_listed():
    assert FRAME_FILTER_KEYS == (
        "src",
        "dst",
        "host",
        "sport",
        "dport",
        "port",
        "proto",
        "vlan",
        "linktype",
    )


@pytest.mark.parametrize(
    "text, udp4, tcp6",
    [
        ("src=10.0.0.5", True, False),
        ("src=10.0.0.0/8", True, False),
        ("src=192.0.2.1", False, False),
        ("dst=192.0.2.0/24", True, False),
        ("host=192.0.2.1", True, False),
        ("host=2001:db8::/32", False, True),
        ("src=2001:db8::5", False, True),
        ("host=10.0.0.5,2001:db8::1", True, True),
        ("host!=10.0.0.5", False, True),
        ("sport=50000", True, False),
        ("dport=69", True, False),
        ("dport=443", False, True),
        ("port=69,443", True, True),
        ("port=40000", False, True),
        ("port=1", False, False),
        ("proto=udp", True, False),
        ("proto=tcp", False, True),
        ("proto=UDP,TCP", True, True),
        ("proto=ipv4", True, False),
        ("proto=ipv6", False, True),
        ("proto=ethernet", True, False),
        ("proto=17", True, False),
        ("proto=6", False, True),
        ("proto=icmp", False, False),
        ("vlan=5", True, False),
        ("vlan=6", False, False),
        ("linktype=1", True, False),
        ("linktype=101,105", False, True),
        ("proto=udp and dst=192.0.2.0/24 and port!=67", True, False),
        ("PORT=69", True, False),
    ],
)
def test_a_key_answers_from_the_layers_of_the_frame(text, udp4, tcp6):
    assert matches(text, UDP4) is udp4
    assert matches(text, TCP6) is tcp6


def test_a_frame_without_the_layer_matches_no_positive_clause_and_every_negated_one():
    for text in ("host=10.0.0.5", "port=69", "proto=udp", "vlan=5"):
        assert matches(text, ARP) is False
    for text in ("host!=10.0.0.5", "port!=69", "proto!=udp", "vlan!=5"):
        assert matches(text, ARP) is True
    assert matches("proto=ethernet and linktype=1", ARP) is True


def test_a_mapped_address_is_the_ipv4_host_it_stands_for():
    assert matches("src=10.0.0.0/8", MAPPED) and matches("host=10.0.0.9", MAPPED)
    assert not matches("src=::ffff:0:0/96", MAPPED)


def test_vlan_looks_at_every_tag():
    assert matches("vlan=100", QINQ) and matches("vlan=200", QINQ)
    assert not matches("vlan=300", QINQ)


def test_the_layer_of_a_registered_dissector_is_a_protocol_by_its_name():
    class TFTPLayer(dict):
        pass

    registry = DissectorRegistry()
    registry.register("udp", 69, lambda data: Dissected(TFTPLayer(op=1), data[2:]))
    item = FrameDissector(registry).dissect(UDP4.frame)
    assert matches("proto=tftp", item) and not matches("proto=tftp", UDP4)


@pytest.mark.parametrize(
    "text, problem",
    [
        ("colour=red", "unknown filter key 'colour'"),
        ("src=not-an-address", "src=not-an-address"),
        ("host=10.0.0.300", "host=10.0.0.300"),
        ("port=http", "port takes numbers from 0 to 65535"),
        ("port=65536", "port takes numbers"),
        ("dport=-1", "dport takes numbers"),
        ("sport=٣", "sport takes numbers"),
        ("vlan=4096", "vlan takes numbers from 0 to 4095"),
        ("linktype=ethernet", "linktype takes numbers"),
        ("port=,", "port has no value"),
    ],
)
def test_a_key_or_a_value_that_is_wrong_is_one_error_when_the_filter_is_compiled(
    text, problem
):
    with pytest.raises(CaptureFilterError, match=problem):
        compile_capture_filter(text, frame_filter)


def test_a_caller_adds_its_own_keys_and_falls_back_to_the_built_in_ones():
    def build_clause(clause):
        if clause.key == "big":
            return lambda item: len(item.frame.data) > 50
        return frame_filter(clause)

    wanted = compile_capture_filter("big=yes and proto=udp", build_clause)
    assert wanted(UDP4) and not wanted(TCP6)


def test_the_builder_is_usable_on_its_own():
    assert frame_filter(FilterClause("port", "69"))(UDP4) is True
    with pytest.raises(ValueError, match="unknown filter key"):
        frame_filter(FilterClause("colour", "red"))
