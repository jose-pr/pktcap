"""``frame_summary`` and the ``summary()`` of each built-in layer: one line a
person reads, safe to print whatever the wire held.

Expected lines are written from the arguments of the builders in
``captures.py``, not from the code under test.
"""

import logging
import re
import time
from typing import NamedTuple

import pytest

import captures as build
from pktcap import (
    CapturedFrame,
    Dissected,
    DissectedFrame,
    DissectorRegistry,
    EthernetLayer,
    FrameDissector,
    IPv4Layer,
    IPv6ExtensionLayer,
    IPv6FragmentLayer,
    IPv6Layer,
    LinuxCookedLayer,
    LoopbackLayer,
    TCPLayer,
    UDPLayer,
    VLANLayer,
    frame_summary,
)

WHEN = 1_700_000_000.5
STAMP = "2023-11-14T22:13:20.500000Z"


def dissect(raw, linktype=1, registry=None, when=WHEN):
    return FrameDissector(registry).dissect(CapturedFrame(when, linktype, raw))


def udp_frame(sport=50000, dport=69, payload=b"first"):
    return build.ethernet(
        build.ipv4("10.0.0.5", "10.0.0.1", build.udp(sport, dport, payload))
    )


class Demo(NamedTuple):
    opcode: int


class Spoken(NamedTuple):
    opcode: int

    def summary(self):
        return "opcode %d" % self.opcode


def registry_with(layer_class, port=9999):
    registry = DissectorRegistry()
    registry.register_layer(layer_class, name=layer_class.__name__.lower())
    registry.register(
        "udp", port, lambda data: Dissected(layer_class(data[0]), data[1:])
    )
    return registry


def demo_frame(layer_class, port=9999, payload=b"\x07rest"):
    return dissect(
        udp_frame(dport=port, payload=payload),
        registry=registry_with(layer_class, port),
    )


# -- the summary of each built-in layer ------------------------------------------


def test_every_built_in_layer_has_a_summary_method():
    for layer_class in (
        EthernetLayer,
        VLANLayer,
        LinuxCookedLayer,
        LoopbackLayer,
        IPv4Layer,
        IPv6Layer,
        IPv6ExtensionLayer,
        IPv6FragmentLayer,
        UDPLayer,
        TCPLayer,
    ):
        assert callable(layer_class.summary), layer_class.__name__


def test_the_summaries_of_an_ethernet_ipv4_udp_frame():
    ethernet, ipv4, udp = dissect(udp_frame()).layers
    assert (
        ethernet.summary() == "04:04:04:04:04:04 > 02:02:02:02:02:02 ethertype 0x0800"
    )
    assert ipv4.summary() == "10.0.0.5 > 10.0.0.1 protocol 17 ttl 64 id 1"
    assert udp.summary() == "50000 > 69 length 13"


def test_the_summary_of_a_fragment_says_where_it_starts_and_that_more_follow():
    frame = dissect(
        build.ethernet(
            build.ipv4(
                "10.0.0.5", "10.0.0.1", b"x" * 16, offset=1480, more=True, ident=7
            )
        )
    )
    ipv4 = frame.layer(IPv4Layer)
    assert ipv4.summary() == (
        "10.0.0.5 > 10.0.0.1 protocol 17 ttl 64 id 7, fragment at 1480, more follow"
    )


def test_the_summaries_of_a_tagged_ipv6_tcp_frame():
    segment = build.tcp(40000, 80, b"GET", flags=0x12, sequence=100, acknowledgment=7)
    raw = build.ethernet(
        build.ipv6("2001:db8::5", "2001:db8::1", segment, next_header=6),
        vlans=1,
        v6=True,
    )
    frame = dissect(raw)
    vlan = frame.layer(VLANLayer)
    ipv6 = frame.layer(IPv6Layer)
    tcp = frame.layer(TCPLayer)
    assert vlan.summary() == "vlan 5 priority 0 ethertype 0x86dd"
    assert ipv6.summary() == "2001:db8::5 > 2001:db8::1 next header 6 hop limit 64"
    assert tcp.summary() == "40000 > 80 [SYN,ACK] seq 100 ack 7 window 4096"


def test_a_tcp_segment_with_no_flag_says_none():
    segment = build.tcp(1, 2, b"", flags=0)
    frame = dissect(
        build.ethernet(build.ipv4("10.0.0.5", "10.0.0.1", segment, protocol=6))
    )
    assert (
        frame.layer(TCPLayer).summary() == "1 > 2 [none] seq 1000 ack 2000 window 4096"
    )


def test_the_summaries_of_ipv6_extension_and_fragment_headers():
    fragment = build.ipv6_fragment(b"abcdefgh", offset=16, more=True, ident=77)
    extension = build.ipv6_extension(fragment, next_header=44)
    raw = build.ethernet(
        build.ipv6("2001:db8::5", "2001:db8::1", extension, next_header=0), v6=True
    )
    frame = dissect(raw)
    assert frame.layer(IPv6ExtensionLayer).summary() == "next header 44, 6 octets"
    assert frame.layer(IPv6FragmentLayer).summary() == (
        "next header 17, id 77, offset 16, more follow"
    )


def test_the_summaries_of_a_cooked_capture_and_a_loopback_header():
    ip = build.ipv4("10.0.0.5", "10.0.0.1", build.udp(1, 2, b""))
    cooked = dissect(build.linux_sll2(ip), linktype=276).layer(LinuxCookedLayer)
    assert cooked.summary() == "host, hardware type 772, ethertype 0x0800"
    cooked1 = dissect(build.linux_sll(ip), linktype=113).layer(LinuxCookedLayer)
    assert cooked1.summary() == "host, hardware type 772, ethertype 0x0800"
    loopback = dissect(b"\x02\x00\x00\x00" + ip, linktype=0).layer(LoopbackLayer)
    assert loopback.summary() == "family 2"
    assert LinuxCookedLayer(4, 1, "aabbcc", 0x86DD).summary() == (
        "outgoing, hardware type 1, address aabbcc, ethertype 0x86dd"
    )
    assert LinuxCookedLayer(9, 1, "", 0x0800).summary().startswith("type 9,")


def test_a_summary_is_a_single_line_of_text():
    for layer in dissect(udp_frame()).layers:
        text = layer.summary()
        assert isinstance(text, str) and "\n" not in text and text


# -- the line of a frame -------------------------------------------------------------


def test_a_udp_frame_is_its_time_both_socket_addresses_and_its_innermost_layer():
    assert frame_summary(dissect(udp_frame())) == (
        STAMP + " 10.0.0.5:50000 > 10.0.0.1:69 udp: 50000 > 69 length 13"
    )


def test_an_ipv6_address_is_in_brackets_beside_its_port():
    raw = build.ethernet(
        build.ipv6("2001:db8::5", "2001:db8::1", build.udp(546, 547, b"x")), v6=True
    )
    assert frame_summary(dissect(raw)).startswith(
        STAMP + " [2001:db8::5]:546 > [2001:db8::1]:547 udp:"
    )


def test_a_tcp_frame_has_its_socket_addresses_too():
    raw = build.tcp_frame("10.0.0.5", "10.0.0.1", 40000, 80, 100, b"x", flags=0x02)
    assert frame_summary(dissect(raw)) == (
        STAMP
        + " 10.0.0.5:40000 > 10.0.0.1:80 tcp: 40000 > 80 [SYN] seq 100 ack 0 window 4096"
    )


def test_a_packet_with_no_transport_has_hosts_and_no_ports():
    raw = build.ethernet(
        build.ipv4("10.0.0.5", "10.0.0.1", b"\x08\x00\x00\x00", protocol=1)
    )
    assert frame_summary(dissect(raw)) == (
        STAMP + " 10.0.0.5 > 10.0.0.1 ipv4: 10.0.0.5 > 10.0.0.1 protocol 1 ttl 64 id 1"
    )


def test_a_frame_with_no_addresses_has_none_in_its_line():
    arp = b"\x02" * 12 + b"\x08\x06" + bytes(28)
    assert frame_summary(dissect(arp)) == (
        STAMP + " ethernet: 02:02:02:02:02:02 > 02:02:02:02:02:02 ethertype 0x0806"
    )


def test_a_frame_nothing_dissects_is_its_link_type_and_size():
    assert frame_summary(dissect(b"\x01\x02\x03", linktype=147)) == (
        STAMP + " linktype 147, 3 octets"
    )


def test_the_outermost_ip_layer_gives_the_addresses():
    inner = build.ipv4("10.9.9.9", "10.9.9.8", build.udp(1, 2, b""))
    raw = build.ethernet(build.ipv4("10.0.0.5", "10.0.0.1", inner, protocol=4))
    assert " 10.0.0.5 > 10.0.0.1 " in frame_summary(dissect(raw))


def test_the_summary_of_a_registered_layer_is_used():
    text = frame_summary(demo_frame(Spoken))
    assert text == STAMP + " 10.0.0.5:50000 > 10.0.0.1:9999 spoken: opcode 7"


def test_a_layer_without_a_summary_is_described_by_its_name():
    assert frame_summary(demo_frame(Demo)) == (
        STAMP + " 10.0.0.5:50000 > 10.0.0.1:9999 demo"
    )


def test_a_layer_that_is_a_mapping_is_described_by_its_name():
    class MappingLayer(dict):
        pass

    frame = dissect(udp_frame())._replace(layers=(MappingLayer(a=1),), payloads=(b"",))
    assert frame_summary(frame) == STAMP + " mapping"


def test_a_field_named_summary_is_not_a_summary_method():
    class Holds(NamedTuple):
        summary: str

    frame = dissect(udp_frame())
    frame = frame._replace(
        layers=frame.layers + (Holds("a field"),), payloads=frame.payloads + (b"",)
    )
    assert frame_summary(frame).endswith(" 10.0.0.1:69 holds")


# -- a summary that fails ---------------------------------------------------------------


def failing(kind):
    """A new layer class whose summary fails in the way ``kind`` says; a new
    class each time, since a failing class is logged once for its life."""

    def raises(self):
        raise RuntimeError("boom with " + "x" * 5000)

    behaviours = {
        "Raises": raises,
        "NotText": lambda self: 42,
        "BytesBack": lambda self: b"bytes",
    }

    class Layer(NamedTuple):
        opcode: int

    Layer.__name__ = Layer.__qualname__ = kind
    Layer.summary = behaviours[kind]
    return Layer


KINDS = ["Raises", "NotText", "BytesBack"]


@pytest.mark.parametrize("kind", KINDS)
def test_a_summary_that_fails_leaves_the_layer_described_by_its_name(kind, caplog):
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        text = frame_summary(demo_frame(failing(kind)))
    assert text == STAMP + " 10.0.0.5:50000 > 10.0.0.1:9999 " + kind.lower()


@pytest.mark.parametrize("kind", KINDS)
def test_the_failure_of_a_layer_class_is_logged_once(kind, caplog):
    frame = demo_frame(failing(kind))
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        for _ in range(5):
            frame_summary(frame)
    lines = [r.getMessage() for r in caplog.records if kind in r.getMessage()]
    assert len(lines) == 1
    assert len(lines[0]) < 400 and "x" * 100 not in lines[0]  # the message is bounded


def test_each_failing_class_is_logged_for_itself(caplog):
    first, second = failing("Raises"), failing("NotText")
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        frame_summary(demo_frame(first))
        frame_summary(demo_frame(second))
        frame_summary(demo_frame(first))
        frame_summary(demo_frame(failing("Raises")))  # another class of the same name
    names = [r.getMessage() for r in caplog.records]
    assert sum("Raises" in n for n in names) == 2
    assert sum("NotText" in n for n in names) == 1


def test_a_failing_summary_does_not_stop_the_next_frame(caplog):
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        assert "udp:" in frame_summary(dissect(udp_frame()))
        frame_summary(demo_frame(failing("Raises")))
        assert "udp:" in frame_summary(dissect(udp_frame()))


def test_a_keyboard_interrupt_in_a_summary_is_not_swallowed():
    class Interrupts(NamedTuple):
        opcode: int

        def summary(self):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        frame_summary(demo_frame(Interrupts))


# -- text from the wire -----------------------------------------------------------------


class Wire(NamedTuple):
    opcode: int
    text: str = ""

    def summary(self):
        return self.text


def wire_frame(text):
    frame = dissect(udp_frame())
    return frame._replace(
        layers=frame.layers + (Wire(1, text),), payloads=frame.payloads + (b"",)
    )


def test_a_terminal_control_sequence_is_escaped():
    line = frame_summary(wire_frame("name \x1b[31mred\x1b]0;title\x07 \x00 \n\r\t end"))
    assert "\x1b" not in line and "\x07" not in line and "\x00" not in line
    assert "\\x1b[31mred\\x1b]0;title\\x07 \\x00 \\n\\r\\t end" in line


def test_a_lone_surrogate_and_non_ascii_text_are_escaped():
    line = frame_summary(wire_frame("a\ud800b é 中 \U0001f600"))
    assert line.endswith("wire: a\\ud800b \\xe9 \\u4e2d \\U0001f600")


def test_a_line_is_printable_ascii_on_one_line():
    line = frame_summary(wire_frame("".join(chr(c) for c in range(0, 300))))
    assert re.fullmatch(r"[ -~]+", line)


def test_a_backslash_in_wire_text_cannot_forge_an_escape():
    line = frame_summary(wire_frame("\\x1b[31m"))
    assert line.endswith("wire: \\\\x1b[31m")


def test_a_line_is_cut_at_512_characters_with_a_mark():
    line = frame_summary(wire_frame("a" * 10_000))
    assert len(line) == 512 and line.endswith("...")
    assert line.startswith(STAMP + " 10.0.0.5:50000 > 10.0.0.1:69 wire: aaaa")


def test_a_line_of_exactly_512_characters_is_not_cut():
    named = len(frame_summary(wire_frame("")))  # the layer's name alone
    exact = frame_summary(wire_frame("a" * (512 - named - 2)))  # ": " joins them
    assert len(exact) == 512 and not exact.endswith("...")
    over = frame_summary(wire_frame("a" * (512 - named - 1)))
    assert len(over) == 512 and over.endswith("...")


def test_a_cut_never_splits_an_escape():
    line = frame_summary(wire_frame("\x1b" * 1000))
    assert len(line) <= 512 and line.endswith("\\x1b...")
    body = line[line.index("wire: ") + len("wire: ") : -3]
    assert re.fullmatch(r"(?:\\x1b)+", body)


def test_a_summary_of_any_length_costs_a_bounded_amount():
    started = time.monotonic()
    line = frame_summary(wire_frame("\x1b" * 20_000_000))
    assert 500 < len(line) <= 512
    assert time.monotonic() - started < 2.0


def test_a_layer_name_from_a_class_is_escaped_too():
    class Evil(NamedTuple):
        value: int

    Evil.__name__ = "Evil\x1b[31mLayer"
    frame = dissect(udp_frame())
    frame = frame._replace(
        layers=frame.layers + (Evil(1),), payloads=frame.payloads + (b"",)
    )
    line = frame_summary(frame)
    assert "\x1b" not in line and re.fullmatch(r"[ -~]+", line)


# -- the time -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "when, text",
    [
        (0.0, "1970-01-01T00:00:00.000000Z"),
        (1_700_000_000.123456, "2023-11-14T22:13:20.123456Z"),
        (1e15, "t1000000000000000"),
        (-1e15, "t-1000000000000000"),
        (1e20, "unknown"),
        (float("nan"), "unknown"),
        (float("inf"), "unknown"),
    ],
)
def test_a_time_outside_any_calendar_is_a_count_of_seconds(when, text):
    assert frame_summary(dissect(udp_frame(), when=when)).startswith(text + " ")


def test_what_is_not_a_dissected_frame_is_a_type_error():
    with pytest.raises(TypeError, match="DissectedFrame"):
        frame_summary(CapturedFrame(0.0, 1, b""))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        frame_summary(None)  # type: ignore[arg-type]


def test_a_frame_summary_is_a_function_of_its_one_frame_and_cheap():
    frame = dissect(udp_frame())
    started = time.monotonic()
    for _ in range(2000):
        frame_summary(frame)
    assert time.monotonic() - started < 5.0
    assert isinstance(frame, DissectedFrame)
