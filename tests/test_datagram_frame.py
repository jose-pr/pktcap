"""``datagram_frame``: a datagram seen at a socket as the frame a dissector reads.

The octets are checked against what the wire format says (a header checksum
folds to all ones, the fields sit at their offsets) and against what
``PcapWriter`` has always written for the same datagram.
"""

import io
import ipaddress
import struct

import pytest

from pktcap import (
    CapturedDatagram,
    CapturedFrame,
    FrameDissector,
    IPv4Layer,
    IPv6Layer,
    PcapWriter,
    UDPLayer,
    datagram_frame,
    read_frames,
)


def _datagram(source, destination, payload=b"hello", when=1700000000.5):
    return CapturedDatagram(when, source, destination, payload)


def _folds_to_ones(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


# -- the law ----------------------------------------------------------------


@pytest.mark.parametrize(
    "source, destination",
    [
        (("10.0.0.5", 50000), ("10.0.0.1", 69)),
        (("2001:db8::5", 50000), ("2001:db8::1", 69)),
        (("::1", 1), ("::1", 65535)),
        (("0.0.0.0", 0), ("255.255.255.255", 67)),
    ],
)
def test_a_dissected_datagram_frame_gives_the_datagram_back(source, destination):
    sent = _datagram(source, destination, bytes(range(256)) * 3)
    frame = FrameDissector().dissect(datagram_frame(sent))
    assert frame.datagram() == sent
    assert frame.error is None


def test_an_empty_payload_is_a_datagram():
    sent = _datagram(("10.0.0.5", 1), ("10.0.0.1", 2), b"")
    assert FrameDissector().dissect(datagram_frame(sent)).datagram() == sent


def test_two_v4_mapped_addresses_are_an_ipv4_packet_with_plain_hosts():
    sent = _datagram(("::ffff:10.0.0.5", 50000), ("::ffff:10.0.0.1", 69))
    frame = FrameDissector().dissect(datagram_frame(sent))
    assert frame.layer(IPv4Layer) is not None and frame.layer(IPv6Layer) is None
    assert frame.datagram() == sent._replace(
        source=("10.0.0.5", 50000), destination=("10.0.0.1", 69)
    )


def test_one_v4_end_and_one_v6_end_are_an_ipv6_packet_with_the_v4_end_mapped():
    sent = _datagram(("10.0.0.5", 50000), ("2001:db8::1", 69))
    frame = FrameDissector().dissect(datagram_frame(sent))
    assert frame.layer(IPv6Layer) is not None and frame.layer(IPv4Layer) is None
    assert frame.datagram() == sent._replace(source=("::ffff:10.0.0.5", 50000))


def test_a_zone_is_not_on_the_wire():
    sent = _datagram(("fe80::1%12", 5), ("fe80::2%eth0", 6))
    frame = FrameDissector().dissect(datagram_frame(sent))
    assert frame.datagram() == sent._replace(
        source=("fe80::1", 5), destination=("fe80::2", 6)
    )


def test_the_four_item_ipv6_socket_address_is_taken():
    sent = _datagram(("2001:db8::5", 50000, 0, 0), ("2001:db8::1", 69, 0, 0))
    frame = FrameDissector().dissect(datagram_frame(sent))
    assert frame.datagram() == sent._replace(
        source=("2001:db8::5", 50000), destination=("2001:db8::1", 69)
    )


# -- the octets ---------------------------------------------------------------


def test_the_frame_is_raw_ip_with_the_time_and_the_interface_given():
    frame = datagram_frame(
        _datagram(("10.0.0.5", 1), ("10.0.0.1", 2), when=12.25), interface=7
    )
    assert isinstance(frame, CapturedFrame)
    assert (frame.time, frame.linktype, frame.interface) == (12.25, 101, 7)
    assert datagram_frame(_datagram(("10.0.0.5", 1), ("10.0.0.1", 2))).interface is None


def test_an_ipv4_frame_has_the_fields_the_wire_format_puts_at_their_offsets():
    payload = b"abcdef"
    data = datagram_frame(
        _datagram(("10.0.0.5", 50000), ("10.0.0.1", 69), payload), ident=0x1234
    ).data
    assert len(data) == 20 + 8 + len(payload)
    assert data[0] == 0x45  # version 4, 5 words
    assert struct.unpack("!H", data[2:4])[0] == len(data)
    assert struct.unpack("!H", data[4:6])[0] == 0x1234  # identification
    assert struct.unpack("!H", data[6:8])[0] == 0  # never a fragment
    assert data[8] == 64 and data[9] == 17  # ttl, UDP
    assert data[12:16] == bytes([10, 0, 0, 5]) and data[16:20] == bytes([10, 0, 0, 1])
    assert _folds_to_ones(data[:20])
    sport, dport, length, _ = struct.unpack("!HHHH", data[20:28])
    assert (sport, dport, length) == (50000, 69, 8 + len(payload))
    pseudo = data[12:20] + struct.pack("!BBH", 0, 17, length)
    assert _folds_to_ones(pseudo + data[20:])
    assert data[28:] == payload


def test_an_ipv6_frame_has_the_fields_the_wire_format_puts_at_their_offsets():
    payload = b"abcdef"
    data = datagram_frame(
        _datagram(("2001:db8::5", 50000), ("2001:db8::1", 69), payload)
    ).data
    assert len(data) == 40 + 8 + len(payload)
    assert data[0] >> 4 == 6
    assert struct.unpack("!H", data[4:6])[0] == 8 + len(payload)
    assert data[6] == 17 and data[7] == 64  # next header UDP, hop limit
    assert data[8:24] == ipaddress.IPv6Address("2001:db8::5").packed
    assert data[24:40] == ipaddress.IPv6Address("2001:db8::1").packed
    pseudo = data[8:40] + struct.pack("!I3xB", 8 + len(payload), 17)
    assert _folds_to_ones(pseudo + data[40:])


def test_the_identification_is_the_callers_and_wraps_to_sixteen_bits():
    one = ("10.0.0.5", 1), ("10.0.0.1", 2)
    assert (
        struct.unpack("!H", datagram_frame(_datagram(*one), ident=0x1FFFF).data[4:6])[0]
        == 0xFFFF
    )
    assert struct.unpack("!H", datagram_frame(_datagram(*one)).data[4:6])[0] == 0


def test_the_octets_are_those_pcapwriter_writes_for_the_same_datagram():
    sent = _datagram(("10.0.0.5", 50000), ("2001:db8::1", 69), b"payload")
    out = io.BytesIO()
    with PcapWriter(out) as writer:
        writer.write_datagram(sent)
    (written,) = read_frames(io.BytesIO(out.getvalue()))
    # The writer numbers its first packet 1; the frame is told to.
    assert datagram_frame(sent, ident=1).data == written.data


def test_a_partial_datagram_is_framed_with_the_payload_it_has():
    sent = CapturedDatagram(
        1.0, ("10.0.0.5", 1), ("10.0.0.1", 2), b"cut", truncated=True
    )
    frame = FrameDissector().dissect(datagram_frame(sent))
    assert frame.datagram().payload == b"cut"


# -- what is refused -----------------------------------------------------------


@pytest.mark.parametrize(
    "datagram",
    [
        _datagram(("not-an-address", 1), ("10.0.0.1", 2)),
        _datagram(("10.0.0.5", 1), ("example.org", 2)),
        _datagram(("10.0.0.5", 65536), ("10.0.0.1", 2)),
        _datagram(("10.0.0.5", 1), ("10.0.0.1", -1)),
        _datagram(("10.0.0.5", 1), ("10.0.0.1", 2), b"x" * 65508),
        _datagram(("2001:db8::5", 1), ("2001:db8::1", 2), b"x" * 65528),
        _datagram(("10.0.0.5", 1), ("10.0.0.1", 2), when=-1.0),
        _datagram(("10.0.0.5", 1), ("10.0.0.1", 2), when=float("nan")),
        _datagram(("10.0.0.5", 1), ("10.0.0.1", 2), when=float(1 << 32)),
    ],
)
def test_what_the_writer_refuses_is_refused(datagram):
    with pytest.raises(ValueError):
        datagram_frame(datagram)


def test_the_largest_payloads_fit():
    big4 = _datagram(("10.0.0.5", 1), ("10.0.0.1", 2), b"x" * 65507)
    big6 = _datagram(("2001:db8::5", 1), ("2001:db8::1", 2), b"x" * 65527)
    assert FrameDissector().dissect(datagram_frame(big4)).datagram() == big4
    assert FrameDissector().dissect(datagram_frame(big6)).datagram() == big6


@pytest.mark.parametrize(
    "datagram",
    [
        ("10.0.0.5", 1),
        _datagram("10.0.0.5", ("10.0.0.1", 2)),
        _datagram(("10.0.0.5", "1"), ("10.0.0.1", 2)),
        _datagram(("10.0.0.5", True), ("10.0.0.1", 2)),
        _datagram((b"10.0.0.5", 1), ("10.0.0.1", 2)),
        _datagram(("10.0.0.5", 1), ("10.0.0.1", 2), when="now"),
        _datagram(("10.0.0.5", 1), ("10.0.0.1", 2), when=True),
    ],
)
def test_a_wrong_type_is_a_type_error(datagram):
    with pytest.raises(TypeError):
        datagram_frame(datagram)


@pytest.mark.parametrize("interface", [-1, 1 << 32])
def test_an_interface_outside_what_a_capture_holds_is_refused(interface):
    with pytest.raises(ValueError):
        datagram_frame(_datagram(("10.0.0.5", 1), ("10.0.0.1", 2)), interface=interface)


@pytest.mark.parametrize("interface", [True, "eth0", 1.5])
def test_an_interface_that_is_not_an_index_is_a_type_error(interface):
    with pytest.raises(TypeError):
        datagram_frame(_datagram(("10.0.0.5", 1), ("10.0.0.1", 2)), interface=interface)


def test_the_options_are_keyword_only():
    with pytest.raises(TypeError):
        datagram_frame(_datagram(("10.0.0.5", 1), ("10.0.0.1", 2)), 3)


def test_the_frame_dissects_to_the_layers_a_capture_of_it_would():
    frame = FrameDissector().dissect(
        datagram_frame(_datagram(("10.0.0.5", 50000), ("10.0.0.1", 69), b"x"))
    )
    assert [type(layer) for layer in frame.layers] == [IPv4Layer, UDPLayer]
    assert frame.layer(UDPLayer).destination_port == 69
