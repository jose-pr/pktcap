"""Replay what the reference recorded: pktcap against tshark, with no tool
installed.

Each directory under ``cases/`` holds an input (``case.pcap``,
``case.pcapng``, or ``case.json`` for what a writer is asked to write) and
``golden.json``, tshark's answer about it, recorded by ``record.py``.

- ``read-``: pktcap reads the same frames, names the same layers with the
  same fields in each, and decodes the same UDP datagrams.
- ``refuse-``: tshark fails on the capture, and pktcap raises
  ``CaptureFormatError`` after the same number of frames.
- ``write-``: what a writer writes is, octet for octet, the file tshark read
  as the frames or datagrams asked for, with every checksum good.

A case named in ``deviations.json`` is one where pktcap differs on purpose:
it is asserted as pktcap behaves, and the README lists it.
"""

import hashlib
import io
import json
import pathlib
import re

import pytest

from pktcap import (
    CapturedFrame,
    CaptureFormatError,
    EthernetLayer,
    FrameDissector,
    IPv4Layer,
    IPv6ExtensionLayer,
    IPv6FragmentLayer,
    IPv6Layer,
    LinuxCookedLayer,
    LoopbackLayer,
    PcapngWriter,
    PcapWriter,
    TCPLayer,
    UDPLayer,
    VLANLayer,
    read_datagrams,
    read_dissected,
    read_frames,
)

HERE = pathlib.Path(__file__).resolve().parent
CASES = sorted(p for p in (HERE / "cases").iterdir() if p.is_dir())
DEVIATIONS = {
    entry["case"]: entry
    for entry in json.loads((HERE / "deviations.json").read_text(encoding="utf-8"))
}
README = HERE.parent.parent / "README.md"


def _named(prefix, deviating=False):
    return [
        pytest.param(case, id=case.name)
        for case in CASES
        if case.name.startswith(prefix) and (case.name in DEVIATIONS) == deviating
    ]


def _golden(case):
    return json.loads((case / "golden.json").read_text(encoding="utf-8"))


def _capture(case):
    (path,) = [p for p in case.iterdir() if p.name in ("case.pcap", "case.pcapng")]
    return path


def _as_golden(datagram):
    return (
        [datagram.source[0], datagram.source[1]],
        [datagram.destination[0], datagram.destination[1]],
        datagram.payload.hex(),
    )


# -- one frame's layers, as each side names them ---------------------------


def _described(frame):
    """The layers pktcap read from a frame, each as tshark's name for it and
    the fields both print."""
    out = []
    for layer, payload in zip(frame.layers, frame.payloads):
        if isinstance(layer, EthernetLayer):
            out.append(("eth", layer.destination, layer.source, layer.ethertype))
        elif isinstance(layer, VLANLayer):
            out.append(("vlan", layer.id, layer.priority, layer.drop_eligible))
        elif isinstance(layer, LinuxCookedLayer):
            out.append(
                (
                    "sll",
                    layer.packet_type,
                    layer.hardware_type,
                    layer.ethertype,
                    layer.interface,
                )
            )
        elif isinstance(layer, LoopbackLayer):
            out.append(("null", layer.family))
        elif isinstance(layer, IPv4Layer):
            out.append(
                (
                    "ip",
                    layer.source,
                    layer.destination,
                    layer.protocol,
                    layer.ttl,
                    layer.identification,
                    layer.length,
                    layer.dont_fragment,
                    layer.more_fragments,
                    layer.fragment_offset // 8,
                )
            )
        elif isinstance(layer, IPv6Layer):
            out.append(
                (
                    "ipv6",
                    layer.source,
                    layer.destination,
                    layer.next_header,
                    layer.hop_limit,
                    layer.payload_length,
                )
            )
        elif isinstance(layer, IPv6ExtensionLayer):
            out.append(("ipv6 extension",))
        elif isinstance(layer, IPv6FragmentLayer):
            out.append(
                (
                    "ipv6.fraghdr",
                    layer.fragment_offset // 8,
                    layer.more_fragments,
                    layer.identification,
                )
            )
        elif isinstance(layer, TCPLayer):
            out.append(
                (
                    "tcp",
                    layer.source_port,
                    layer.destination_port,
                    layer.sequence,
                    layer.acknowledgment,
                    layer.flags,
                    layer.window,
                    20 + len(layer.options),
                    layer.options.hex(),
                    payload.hex(),
                )
            )
        elif isinstance(layer, UDPLayer):
            out.append(("udp", layer.source_port, layer.destination_port, layer.length))
        else:  # pragma: no cover - a layer no built-in dissector makes
            raise AssertionError(layer)
    return out


def _recorded(row):
    """The same, from a row of the fields tshark printed for a frame: its
    protocols up to the first this library has no dissector for.

    A field printed more than once in a frame is taken in order, so the outer
    of two tags, or of two IP headers, is the first.
    """
    taken = {}

    def text(name):
        index = taken.get(name, 0)
        taken[name] = index + 1
        return row.get(name, "").split(",")[index]

    def number(name):
        return int(text(name), 0)

    def flag(name):
        return text(name) in ("True", "1")

    out = []
    for name in row["frame.protocols"].split(":"):
        if name in ("ethertype", "raw"):  # not a header: nothing to compare
            continue
        if name == "eth":
            out.append(("eth", text("eth.dst"), text("eth.src"), number("eth.type")))
        elif name == "vlan":
            out.append(
                (
                    "vlan",
                    number("vlan.id"),
                    number("vlan.priority"),
                    flag("vlan.dei"),
                )
            )
        elif name == "ieee8021ad":  # tshark's name for the outer tag of QinQ
            out.append(
                (
                    "vlan",
                    number("ieee8021ad.id"),
                    number("ieee8021ad.priority"),
                    flag("ieee8021ad.dei"),
                )
            )
        elif name == "sll":
            out.append(
                (
                    "sll",
                    number("sll.pkttype"),
                    number("sll.hatype"),
                    number("sll.etype"),
                    # Only version 2 of the header has an interface index.
                    number("sll.ifindex") if "sll.ifindex" in row else None,
                )
            )
        elif name == "null":
            out.append(("null", number("null.family")))
        elif name == "ip":
            out.append(
                (
                    "ip",
                    text("ip.src"),
                    text("ip.dst"),
                    number("ip.proto"),
                    number("ip.ttl"),
                    number("ip.id"),
                    number("ip.len"),
                    flag("ip.flags.df"),
                    flag("ip.flags.mf"),
                    number("ip.frag_offset"),
                )
            )
        elif name == "ipv6":
            out.append(
                (
                    "ipv6",
                    text("ipv6.src"),
                    text("ipv6.dst"),
                    number("ipv6.nxt"),
                    number("ipv6.hlim"),
                    number("ipv6.plen"),
                )
            )
        elif name in ("ipv6.hopopts", "ipv6.dstopts", "ipv6.routing"):
            out.append(("ipv6 extension",))
        elif name == "ipv6.fraghdr":
            out.append(
                (
                    "ipv6.fraghdr",
                    number("ipv6.fraghdr.offset"),
                    flag("ipv6.fraghdr.more"),
                    number("ipv6.fraghdr.ident"),
                )
            )
        elif name == "tcp":
            out.append(
                (
                    "tcp",
                    number("tcp.srcport"),
                    number("tcp.dstport"),
                    number("tcp.seq_raw"),
                    number("tcp.ack_raw"),
                    number("tcp.flags"),
                    number("tcp.window_size_value"),
                    number("tcp.hdr_len"),
                    text("tcp.options"),
                    text("tcp.payload"),
                )
            )
        elif name == "udp":
            out.append(
                (
                    "udp",
                    number("udp.srcport"),
                    number("udp.dstport"),
                    number("udp.length"),
                )
            )
        else:
            break
    return out


def _assert_frames_are_the_recorded_ones(frames, rows):
    assert len(frames) == len(rows)
    for frame, row in zip(frames, rows):
        number = row["frame.number"]
        assert _described(frame) == _recorded(row), number
        assert frame.error is None, number
        assert len(frame.frame.data) == int(row["frame.cap_len"]), number
        assert frame.time == pytest.approx(float(row["frame.time_epoch"]), abs=2e-6)
        if frame.frame.interface is not None:
            assert frame.frame.interface == int(row["frame.interface_id"]), number


# -- the cases themselves -------------------------------------------------


def test_there_are_cases_of_every_kind_and_each_has_a_golden():
    kinds = {case.name.split("-")[0] for case in CASES}
    assert kinds == {"read", "refuse", "write"}
    assert len(CASES) >= 33
    for case in CASES:
        assert (case / "golden.json").is_file(), case.name


def test_every_golden_names_the_one_reference_that_produced_it():
    references = {
        json.dumps(_golden(case)["reference"], sort_keys=True) for case in CASES
    }
    assert len(references) == 1
    reference = json.loads(references.pop())
    assert re.match(r"TShark \(Wireshark\) \d+\.\d+\.\d+", reference["tshark"])
    assert reference["environment"]


def test_a_deviation_names_a_case_that_exists():
    assert set(DEVIATIONS) <= {case.name for case in CASES}
    assert all(entry["difference"].strip() for entry in DEVIATIONS.values())


# -- reading --------------------------------------------------------------


@pytest.mark.parametrize("case", _named("read-"))
def test_pktcap_names_the_layers_tshark_does_in_every_frame(case):
    golden = _golden(case)
    assert golden["exit_status"] == 0 and golden["layers"] is not None
    dissector = FrameDissector()
    frames = list(read_dissected(_capture(case), dissector=dissector))
    _assert_frames_are_the_recorded_ones(frames, golden["layers"])
    stats = dissector.stats
    assert (stats.malformed, stats.failed, stats.dropped, stats.pending) == (0,) * 4
    # A frame whose link type nothing dissects is the one tshark, too, names
    # no layer of ours in.
    assert stats.unsupported == sum(1 for f in frames if not f.layers)


@pytest.mark.parametrize("case", _named("read-"))
def test_pktcap_decodes_the_datagrams_tshark_does(case):
    golden = _golden(case)
    assert golden["exit_status"] == 0
    dissector = FrameDissector()
    datagrams = list(read_datagrams(_capture(case), dissector=dissector))
    assert dissector.stats.frames == golden["frames"]
    assert [_as_golden(d) for d in datagrams] == [
        (g["source"], g["destination"], g["payload"]) for g in golden["datagrams"]
    ]
    for datagram, recorded in zip(datagrams, golden["datagrams"]):
        assert datagram.time == pytest.approx(float(recorded["time"]), abs=2e-6)
        # tshark states the datagram's own length; what the capture kept of
        # it may be less, and pktcap says so.
        cut = recorded["udp_length"] - 8 > len(datagram.payload)
        assert datagram.truncated is cut and not datagram.fragmented


def test_one_case_is_cut_by_a_snap_length_and_both_say_so():
    case = HERE / "cases" / "read-built-snap-length"
    (datagram,) = read_datagrams(_capture(case))
    (recorded,) = _golden(case)["datagrams"]
    assert datagram.truncated and recorded["udp_length"] - 8 > len(datagram.payload)


@pytest.mark.parametrize("case", _named("read-", deviating=True))
def test_a_listed_deviation_behaves_as_listed_and_does_differ(case):
    golden = _golden(case)
    expected = DEVIATIONS[case.name]["pktcap"]
    dissector = FrameDissector()
    datagrams, raised = [], False
    try:
        for datagram in read_datagrams(_capture(case), dissector=dissector):
            datagrams.append(datagram)
    except CaptureFormatError:
        raised = True
    assert raised is expected.get("raises", False)
    if raised:
        assert dissector.stats.frames == expected["frames"]
    else:
        stats = dissector.stats
        assert {
            "datagrams": len(datagrams),
            "dropped": stats.dropped,
            "pending": stats.pending,
        } == expected
    # tshark read it and made datagrams of it: the two do differ.
    assert golden["exit_status"] == 0
    assert len(golden["datagrams"]) != len(datagrams) or raised


# -- refusing -------------------------------------------------------------


@pytest.mark.parametrize("case", _named("refuse-"))
def test_pktcap_refuses_what_tshark_refuses_after_the_same_frames(case):
    golden = _golden(case)
    assert golden["exit_status"] != 0 and golden["error"]
    frames = []
    with pytest.raises(CaptureFormatError):
        for frame in read_frames(_capture(case)):
            frames.append(frame)
    assert len(frames) == golden["frames"]


# -- writing --------------------------------------------------------------


def _written(question):
    """The capture file a ``write-`` case asks a writer for, as octets."""
    stream = io.BytesIO()
    writer_type = PcapngWriter if question.get("writer") == "pcapng" else PcapWriter
    with writer_type(stream) as writer:
        for time, source, destination, payload in question.get("datagrams", ()):
            writer.write(
                time, tuple(source), tuple(destination), bytes.fromhex(payload)
            )
        for time, linktype, data in question.get("frames", ()):
            writer.write_frame(CapturedFrame(time, linktype, bytes.fromhex(data)))
    return stream.getvalue()


@pytest.mark.parametrize("case", _named("write-"))
def test_tshark_read_exactly_what_the_writer_writes(case):
    golden = _golden(case)
    question = json.loads((case / "case.json").read_text(encoding="utf-8"))
    written = _written(question)
    # The golden is about this very file.
    assert hashlib.sha256(written).hexdigest() == golden["sha256"]
    assert golden["exit_status"] == 0 and golden["error"] is None
    datagrams, frames = question.get("datagrams", []), question.get("frames", [])
    assert golden["frames"] == len(datagrams) + len(frames) > 0
    if datagrams:
        assert len(golden["datagrams"]) == len(datagrams)
        for recorded, asked in zip(golden["datagrams"], datagrams):
            assert recorded["payload"] == asked[3]
            assert float(recorded["time"]) == pytest.approx(asked[0], abs=1e-6)
            assert recorded["udp_checksum"] == "1"  # good
            assert recorded["ip_checksum"] in ("1", "")  # good; IPv6 has none
    # The frames asked for come back octet for octet, with their link types.
    read_back = list(read_frames(io.BytesIO(written)))
    if frames:
        assert [(f.linktype, f.data.hex()) for f in read_back] == [
            (linktype, data) for _, linktype, data in frames
        ]
        for frame, asked in zip(read_back, frames):
            assert frame.time == pytest.approx(asked[0], abs=1e-6)
    # And pktcap reads its own output as tshark does.
    dissector = FrameDissector()
    _assert_frames_are_the_recorded_ones(
        [dissector.dissect(frame) for frame in read_back], golden["layers"]
    )
    assert [_as_golden(d) for d in read_datagrams(io.BytesIO(written))] == [
        (g["source"], g["destination"], g["payload"]) for g in golden["datagrams"]
    ]


# -- the README -----------------------------------------------------------


def test_the_readme_states_how_many_captures_there_are():
    text = " ".join(README.read_text(encoding="utf-8").split())
    (count,) = re.findall(r"records what it says about (\d+) captures", text)
    assert int(count) == len(CASES)


def test_the_readme_lists_exactly_the_deviations():
    text = README.read_text(encoding="utf-8")
    start = text.index("\n## Differences from tshark\n")
    section = text[start : text.index("\n## ", start + 1)]
    rows = re.findall(r"^\| `([a-z0-9-]+)` \| (.+) \|$", section, re.MULTILINE)
    assert dict(rows) == {
        name: entry["difference"] for name, entry in DEVIATIONS.items()
    }
