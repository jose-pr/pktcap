"""`CaptureWriter`: one writer, every format, a growing file or one per record."""

import configparser
import hashlib
import io
import json
import logging
import os
import sys

import pytest

import captures as build
from pktcap import (
    CapturedDatagram,
    CapturedFrame,
    CaptureWriter,
    Dissected,
    DissectorRegistry,
    FrameDissector,
    UnsupportedFormatError,
    datagram_record,
    dumps_record,
    frame_record,
    read_datagrams,
    read_frames,
)

FIRST = CapturedDatagram(
    1_700_000_000.5, ("10.0.0.5", 68), ("10.0.0.1", 67), b"\x01\x02"
)
SECOND = CapturedDatagram(
    1_700_000_001.5, ("2001:db8::5", 546), ("ff02::1:2", 547), b"\x03"
)
THIRD = CapturedDatagram(1_700_000_002.5, ("10.0.0.5", 68), ("10.0.0.1", 67), b"")
ALL = [FIRST, SECOND, THIRD]


def _write(target, *args, datagrams=ALL, records=None, **options):
    with CaptureWriter(target, *args, **options) as writer:
        for index, datagram in enumerate(datagrams):
            writer.write(datagram, None if records is None else records[index])
        return writer


# -- the default record ---------------------------------------------------


def test_the_record_of_a_datagram_needs_no_protocol():
    assert datagram_record(FIRST) == {
        "time": 1_700_000_000.5,
        "source": "10.0.0.5:68",
        "destination": "10.0.0.1:67",
        "length": 2,
        "payload": "0102",
    }
    assert datagram_record(SECOND)["source"] == "[2001:db8::5]:546"


def test_a_partial_datagram_says_so_in_its_record():
    assert datagram_record(FIRST._replace(fragmented=True))["fragmented"] is True
    assert datagram_record(FIRST._replace(truncated=True))["truncated"] is True
    assert "fragmented" not in datagram_record(FIRST)


# -- one growing file -----------------------------------------------------


def test_pcap_output_is_read_back_by_the_reader(tmp_path):
    path = tmp_path / "out.pcap"
    writer = _write(path)
    assert writer.format == "pcap" and writer.written == 3
    assert list(read_datagrams(path)) == ALL


def test_pcap_ignores_the_record():
    stream = io.BytesIO()
    _write(stream, "pcap", records=[{"a": object()}] * 3)
    assert list(read_datagrams(io.BytesIO(stream.getvalue()))) == ALL


def test_json_is_one_line_per_record_and_defaults_to_the_datagram(tmp_path):
    path = tmp_path / "out.json"
    _write(path)
    lines = path.read_bytes().split(b"\n")
    assert lines[-1] == b"" and len(lines) == 4
    assert [json.loads(line) for line in lines[:3]] == [datagram_record(d) for d in ALL]


def test_a_record_the_caller_made_is_what_is_written(tmp_path):
    path = tmp_path / "out.jsonl"
    records = [{"msg_type": "DISCOVER", "xid": n} for n in range(3)]
    _write(path, records=records)
    assert [
        json.loads(line) for line in path.read_text("ascii").splitlines()
    ] == records


def test_yaml_documents_each_start_with_a_marker_and_load_as_a_stream(tmp_path):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "out.yaml"
    _write(path, records=[{"n": 1}, {"n": 2}, {"n": 3}])
    text = path.read_text("ascii")
    assert text == "---\nn: 1\n---\nn: 2\n---\nn: 3\n"
    assert list(yaml.safe_load_all(text)) == [{"n": 1}, {"n": 2}, {"n": 3}]


@pytest.mark.parametrize("name", ["json", "yaml"])
def test_appending_keeps_the_file_one_valid_stream(name, tmp_path):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / ("out." + name)
    _write(path, datagrams=[FIRST], records=[{"n": 1}])
    _write(path, datagrams=[SECOND], records=[{"n": 2}], append=True)
    text = path.read_text("ascii")
    loaded = (
        [json.loads(line) for line in text.splitlines()]
        if name == "json"
        else list(yaml.safe_load_all(text))
    )
    assert loaded == [{"n": 1}, {"n": 2}]


def test_without_append_an_existing_file_is_replaced_at_the_first_write(tmp_path):
    path = tmp_path / "out.json"
    path.write_text("earlier\n")
    writer = CaptureWriter(path)
    assert path.read_text() == "earlier\n"
    writer.write(FIRST, {"n": 1})
    writer.close()
    assert path.read_text() == '{"n": 1}\n'


def test_a_writer_that_never_writes_creates_no_file(tmp_path):
    for name in ("out.json", "out.pcap"):
        with CaptureWriter(tmp_path / name):
            pass
        assert not (tmp_path / name).exists()


def test_each_record_is_on_disk_when_write_returns(tmp_path):
    path = tmp_path / "live.json"
    with CaptureWriter(path) as writer:
        writer.write(FIRST, {"n": 1})
        assert path.read_text() == '{"n": 1}\n'


def test_a_stream_is_written_as_octets_and_left_open():
    stream = io.BytesIO()
    writer = _write(
        stream, "json", datagrams=[FIRST], records=[{"caf\u00e9": "\u2028"}]
    )
    assert stream.getvalue() == b'{"caf\\u00e9": "\\u2028"}\n'
    assert not stream.closed and writer.written == 1


def test_a_record_that_cannot_be_written_writes_nothing_and_uses_no_index(tmp_path):
    stream = io.BytesIO()
    with CaptureWriter(stream, "json") as writer:
        with pytest.raises(TypeError):
            writer.write(FIRST, {"a": object()})
        with pytest.raises(TypeError, match="a record is a mapping"):
            writer.write(FIRST, [1, 2])
        assert stream.getvalue() == b"" and writer.written == 0


def test_a_closed_writer_refuses_and_close_is_harmless_twice():
    writer = CaptureWriter(io.BytesIO(), "json")
    writer.close()
    writer.close()
    with pytest.raises(ValueError, match="closed"):
        writer.write(FIRST)


# -- choosing the format --------------------------------------------------


@pytest.mark.parametrize(
    "name, expected",
    [
        ("trace.pcap", "pcap"),
        ("trace.CAP", "pcap"),
        ("x.json", "json"),
        ("x.ndjson", "json"),
        ("x.JSONL", "json"),
        ("x.yaml", "yaml"),
        ("x.yml", "yaml"),
        ("dir.json/x.yml", "yaml"),
    ],
)
def test_the_format_comes_from_the_end_of_the_name(name, expected):
    assert CaptureWriter(name).format == expected


def test_a_name_given_wins_over_the_file_name():
    assert CaptureWriter("x.json", "pcap").format == "pcap"
    assert CaptureWriter("x.pcap", "JSON").format == "json"


@pytest.mark.parametrize("target", ["capture", "x.pcapx", "x.txt", io.BytesIO()])
def test_a_format_that_cannot_be_told_must_be_named(target):
    with pytest.raises(
        UnsupportedFormatError, match="pcap, pcapng, json, yaml, toml, ini"
    ):
        CaptureWriter(target)


def test_an_unknown_format_names_the_ones_there_are():
    with pytest.raises(
        UnsupportedFormatError, match="pcap, pcapng, json, yaml, toml, ini"
    ):
        CaptureWriter("x.json", "xml")


@pytest.mark.parametrize("name, module", [("yaml", "yaml"), ("toml", "tomli_w")])
def test_a_missing_extra_fails_when_the_writer_is_built_not_per_packet(
    name, module, monkeypatch
):
    monkeypatch.setitem(sys.modules, module, None)
    with pytest.raises(ImportError, match=r'pip install "pktcap\[%s\]"' % name):
        CaptureWriter("cap_{index}." + name, per_record=True)


# -- combinations that cannot work ----------------------------------------


@pytest.mark.parametrize("name", ["toml", "ini"])
def test_a_format_of_one_record_per_file_refuses_to_be_a_stream(name):
    with pytest.raises(ValueError, match="cannot hold more than one record"):
        CaptureWriter("out." + name)
    with pytest.raises(ValueError, match="cannot hold more than one record"):
        CaptureWriter(io.BytesIO(), name)


def test_a_capture_file_cannot_be_appended_to():
    with pytest.raises(ValueError, match="pcap capture cannot be appended"):
        CaptureWriter("x.pcap", append=True)
    with pytest.raises(ValueError, match="pcapng capture cannot be appended"):
        CaptureWriter("x.pcapng", append=True)


# -- frames ---------------------------------------------------------------

UDP = build.udp(50000, 69, b"\x00\x01boot\x00")
DISSECTOR = FrameDissector()
FRAMES = [
    DISSECTOR.dissect(
        CapturedFrame(
            1_700_000_000.0,
            1,
            build.ethernet(build.ipv4("10.0.0.5", "10.0.0.1", UDP), vlans=1),
        )
    ),
    DISSECTOR.dissect(
        CapturedFrame(1_700_000_001.0, 1, b"\x02" * 12 + b"\x08\x06" + bytes(28))
    ),
    DISSECTOR.dissect(CapturedFrame(1_700_000_002.0, 113, b"short")),
]


def test_the_record_of_a_frame_lists_its_layers_as_plain_data():
    assert frame_record(FRAMES[0]) == {
        "time": 1_700_000_000.0,
        "linktype": 1,
        "length": len(FRAMES[0].frame.data),
        "layers": [
            {
                "layer": "ethernet",
                "destination": "02:02:02:02:02:02",
                "source": "04:04:04:04:04:04",
                "ethertype": 0x8100,
            },
            {
                "layer": "vlan",
                "id": 5,
                "priority": 0,
                "drop_eligible": False,
                "ethertype": 0x0800,
            },
            {
                "layer": "ipv4",
                "source": "10.0.0.5",
                "destination": "10.0.0.1",
                "protocol": 17,
                "ttl": 64,
                "identification": 1,
                "dont_fragment": False,
                "more_fragments": False,
                "fragment_offset": 0,
                "length": 20 + len(UDP),
            },
            {
                "layer": "udp",
                "source_port": 50000,
                "destination_port": 69,
                "length": len(UDP),
                "checksum": 0,
            },
        ],
        "payload": b"\x00\x01boot\x00".hex(),
    }


def test_a_frame_record_says_what_went_wrong_and_what_was_left():
    arp, broken = frame_record(FRAMES[1]), frame_record(FRAMES[2])
    assert [layer["layer"] for layer in arp["layers"]] == ["ethernet"]
    assert arp["payload"] == bytes(28).hex() and "error" not in arp
    assert broken["layers"] == [] and broken["payload"] == b"short".hex()
    assert broken["error"].startswith("linktype 113: a Linux cooked header")


def test_a_layer_from_a_registered_dissector_is_in_the_record_and_octets_are_hex():
    registry = DissectorRegistry()
    registry.register(
        "udp", 69, lambda data: Dissected({"opcode": 1, "raw": data[:2]}, data[2:])
    )
    frame = FrameDissector(registry).dissect(FRAMES[0].frame)
    assert frame_record(frame)["layers"][-1] == {
        "layer": "dict",
        "opcode": 1,
        "raw": "0001",
    }
    # Every format can write it.
    for name in ("json", "yaml", "toml", "ini"):
        assert dumps_record(frame_record(frame), name)


@pytest.mark.parametrize("name", ["pcap", "pcapng"])
def test_a_capture_format_writes_a_frame_as_it_was_captured(name, tmp_path):
    path = tmp_path / ("out." + name)
    same_link_type = FRAMES[:2]
    with CaptureWriter(path) as writer:
        for frame in same_link_type:
            writer.write(frame)
    assert writer.format == name and writer.written == 2
    assert [f.data for f in read_frames(path)] == [f.frame.data for f in same_link_type]
    assert [f.linktype for f in read_frames(path)] == [1, 1]


def test_pcapng_takes_frames_of_several_link_types_and_datagrams_together(tmp_path):
    path = tmp_path / "mixed.pcapng"
    with CaptureWriter(path) as writer:
        for frame in FRAMES:
            writer.write(frame)
        writer.write(FIRST)
    assert [f.linktype for f in read_frames(path)] == [1, 1, 113, 101]
    with CaptureWriter(tmp_path / "one.pcap") as pcap:
        pcap.write(FRAMES[0])
        with pytest.raises(ValueError, match="link type 1 and cannot take 113"):
            pcap.write(FRAMES[2])


def test_a_record_format_writes_the_frame_record_by_default(tmp_path):
    path = tmp_path / "frames.json"
    with CaptureWriter(path) as writer:
        for frame in FRAMES:
            writer.write(frame)
    lines = path.read_text("ascii").splitlines()
    assert [json.loads(line) for line in lines] == [frame_record(f) for f in FRAMES]


def test_one_file_per_frame_in_a_capture_format(tmp_path):
    pattern = str(tmp_path / "f{index}.pcapng")
    with CaptureWriter(pattern, per_record=True) as writer:
        for frame in FRAMES:
            writer.write(frame)
    assert sorted(os.listdir(tmp_path)) == ["f0.pcapng", "f1.pcapng", "f2.pcapng"]
    (only,) = read_frames(tmp_path / "f2.pcapng")
    assert (only.linktype, only.data) == (113, b"short")


@pytest.mark.parametrize("item", [None, b"octets", FRAMES[0].frame, ("a", "b")])
def test_an_item_that_is_neither_datagram_nor_dissected_frame_is_a_type_error(item):
    stream = io.BytesIO()
    with pytest.raises(TypeError, match="CapturedDatagram or a DissectedFrame"):
        CaptureWriter(stream, "json").write(item)
    assert stream.getvalue() == b""


def test_a_text_stream_is_refused_by_name():
    with pytest.raises(TypeError, match="sys.stdout.buffer"):
        CaptureWriter(io.StringIO(), "json")
    with pytest.raises(TypeError, match="path or a binary stream"):
        CaptureWriter(None, "json")


def test_one_file_per_record_needs_a_pattern_not_a_stream():
    with pytest.raises(ValueError, match="needs a file-name pattern"):
        CaptureWriter(io.BytesIO(), "json", per_record=True)


@pytest.mark.parametrize(
    "value, error",
    [(0, ValueError), (-5, ValueError), (2.5, TypeError), (True, TypeError)],
)
def test_the_file_budget_must_be_a_positive_int(value, error):
    with pytest.raises(error):
        CaptureWriter("cap_{index}.json", per_record=True, max_files=value)


# -- one file per record --------------------------------------------------


def test_each_record_gets_its_own_file_named_by_the_pattern(tmp_path):
    pattern = str(tmp_path / "sub" / "cap_{index:03d}_{xid}_{format}.json")
    with CaptureWriter(pattern, per_record=True, fields=("xid",)) as writer:
        for number, datagram in enumerate(ALL):
            writer.write(datagram, {"n": number}, names={"xid": "%08X" % number})
    names = sorted(os.listdir(tmp_path / "sub"))
    assert names == [
        "cap_000_00000000_json.json",
        "cap_001_00000001_json.json",
        "cap_002_00000002_json.json",
    ]
    assert json.loads((tmp_path / "sub" / names[1]).read_text()) == {"n": 1}
    assert writer.written == 3 and writer.refused == 0


def test_the_timestamp_field_is_the_datagrams_time_in_utc(tmp_path):
    with CaptureWriter(str(tmp_path / "{timestamp}.json"), per_record=True) as writer:
        writer.write(FIRST)
    assert os.listdir(tmp_path) == ["20231114T221320.500000Z.json"]


def test_a_time_outside_any_calendar_still_names_a_file(tmp_path):
    """The capture controls the time: 2**40 seconds is the year 36,812."""
    with CaptureWriter(str(tmp_path / "{timestamp}.json"), per_record=True) as writer:
        writer.write(FIRST._replace(time=float(2**40)))
        writer.write(FIRST._replace(time=1e300))
    assert sorted(os.listdir(tmp_path)) == ["t1099511627776.json", "unknown.json"]


@pytest.mark.parametrize("name", ["toml", "ini", "yaml", "json", "pcap"])
def test_every_format_can_be_one_file_per_record(name, tmp_path):
    pytest.importorskip("yaml")
    pytest.importorskip("tomli_w")
    pattern = str(tmp_path / ("r{index}." + name))
    with CaptureWriter(pattern, per_record=True) as writer:
        writer.write(FIRST, {"n": 1})
        writer.write(SECOND, {"n": 2})
    assert sorted(os.listdir(tmp_path)) == ["r0." + name, "r1." + name]
    first = (tmp_path / ("r0." + name)).read_bytes()
    if name == "pcap":
        assert list(read_datagrams(io.BytesIO(first))) == [FIRST]
    elif name == "ini":
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(first.decode("ascii"))
        assert dict(parser["record"]) == {"n": "1"}
    elif name == "yaml":
        assert first == b"n: 1\n"
    else:
        assert first.startswith(b"n = 1" if name == "toml" else b'{"n": 1}')


def test_a_pattern_is_checked_when_the_writer_is_built(tmp_path):
    """A mistake in it would otherwise cost one error per packet."""
    for pattern, problem in [
        ("cap_{mac}.json", r"uses \{mac\}, which is not a field"),
        ("cap_{}.json", "bare field names only"),
        ("cap_{0}.json", "bare field names only"),
        ("cap_{xid.real}.json", "bare field names only"),
        ("cap_{xid[0]}.json", "bare field names only"),
        ("cap_{xid.json", "malformed"),
        ("cap_{index:{width}}.json", r"uses \{width\}"),
    ]:
        with pytest.raises(ValueError, match=problem):
            CaptureWriter(str(tmp_path / pattern), per_record=True, fields=("xid",))
    with pytest.raises(ValueError, match="filled in by the writer"):
        CaptureWriter("cap_{index}.json", per_record=True, fields=("index",))
    with pytest.raises(ValueError, match="identifier"):
        CaptureWriter("cap_{index}.json", per_record=True, fields=("not a name",))


def test_a_field_with_no_value_is_refused_when_written(tmp_path):
    pattern = str(tmp_path / "cap_{xid}.json")
    with CaptureWriter(pattern, per_record=True, fields=("xid",)) as writer:
        with pytest.raises(ValueError, match=r"no value for the field \{xid\}"):
            writer.write(FIRST)
    assert os.listdir(tmp_path) == []


@pytest.mark.parametrize(
    "value, name",
    [
        ("..", "unknown"),
        ("../../etc/passwd", "etc_passwd"),
        ("a/b\\c", "a_b_c"),
        ("C:\\Users\\Public\\x", "C_Users_Public_x"),
        ("", "unknown"),
        ("\x00\x1b[2J", "2J"),
        ("NUL", "_NUL"),
        ("com1", "_com1"),
        ("x" * 500, "x" * 55 + "-" + hashlib.sha256(b"x" * 500).hexdigest()[:8]),
    ],
)
def test_a_value_from_the_network_cannot_leave_the_directory_or_name_a_device(
    value, name, tmp_path
):
    pattern = str(tmp_path / "{client}.json")
    with CaptureWriter(pattern, per_record=True, fields=("client",)) as writer:
        writer.write(FIRST, {"n": 1}, names={"client": value})
    assert os.listdir(tmp_path) == [name + ".json"]


def test_one_writer_creates_at_most_its_budget_of_files(tmp_path, caplog):
    """A field value a peer chooses would otherwise decide how many files
    land on the disk."""
    pattern = str(tmp_path / "{client}.json")
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        with CaptureWriter(
            pattern, per_record=True, fields=("client",), max_files=5
        ) as writer:
            for number in range(50):
                writer.write(FIRST, {"n": number}, names={"client": "c%d" % number})
            # A file already created may still be rewritten.
            writer.write(FIRST, {"n": "again"}, names={"client": "c0"})
    assert len(os.listdir(tmp_path)) == 5
    assert (writer.written, writer.refused) == (6, 45)
    assert json.loads((tmp_path / "c0.json").read_text()) == {"n": "again"}
    assert (
        len(caplog.records) == 1 and "5 files written" in caplog.records[0].getMessage()
    )


def test_the_default_budget_is_a_thousand_files(tmp_path):
    pattern = str(tmp_path / "{index}.json")
    with CaptureWriter(pattern, per_record=True) as writer:
        for _ in range(1003):
            writer.write(THIRD, {})
    assert (writer.written, writer.refused) == (1000, 3)


# -- a value cut for a file name keeps a digest ----------------------------------

#: What the rule gives for these values: the first 55 characters that survive
#: the clean-up, a hyphen, and the first 8 hex digits of the SHA-256 of the
#: value as given. Written out, so a change of the rule fails here.
LONG_ID = "01:" + ":".join("%02x" % number for number in range(1, 90))


@pytest.mark.parametrize(
    "value, name",
    [
        ("a" * 300, "a" * 55 + "-9835fa6b"),
        ("a" * 299 + "b", "a" * 55 + "-daf00507"),
        (LONG_ID, "01_01_02_03_04_05_06_07_08_09_0a_0b_0c_0d_0e_0f_10_11_1-fd60b6a7"),
        ("a" * 65, "a" * 55 + "-635361c4"),
        ("a" * 64, "a" * 64),
        ("a" * 54 + "." + "b" * 40, "a" * 54 + "-4adc9d0e"),
    ],
)
def test_a_value_over_the_ceiling_is_cut_and_ends_in_a_digest_of_the_whole(
    value, name, tmp_path
):
    pattern = str(tmp_path / "{client}.json")
    with CaptureWriter(pattern, per_record=True, fields=("client",)) as writer:
        writer.write(FIRST, {"n": 1}, names={"client": value})
    assert os.listdir(tmp_path) == [name + ".json"]
    assert len(name) <= 64


def test_two_long_values_that_agree_at_the_start_name_two_files(tmp_path):
    pattern = str(tmp_path / "{client}.json")
    with CaptureWriter(pattern, per_record=True, fields=("client",)) as writer:
        writer.write(FIRST, {"n": 1}, names={"client": "a" * 300})
        writer.write(FIRST, {"n": 2}, names={"client": "a" * 299 + "b"})
        writer.write(FIRST, {"n": 3}, names={"client": "a" * 300})
    assert len(os.listdir(tmp_path)) == 2
    assert writer.written == 3 and writer.refused == 0
