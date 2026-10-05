"""Replay what the reference recorded: pktcap against tshark, with no tool
installed.

Each directory under ``cases/`` holds an input (``case.pcap``,
``case.pcapng``, or ``case.json`` for what ``PcapWriter`` is asked to write)
and ``golden.json``, tshark's answer about it, recorded by ``record.py``.

- ``read-``: pktcap decodes the same datagrams tshark does.
- ``refuse-``: tshark fails on the capture, and pktcap raises
  ``CaptureFormatError`` after the same number of frames.
- ``write-``: what ``PcapWriter`` writes is, octet for octet, the file tshark
  read with every checksum good.

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
    CaptureFormatError,
    FrameDecoder,
    PcapWriter,
    read_datagrams,
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


# -- the cases themselves -------------------------------------------------


def test_there_are_cases_of_every_kind_and_each_has_a_golden():
    kinds = {case.name.split("-")[0] for case in CASES}
    assert kinds == {"read", "refuse", "write"}
    assert len(CASES) >= 30
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
def test_pktcap_decodes_the_datagrams_tshark_does(case):
    golden = _golden(case)
    assert golden["exit_status"] == 0
    decoder = FrameDecoder()
    datagrams = list(read_datagrams(_capture(case), decoder=decoder))
    assert decoder.stats.frames == golden["frames"]
    assert [_as_golden(d) for d in datagrams] == [
        (g["source"], g["destination"], g["payload"]) for g in golden["datagrams"]
    ]
    for datagram, recorded in zip(datagrams, golden["datagrams"]):
        assert datagram.time == pytest.approx(float(recorded["time"]), abs=2e-6)
        # tshark states the datagram's own length; what the capture kept of
        # it may be less, and pktcap says so.
        cut = recorded["udp_length"] - 8 > len(datagram.payload)
        assert datagram.truncated is cut and not datagram.fragmented
    stats = decoder.stats
    assert (stats.malformed, stats.unsupported, stats.dropped, stats.pending) == (
        0,
        0,
        0,
        0,
    )


def test_one_case_is_cut_by_a_snap_length_and_both_say_so():
    case = HERE / "cases" / "read-built-snap-length"
    (datagram,) = read_datagrams(_capture(case))
    (recorded,) = _golden(case)["datagrams"]
    assert datagram.truncated and recorded["udp_length"] - 8 > len(datagram.payload)


@pytest.mark.parametrize("case", _named("read-", deviating=True))
def test_a_listed_deviation_behaves_as_listed_and_does_differ(case):
    golden = _golden(case)
    expected = DEVIATIONS[case.name]["pktcap"]
    decoder = FrameDecoder()
    datagrams, raised = [], False
    try:
        for datagram in read_datagrams(_capture(case), decoder=decoder):
            datagrams.append(datagram)
    except CaptureFormatError:
        raised = True
    assert raised is expected.get("raises", False)
    if raised:
        assert decoder.stats.frames == expected["frames"]
    else:
        stats = decoder.stats
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


@pytest.mark.parametrize("case", _named("write-"))
def test_tshark_read_exactly_what_pcapwriter_writes(case):
    golden = _golden(case)
    question = json.loads((case / "case.json").read_text(encoding="utf-8"))
    stream = io.BytesIO()
    with PcapWriter(stream) as writer:
        for time, source, destination, payload in question["datagrams"]:
            writer.write(
                time, tuple(source), tuple(destination), bytes.fromhex(payload)
            )
    written = stream.getvalue()
    # The golden is about this very file.
    assert hashlib.sha256(written).hexdigest() == golden["pcap_sha256"]
    assert golden["exit_status"] == 0 and golden["error"] is None
    assert golden["frames"] == len(question["datagrams"]) == len(golden["datagrams"])
    for recorded, asked in zip(golden["datagrams"], question["datagrams"]):
        assert recorded["payload"] == asked[3]
        assert float(recorded["time"]) == pytest.approx(asked[0], abs=1e-6)
        assert recorded["udp_checksum"] == "1"  # good
        assert recorded["ip_checksum"] in ("1", "")  # good; IPv6 has none
    # And pktcap reads its own output as tshark does.
    assert [_as_golden(d) for d in read_datagrams(io.BytesIO(written))] == [
        (g["source"], g["destination"], g["payload"]) for g in golden["datagrams"]
    ]


# -- the README -----------------------------------------------------------


def test_the_readme_lists_exactly_the_deviations():
    text = README.read_text(encoding="utf-8")
    start = text.index("\n## Differences from tshark\n")
    section = text[start : text.index("\n## ", start + 1)]
    rows = re.findall(r"^\| `([a-z0-9-]+)` \| (.+) \|$", section, re.MULTILINE)
    assert dict(rows) == {
        name: entry["difference"] for name, entry in DEVIATIONS.items()
    }
