"""The scripts under ``examples/`` run as a reader would run them.

Each is started as its own process with no argument, so it builds its own
capture in a temporary directory. Neither touches the network beyond a
loopback socket it binds itself.
"""

import json
import pathlib
import re
import subprocess
import sys

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _run(name, *arguments):
    return subprocess.run(
        [sys.executable, str(EXAMPLES / name)] + list(arguments),
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_every_example_is_run_by_a_test_here():
    assert sorted(path.name for path in EXAMPLES.glob("*.py")) == [
        "dissect_capture.py",
        "replay_to_loopback.py",
    ]


def test_dissect_capture_prints_one_record_per_frame_with_its_own_layer():
    done = _run("dissect_capture.py")
    assert done.returncode == 0, done.stderr
    records = [json.loads(line) for line in done.stdout.splitlines()]
    assert [[layer["layer"] for layer in r["layers"]] for r in records] == [
        ["ethernet", "ipv4", "udp", "syslog"],
        ["ethernet", "ipv4", "tcp"],
        ["ethernet"],
        ["ethernet", "ipv4", "udp", "syslog"],
    ]
    assert records[0]["layers"][-1] == {"layer": "syslog", "facility": 4, "severity": 2}
    assert bytes.fromhex(records[3]["payload"]) == b"the fan is back"
    assert "4 frames, 0 malformed, 0 of a link type with no dissector" in done.stderr


def test_dissect_capture_takes_a_capture_and_a_filter(tmp_path):
    import pktcap

    path = tmp_path / "one.pcap"
    with pktcap.PcapWriter(path) as writer:
        writer.write(1.0, ("192.0.2.5", 50000), ("192.0.2.1", 514), b"<13>kept")
        writer.write(2.0, ("198.51.100.5", 50000), ("192.0.2.1", 514), b"<13>not")
        writer.write(3.0, ("192.0.2.5", 50000), ("192.0.2.1", 514), b"no priority")
    done = _run("dissect_capture.py", str(path), "proto=syslog and src=192.0.2.0/24")
    assert done.returncode == 0, done.stderr
    (record,) = [json.loads(line) for line in done.stdout.splitlines()]
    assert bytes.fromhex(record["payload"]) == b"kept"
    # The third datagram is not syslog: counted, and the reader went on.
    assert "3 frames, 1 malformed" in done.stderr


def test_replay_to_loopback_delivers_every_payload_at_the_recorded_pace():
    done = _run("replay_to_loopback.py")
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert lines[-1] == "sent 3, passed over 0 partial"
    rows = [
        re.match(r"\s*([\d.]+)s  127\.0\.0\.1:\d+  (.+)$", line) for line in lines[:-1]
    ]
    assert [row.group(2) for row in rows] == ["b'first'", "b'second'", "b'third'"]
    # A quarter of a second apart in the capture, and so in the replay.
    assert float(rows[2].group(1)) - float(rows[0].group(1)) >= 0.4
