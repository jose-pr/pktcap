"""``pktcap capture`` and the writer rules a subclass and a user meet.

What the override points do when the default invocation gives no ``--duration``,
which format a hook is given, what a subclass's own ``listen`` may hold, what
``--append`` refuses, and that sockets a command bound are not left open when
the source turns them away.
"""

import json
import subprocess
import sys
import threading
import time
from typing import List, Optional

import pytest

pytest.importorskip("duho")

from duho import main as run  # noqa: E402
from hook_programs import python_hook  # noqa: E402
from netimps import UDPEndpoint, bind  # noqa: E402

import captures as build  # noqa: E402
from pktcap import CaptureWriter  # noqa: E402
from pktcap.cli import Capture, main  # noqa: E402
from test_cli_listen import SAFETY, listen_and_send  # noqa: E402

ENVIRONMENT = r"""
import os, sys
(HERE / "format.txt").write_text(os.environ["PKTCAP_HOOK_FORMAT"])
(HERE / "stdin.txt").write_bytes(sys.stdin.buffer.read())
"""


def in_a_thread(command, argv, wait=8.0):
    """``(still running, status)`` of ``run(command, argv)`` after ``wait``
    seconds at most. The thread is a daemon, so a command that never ends does
    not hold the process."""
    outcome = {}

    def target():
        try:
            outcome["status"] = run(command, argv)
        except BaseException as exc:  # reported by the assertion that reads it
            outcome["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(wait)
    return thread.is_alive(), outcome


# -- _stop is asked whatever the options are -------------------------------------


def test_stop_ends_a_capture_that_was_given_no_duration(tmp_path):
    asked = []

    class Stops(Capture):
        _parsername_ = "capture"

        def _stop(self):
            asked.append(time.monotonic())
            return True

    alive, outcome = in_a_thread(
        Stops, ["--listen", "127.0.0.1:0", "-o", str(tmp_path / "out.jsonl")]
    )
    assert not alive, "the capture ran on although _stop said to end it"
    assert outcome.get("status") in (0, None) and "error" not in outcome
    assert asked


def test_the_default_stop_does_not_end_a_capture_that_has_no_duration(tmp_path):
    ran = Capture(duration=None)
    assert ran._stop() is False


# -- the hook is given the format the writer writes -----------------------------------


@pytest.mark.parametrize(
    "target, name, starts",
    [
        ("out.yaml", "yaml", b"time:"),
        ("out.jsonl", "json", b"{"),
        ("out.pcap", "json", b"{"),
        ("-", "json", b"{"),
    ],
)
def test_a_hook_is_given_the_format_the_writer_writes(
    target, name, starts, caplog, tmp_path, monkeypatch, capfd
):
    hook = python_hook(monkeypatch, tmp_path, "format", ENVIRONMENT)
    output = target if target == "-" else str(tmp_path / target)
    argv = ["capture", "--listen", "127.0.0.1:0", "--count", "1", "--hook", hook]
    status, _ = listen_and_send(argv + ["-o", output] + SAFETY, caplog, [b"a"])
    capfd.readouterr()
    assert status == 0
    assert (tmp_path / "format.txt").read_text() == name
    assert (tmp_path / "stdin.txt").read_bytes().lstrip(b"-\r\n").startswith(starts)


# -- a subclass's own listen ------------------------------------------------------


SEEN: List[List[int]] = []


class Ports(Capture):
    """A subclass whose ``--listen`` holds numbers, not text."""

    _parsername_ = "capture"

    listen: Optional[List[int]] = None
    "ports"
    ("--listen",)

    def _endpoints(self):
        SEEN.append(list(self.listen))
        return (UDPEndpoint(bind("127.0.0.1", 0)),)


def test_a_subclass_whose_listen_is_not_text_reaches_its_endpoints(tmp_path):
    SEEN.clear()
    argv = ["--listen", "0", "--count", "0", "-o", str(tmp_path / "out.jsonl")]
    alive, outcome = in_a_thread(Ports, argv)
    assert not alive and "error" not in outcome, outcome
    assert SEEN == [[0]]


def test_a_bind_that_fails_names_what_was_asked_for_as_text(tmp_path):
    class Refuses(Ports):
        def _endpoints(self):
            raise OSError("no such address")

    alive, outcome = in_a_thread(
        Refuses, ["--listen", "7", "--listen", "8", "--count", "0"]
    )
    error = outcome.get("error")
    assert isinstance(error, OSError) and "cannot listen on 7, 8" in str(error)


# -- the source turns the endpoints away ----------------------------------------------


def test_the_endpoints_a_command_bound_are_closed_when_the_source_refuses_them(
    tmp_path,
):
    made = []

    class TooMany(Capture):
        _parsername_ = "capture"

        def _endpoints(self):
            made.extend(UDPEndpoint(bind("127.0.0.1", 0)) for _ in range(257))
            return tuple(made)

    try:
        alive, outcome = in_a_thread(
            TooMany,
            [
                "--listen",
                "127.0.0.1:0",
                "--count",
                "0",
                "-o",
                str(tmp_path / "o.jsonl"),
            ],
        )
        assert not alive
        assert isinstance(outcome.get("error"), ValueError), outcome
        assert len(made) == 257, outcome
        assert all(e.socket.fileno() == -1 for e in made)
    finally:
        for endpoint in made:
            endpoint.close()


# -- listening on ------------------------------------------------------------------------


def test_listening_on_is_shown_unless_quiet(tmp_path):
    """As a real process: the log goes to the stderr the process started with."""
    base = [sys.executable, "-m", "pktcap", "capture", "--listen", "127.0.0.1:0"]
    base += ["--count", "0", "-o"]
    plain = subprocess.run(
        base + [str(tmp_path / "a.jsonl")], capture_output=True, text=True, timeout=60
    )
    assert plain.returncode == 0 and "listening on 127.0.0.1:" in plain.stderr
    quiet = subprocess.run(
        base + [str(tmp_path / "b.jsonl"), "-q"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert quiet.returncode == 0 and "listening on" not in quiet.stderr


# -- --append and --per-record ---------------------------------------------------------


def test_append_with_per_record_is_refused_and_replaces_nothing(tmp_path, capsys):
    trace = tmp_path / "trace.pcap"
    frame = build.ethernet(
        build.ipv4("10.0.0.5", "10.0.0.1", build.udp(5, 9999, b"hello"))
    )
    trace.write_bytes(build.pcap([frame]))
    records = tmp_path / "records"
    records.mkdir()
    (records / "0.txt").write_bytes(b"kept\n")
    argv = ["convert", "-i", str(trace), "-o", str(records / "{index}.txt")]
    assert main(argv + ["--per-record", "--append"]) == 2
    assert "append" in capsys.readouterr().err
    assert (records / "0.txt").read_bytes() == b"kept\n"


def test_the_writer_refuses_append_with_per_record(tmp_path):
    with pytest.raises(ValueError, match="append"):
        CaptureWriter(str(tmp_path / "{index}.json"), per_record=True, append=True)


def test_append_alone_still_adds_to_a_file(tmp_path):
    target = tmp_path / "out.jsonl"
    target.write_bytes(b'{"kept": true}\n')
    with CaptureWriter(str(target), append=True):
        pass
    assert json.loads(target.read_text().splitlines()[0]) == {"kept": True}
