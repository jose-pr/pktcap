"""``command_hook``: a program run for each captured item.

Every test runs a real program from ``tmp_path``: one that prints bytes that
are not UTF-8, one that outlives its time limit with a child of its own, one
that records what it is given. What a hook is given comes from datagrams any
sender can craft, so it is passed on standard input and in the environment,
never as an argument and never through a shell.
"""

import inspect
import json
import logging
import os
import pickle
import re
import sys
import time

import pytest

import captures as build
from hook_programs import kill, python_hook, wait_until_dead
from pktcap import (
    CapturedFrame,
    CaptureHookError,
    CaptureWriter,
    FrameDissector,
    PktcapError,
    UnsupportedFormatError,
    command_hook,
    copy_frames,
    frame_record,
)

NOISE = r"""
import sys
sys.stdout.buffer.write(b"\x81\xff\xfe out\n")
sys.stderr.buffer.write(b"\x81\xff\xfe err\n")
sys.exit(3)
"""

RECORD = r"""
import json, os, sys
(HERE / "argv.json").write_text(json.dumps(sys.argv[1:]))
(HERE / "stdin.txt").write_bytes(sys.stdin.buffer.read())
(HERE / "env.json").write_text(json.dumps({k: v for k, v in os.environ.items() if k.startswith("PKTCAP_HOOK_")}))
(HERE / "names.json").write_text(json.dumps(sorted(os.environ)))
"""

CHILD = r"""
import os, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
(HERE / "child.pid").write_text(str(child.pid))
(HERE / "parent.pid").write_text(str(os.getpid()))
time.sleep(120)
"""

UDP_FRAME = build.ethernet(
    build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"first"))
)


def frame(raw=UDP_FRAME, when=1700000000.5):
    return FrameDissector().dissect(CapturedFrame(when, 1, raw))


def read_json(path):
    return json.loads(path.read_text())


# -- what the program is given ---------------------------------------------------


def test_a_program_is_given_the_record_on_stdin_and_nothing_as_an_argument(
    tmp_path, monkeypatch
):
    program = python_hook(monkeypatch, tmp_path, "record", RECORD)
    item = frame()

    command_hook(program)(item)

    assert read_json(tmp_path / "argv.json") == []
    assert json.loads((tmp_path / "stdin.txt").read_text()) == frame_record(item)
    assert read_json(tmp_path / "env.json") == {"PKTCAP_HOOK_FORMAT": "json"}


def test_the_names_become_variables_of_the_programs_environment(tmp_path, monkeypatch):
    program = python_hook(monkeypatch, tmp_path, "record", RECORD)
    seen = []

    def names(item):
        seen.append(item)
        return {"client_id": "01:00:11", "xid": 0x1234ABCD}

    item = frame()
    command_hook(program, format="yaml", names=names)(item)

    assert seen == [item]
    assert read_json(tmp_path / "env.json") == {
        "PKTCAP_HOOK_CLIENT_ID": "01_00_11",  # the writer's rule for a name
        "PKTCAP_HOOK_XID": "305441741",
        "PKTCAP_HOOK_FORMAT": "yaml",
    }
    assert (tmp_path / "stdin.txt").read_text().startswith("time: 1700000000.5")


def test_the_record_of_the_datagram_is_given_when_the_datagram_is_asked_for(
    tmp_path, monkeypatch
):
    program = python_hook(monkeypatch, tmp_path, "record", RECORD)
    item = frame()

    command_hook(program, datagrams=True)(item)

    record = read_json(tmp_path / "stdin.txt")
    assert record["source"] == "10.0.0.5:50000" and record["payload"] == b"first".hex()
    arp = frame(b"\x02" * 12 + b"\x08\x06" + bytes(28))
    with pytest.raises(ValueError, match="datagram"):
        command_hook(program, datagrams=True)(arp)


def test_a_value_chosen_by_a_sender_reaches_no_shell_and_no_environment_name(
    tmp_path, monkeypatch
):
    """A marker planted in a datagram is rendered by the writer's name rule: it
    holds no separator, no control character, at most 64 characters; the
    program finds it in no argument and in no environment name, and it is
    never run."""
    canary = tmp_path / "pwned"
    nasty = "MARKER $(touch %s); `touch %s` | & > < ; \n\"'" % (canary, canary)
    directory = tmp_path / "dir with spaces & more"
    directory.mkdir()
    program = python_hook(monkeypatch, directory, "record", RECORD)
    planted = frame(
        build.ethernet(
            build.ipv4(
                "10.0.0.5", "10.0.0.1", build.udp(50000, 69, nasty.encode("utf-8"))
            )
        )
    )

    command_hook(
        program,
        names=lambda item: {"client": item.datagram().payload.decode("utf-8")},
    )(planted)

    assert not canary.exists()
    assert read_json(directory / "argv.json") == []
    value = read_json(directory / "env.json")["PKTCAP_HOOK_CLIENT"]
    assert re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value) and "MARKER" in value
    names = read_json(directory / "names.json")
    assert not [name for name in names if "MARKER" in name or "touch" in name]
    # The record on standard input is the capture's own, hex and all.
    assert nasty.encode("utf-8").hex() in (directory / "stdin.txt").read_text()


def test_two_names_that_are_one_variable_are_refused(tmp_path, monkeypatch):
    program = python_hook(monkeypatch, tmp_path, "record", RECORD)
    hook = command_hook(program, names=lambda item: {"xid": 1, "XID": 2})
    with pytest.raises(ValueError, match="XID"):
        hook(frame())


def test_a_long_value_is_cut_to_the_writers_bound(tmp_path, monkeypatch):
    program = python_hook(monkeypatch, tmp_path, "record", RECORD)
    command_hook(program, names=lambda item: {"client": "x" * 5000})(frame())
    value = read_json(tmp_path / "env.json")["PKTCAP_HOOK_CLIENT"]
    assert len(value) == 64 and value.startswith("x" * 55)


@pytest.mark.parametrize(
    "key", ["a b", "a=b", "", "1abc", "a\x00b", "naïve", "format", "FORMAT", "a;b"]
)
def test_a_field_name_that_is_not_a_plain_identifier_is_refused(
    tmp_path, monkeypatch, key
):
    program = python_hook(monkeypatch, tmp_path, "record", RECORD)
    hook = command_hook(program, names=lambda item: {key: "v"})
    with pytest.raises(ValueError, match="name|FORMAT"):
        hook(frame())
    assert not (tmp_path / "argv.json").exists()  # nothing was started


def test_names_must_give_a_mapping(tmp_path, monkeypatch):
    program = python_hook(monkeypatch, tmp_path, "record", RECORD)
    with pytest.raises(TypeError):
        command_hook(program, names=lambda item: ["xid"])(frame())


def test_a_large_record_for_a_program_that_never_reads_it_does_not_hang(
    tmp_path, monkeypatch
):
    program = python_hook(monkeypatch, tmp_path, "deaf", "import sys\nsys.exit(0)\n")
    big = frame(
        build.ethernet(
            build.ipv4("10.0.0.5", "10.0.0.1", build.udp(1, 69, b"x" * 60000))
        )
    )
    hook = command_hook(program, timeout=20.0)
    started = time.monotonic()
    hook(big)
    assert time.monotonic() - started < 15 and hook.failures == 0


# -- failures ---------------------------------------------------------------------


def test_a_program_that_prints_bytes_outside_utf8_is_a_counted_failure(
    tmp_path, monkeypatch, caplog
):
    program = python_hook(monkeypatch, tmp_path, "noise", NOISE)
    hook = command_hook(program)

    with caplog.at_level(logging.DEBUG, logger="pktcap"):
        hook(frame())

    failure = [r for r in caplog.records if "failed" in r.getMessage()]
    assert len(failure) == 1 and failure[0].levelno == logging.ERROR
    assert "3" in failure[0].getMessage()
    assert "\\ufffd" in failure[0].getMessage()  # replaced, then escaped for the log
    assert hook.failures == 1


def test_a_failing_hook_with_fail_fast_raises_the_packages_error(tmp_path, monkeypatch):
    program = python_hook(monkeypatch, tmp_path, "noise", NOISE)

    with pytest.raises(CaptureHookError) as raised:
        command_hook(program, fail_fast=True)(frame())

    error = raised.value
    assert isinstance(error, PktcapError) and isinstance(error, OSError)
    assert (error.status, error.timed_out) == (3, False)
    assert "exit status 3" in str(error) and str(error).startswith("hook command ")
    clone = pickle.loads(pickle.dumps(error))
    assert (clone.status, clone.timed_out, str(clone)) == (3, False, str(error))


def test_without_fail_fast_the_next_item_still_runs(tmp_path, monkeypatch):
    program = python_hook(
        monkeypatch,
        tmp_path,
        "count",
        'import sys\n(HERE / "runs.txt").open("a").write("x")\nsys.exit(1)\n',
    )
    hook = command_hook(program)
    for _ in range(3):
        hook(frame())
    assert (tmp_path / "runs.txt").read_text() == "xxx" and hook.failures == 3


def test_standard_error_is_bounded_in_the_error_and_the_log(
    tmp_path, monkeypatch, caplog
):
    program = python_hook(
        monkeypatch,
        tmp_path,
        "loud",
        'import sys\nsys.stderr.write("x" * 100000 + "\\x1b[31mTAIL")\nsys.exit(1)\n',
    )

    with caplog.at_level(logging.ERROR, logger="pktcap"):
        with pytest.raises(CaptureHookError) as raised:
            command_hook(program, fail_fast=True)(frame())

    assert len(str(raised.value)) < 1000
    assert str(raised.value).endswith("TAIL")
    assert "\x1b" not in str(raised.value) and "\\x1b" in str(raised.value)
    assert all(len(r.getMessage()) < 1000 for r in caplog.records)
    assert all("\x1b" not in r.getMessage() for r in caplog.records)


def test_the_streams_are_logged_by_size_never_by_content(tmp_path, monkeypatch, caplog):
    program = python_hook(
        monkeypatch,
        tmp_path,
        "secret",
        'print("SECRET-PAYLOAD")\nimport sys\nsys.stdin.read()\n',
    )

    with caplog.at_level(logging.DEBUG, logger="pktcap"):
        command_hook(program)(frame())

    text = " ".join(r.getMessage() for r in caplog.records)
    assert "SECRET-PAYLOAD" not in text
    assert re.search(r"wrote \d+ characters to stdout and 0 to stderr", text)


def test_a_failure_is_logged_once_per_interval_with_a_bounded_line(
    tmp_path, monkeypatch, caplog
):
    program = python_hook(
        monkeypatch,
        tmp_path,
        "boom",
        'import sys\nsys.stderr.write("boom\\n" * 200)\nsys.exit(3)\n',
    )
    hook = command_hook(program)
    clock = [1000.0]

    with caplog.at_level(logging.ERROR, logger="pktcap"):
        with monkeypatch.context() as patched:
            patched.setattr(time, "monotonic", lambda: clock[0])
            for _ in range(3):
                hook(frame())
            assert len([r for r in caplog.records if "failed" in r.getMessage()]) == 1
            clock[0] += 61.0
            hook(frame())

    lines = [r.getMessage() for r in caplog.records if "failed" in r.getMessage()]
    assert len(lines) == 2 and hook.failures == 4
    assert "4 failures" in lines[1]
    assert all("\n" not in line and len(line) < 600 for line in lines)


# -- the time limit ------------------------------------------------------------------


def test_a_program_that_outlives_the_limit_is_killed_with_its_children(
    tmp_path, monkeypatch, caplog
):
    program = python_hook(monkeypatch, tmp_path, "sleeper", CHILD)
    hook = command_hook(program, timeout=5.0)
    pids = []
    started = time.monotonic()
    try:
        with caplog.at_level(logging.ERROR, logger="pktcap"):
            hook(frame())
        # The limit, then the kill: not however long the program's children live.
        assert time.monotonic() - started < 30
        pids = [
            int((tmp_path / name).read_text())
            for name in ("child.pid", "parent.pid")
            if (tmp_path / name).exists()
        ]
        assert len(pids) == 2, "the hook had not started its child in time"
        for pid in pids:
            assert wait_until_dead(pid), "process %d outlived its hook" % pid
    finally:
        for pid in pids:
            kill(pid)
    assert hook.failures == 1
    assert any("killed" in r.getMessage() for r in caplog.records)


def test_a_timeout_with_fail_fast_says_so(tmp_path, monkeypatch):
    program = python_hook(monkeypatch, tmp_path, "sleeper", CHILD)
    pids = []
    try:
        with pytest.raises(CaptureHookError) as raised:
            command_hook(program, timeout=5.0, fail_fast=True)(frame())
        assert raised.value.timed_out is True and raised.value.status is None
        assert "killed" in str(raised.value)
        pids = [
            int((tmp_path / n).read_text())
            for n in ("child.pid", "parent.pid")
            if (tmp_path / n).exists()
        ]
        for pid in pids:
            assert wait_until_dead(pid)
    finally:
        for pid in pids:
            kill(pid)


def test_the_time_limit_is_a_keyword_whose_default_is_ten_seconds():
    parameters = inspect.signature(command_hook).parameters
    assert parameters["timeout"].default == 10.0
    assert parameters["timeout"].kind is inspect.Parameter.KEYWORD_ONLY
    assert [n for n, p in parameters.items() if p.kind is p.POSITIONAL_OR_KEYWORD] == [
        "command"
    ]


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_a_time_limit_that_is_not_positive_and_finite_is_refused(
    tmp_path, monkeypatch, timeout
):
    program = python_hook(monkeypatch, tmp_path, "noop", "pass\n")
    with pytest.raises(ValueError, match="timeout"):
        command_hook(program, timeout=timeout)


@pytest.mark.parametrize("timeout", [True, "10", None])
def test_a_time_limit_of_the_wrong_type_is_a_type_error(tmp_path, monkeypatch, timeout):
    program = python_hook(monkeypatch, tmp_path, "noop", "pass\n")
    with pytest.raises(TypeError, match="timeout"):
        command_hook(program, timeout=timeout)


# -- finding the program, once ---------------------------------------------------------


def test_the_command_is_found_before_anything_runs(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        command_hook(str(tmp_path / "absent"))
    with pytest.raises(ValueError, match="not on PATH"):
        command_hook("pktcap-no-such-program-anywhere")
    with pytest.raises(ValueError, match="not a file"):
        command_hook(str(tmp_path))


@pytest.mark.parametrize("command", ["", "a\x00b"])
def test_an_empty_command_and_one_with_a_nul_are_refused(command):
    with pytest.raises(ValueError, match="command"):
        command_hook(command)


def test_a_command_that_is_not_text_is_a_type_error():
    with pytest.raises(TypeError, match="command"):
        command_hook(["echo"])


@pytest.mark.skipif(os.name != "posix", reason="POSIX has an executable bit")
def test_a_file_that_is_not_executable_is_refused(tmp_path):
    plain = tmp_path / "plain"
    plain.write_text("#!/bin/sh\n")
    plain.chmod(0o644)
    with pytest.raises(ValueError, match="not executable"):
        command_hook(str(plain))


@pytest.mark.skipif(sys.platform != "win32", reason="batch files are Windows'")
@pytest.mark.parametrize("suffix", [".bat", ".cmd", ".BAT", ".Cmd"])
def test_a_batch_file_is_refused_on_windows(tmp_path, suffix):
    batch = tmp_path / ("hook" + suffix)
    batch.write_bytes(b"@echo off\r\n")
    with pytest.raises(ValueError, match="batch"):
        command_hook(str(batch))


@pytest.mark.skipif(os.name != "posix", reason="a launcher is a file on POSIX")
def test_a_name_with_a_directory_is_that_file_from_the_directory_it_was_given_in(
    tmp_path, monkeypatch
):
    where = tmp_path / "where"
    other = tmp_path / "other"
    where.mkdir()
    other.mkdir()
    python_hook(monkeypatch, where, "record", RECORD)
    monkeypatch.chdir(where)
    hook = command_hook("./record")
    monkeypatch.chdir(other)

    hook(frame())

    assert (where / "argv.json").exists()


def test_the_program_is_an_absolute_path_found_at_the_start(tmp_path, monkeypatch):
    program = python_hook(monkeypatch, tmp_path, "record", RECORD)
    hook = command_hook(program)
    monkeypatch.chdir(tmp_path.parent)
    hook(frame())
    assert (tmp_path / "argv.json").exists()


def test_a_bare_name_is_looked_up_on_path_once(tmp_path, monkeypatch):
    directory = tmp_path / "bin"
    directory.mkdir()
    program = python_hook(monkeypatch, directory, "pktcap_hook_probe", RECORD)
    if os.name == "nt":
        # The interpreter is the program: find it by its own name.
        name = os.path.basename(program)
        monkeypatch.setenv("PATH", os.path.dirname(program))
    else:
        name = "pktcap_hook_probe"
        monkeypatch.setenv("PATH", str(directory))

    hook = command_hook(name)
    monkeypatch.setenv("PATH", str(tmp_path))  # gone from PATH: already found

    hook(frame())

    assert (directory / "argv.json").exists()


# -- the format of the record ---------------------------------------------------------


def test_a_format_that_is_not_a_record_format_is_refused(tmp_path, monkeypatch):
    program = python_hook(monkeypatch, tmp_path, "noop", "pass\n")
    for name in ("pcap", "pcapng", "nonsense"):
        with pytest.raises(UnsupportedFormatError):
            command_hook(program, format=name)


# -- a hook in a copy -----------------------------------------------------------------


def test_copy_frames_runs_the_program_once_for_each_frame_written(
    tmp_path, monkeypatch
):
    program = python_hook(
        monkeypatch,
        tmp_path,
        "tally",
        'import sys\nsys.stdin.read()\n(HERE / "runs.txt").open("a").write("x")\n',
    )
    out = tmp_path / "out.json"
    raw = [UDP_FRAME, b"\x02" * 12 + b"\x08\x06" + bytes(28), UDP_FRAME]
    frames = [
        FrameDissector().dissect(CapturedFrame(float(i), 1, data))
        for i, data in enumerate(raw)
    ]
    with CaptureWriter(out) as writer:
        result = copy_frames(
            frames, writer, datagrams=True, each=command_hook(program, datagrams=True)
        )
    assert result.written == 2
    assert (tmp_path / "runs.txt").read_text() == "xx"


def test_fail_fast_ends_the_copy_at_the_first_failure(tmp_path, monkeypatch):
    program = python_hook(
        monkeypatch,
        tmp_path,
        "fail",
        'import sys\n(HERE / "runs.txt").open("a").write("x")\nsys.exit(1)\n',
    )
    out = tmp_path / "out.json"
    with CaptureWriter(out) as writer:
        with pytest.raises(CaptureHookError):
            copy_frames(
                [frame(), frame(), frame()],
                writer,
                each=command_hook(program, fail_fast=True),
            )
    assert (tmp_path / "runs.txt").read_text() == "x"
    assert writer.written == 1  # the frame whose hook failed was written
