"""How a hook's program is run: started, bounded, ended, and found.

The run is the program's own exit within the time limit. A process it leaves
behind neither delays it nor makes it a failure, and one still running when the
limit passes is ended with the program, whoever its parent is.
"""

import logging
import os
import sys
import threading
import time

import pytest
from hook_programs import alive, kill, python_hook, wait_until_dead

import captures as build
from pktcap import (
    CapturedFrame,
    CaptureHookError,
    FrameDissector,
    command_hook,
)

UDP_FRAME = build.ethernet(
    build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 69, b"first"))
)

# Leaves a child that holds the program's streams, and exits at once.
LEAVES_A_CHILD = r"""
import subprocess, sys
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
with (HERE / "children.txt").open("a") as pids:
    pids.write("%d\n" % child.pid)
"""

# Starts a middle process, which starts a grandchild and exits: the grandchild's
# parent is gone before the program is. The program then waits.
ORPHANS_A_GRANDCHILD = r"""
import subprocess, sys, time
middle = (
    "import subprocess, sys\n"
    "grandchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
    "open(sys.argv[1], 'w').write(str(grandchild.pid))\n"
)
subprocess.Popen([sys.executable, "-c", middle, str(HERE / "grandchild.pid")]).wait()
(HERE / "ready.txt").write_text("ready")
time.sleep(120)
"""


def frame():
    return FrameDissector().dissect(CapturedFrame(1700000000.5, 1, UDP_FRAME))


def children(directory):
    path = directory / "children.txt"
    if not path.exists():
        return []
    return [int(line) for line in path.read_text().split()]


def test_a_program_that_exits_at_once_and_leaves_a_child_holding_its_streams_succeeds(
    tmp_path, monkeypatch
):
    program = python_hook(monkeypatch, tmp_path, "leaver", LEAVES_A_CHILD)
    hook = command_hook(program, timeout=30.0)
    threads = threading.active_count()
    started = time.monotonic()
    try:
        for _ in range(2):
            hook(frame())
        took = time.monotonic() - started
        assert hook.failures == 0
        assert took < 20, "the run waited for the child"
        assert threading.active_count() == threads
        pids = children(tmp_path)
        assert len(pids) == 2 and all(alive(pid) for pid in pids)
    finally:
        for pid in children(tmp_path):
            kill(pid)


def test_a_grandchild_whose_parent_already_left_is_ended_with_the_program(
    tmp_path, monkeypatch, caplog
):
    program = python_hook(monkeypatch, tmp_path, "orphaner", ORPHANS_A_GRANDCHILD)
    hook = command_hook(program, timeout=8.0)
    grandchild = None
    try:
        with caplog.at_level(logging.ERROR, logger="pktcap"):
            hook(frame())
        assert (tmp_path / "ready.txt").exists(), "the program had not started its tree"
        grandchild = int((tmp_path / "grandchild.pid").read_text())
        assert wait_until_dead(grandchild), "the grandchild outlived the hook"
    finally:
        if grandchild is not None:
            kill(grandchild)
    assert hook.failures == 1


# A file the system cannot start: text where a program should be. It has an
# executable ending and bit, so it passes the checks made when the hook is made.
def unstartable(tmp_path):
    path = tmp_path / ("not-a-program.exe" if os.name == "nt" else "not-a-program")
    path.write_bytes(b"this is text, not a program\n")
    path.chmod(0o755)
    return str(path)


def test_a_program_that_cannot_be_started_is_a_counted_failure(tmp_path, caplog):
    hook = command_hook(unstartable(tmp_path))
    with caplog.at_level(logging.ERROR, logger="pktcap"):
        hook(frame())
        hook(frame())
    assert hook.failures == 2
    lines = [
        r.getMessage()
        for r in caplog.records
        if "could not be started" in r.getMessage()
    ]
    assert len(lines) == 1 and "\n" not in lines[0]


def test_a_program_that_cannot_be_started_is_a_hook_error_with_fail_fast(tmp_path):
    with pytest.raises(CaptureHookError) as raised:
        command_hook(unstartable(tmp_path), fail_fast=True)(frame())
    assert raised.value.status is None and raised.value.timed_out is False
    assert "could not be started" in str(raised.value)


def test_a_program_removed_after_the_hook_was_made_is_a_failure(tmp_path):
    program = tmp_path / ("gone.exe" if os.name == "nt" else "gone")
    program.write_bytes(b"#!/bin/sh\nexit 0\n")
    program.chmod(0o755)
    hook = command_hook(str(program))
    program.unlink()
    hook(frame())
    assert hook.failures == 1


def test_a_copy_goes_on_after_a_program_that_cannot_be_started(tmp_path):
    from pktcap import CaptureWriter, copy_frames

    with CaptureWriter(tmp_path / "out.jsonl") as writer:
        result = copy_frames(
            [frame(), frame()], writer, each=command_hook(unstartable(tmp_path))
        )
    assert result.written == 2


# -- finding the program -----------------------------------------------------------


def planted(tmp_path):
    """A program in a directory of its own, which is the working directory."""
    directory = tmp_path / "plant"
    directory.mkdir()
    name = "pktcap_planted_hook"
    file = directory / (name + (".exe" if os.name == "nt" else ""))
    file.write_bytes(b"#!/bin/sh\nexit 0\n")
    file.chmod(0o755)
    return directory, name


def test_a_bare_name_in_the_working_directory_is_not_found_unless_path_lists_it(
    tmp_path, monkeypatch
):
    directory, name = planted(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(directory)
    monkeypatch.setenv("PATH", str(elsewhere))
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    with pytest.raises(ValueError, match="not on PATH"):
        command_hook(name)


def test_a_bare_name_is_found_in_the_working_directory_when_path_lists_it(
    tmp_path, monkeypatch
):
    directory, name = planted(tmp_path)
    monkeypatch.chdir(directory)
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path), "."]))
    command_hook(name)  # no error: PATH names the directory


def test_the_first_directory_of_path_that_holds_the_name_wins(tmp_path, monkeypatch):
    first, second = tmp_path / "first", tmp_path / "second"
    names = []
    for directory in (first, second):
        directory.mkdir()
        file = directory / ("tool" + (".exe" if os.name == "nt" else ""))
        file.write_bytes(b"#!/bin/sh\n")
        file.chmod(0o755)
        names.append(file)
    monkeypatch.setenv("PATH", os.pathsep.join([str(first), str(second)]))
    hook = command_hook("tool")
    assert os.path.normcase(hook._path) == os.path.normcase(str(names[0]))  # type: ignore[attr-defined]


@pytest.mark.skipif(sys.platform != "win32", reason="PATHEXT is Windows'")
def test_a_bare_name_takes_the_endings_of_pathext_on_windows(tmp_path, monkeypatch):
    file = tmp_path / "tool.exe"
    file.write_bytes(b"MZ")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("PATHEXT", ".CMD;.EXE")
    assert command_hook("tool")._path.lower() == str(file).lower()  # type: ignore[attr-defined]


@pytest.mark.skipif(sys.platform != "win32", reason="taskkill is Windows'")
def test_taskkill_is_found_under_systemroot_whatever_the_key_case(monkeypatch):
    from pktcap._copy._process import taskkill_path

    monkeypatch.setenv("SystemRoot", r"D:\Elsewhere")
    assert taskkill_path() == os.path.join(r"D:\Elsewhere", "System32", "taskkill.exe")
