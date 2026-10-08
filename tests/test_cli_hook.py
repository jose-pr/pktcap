"""``pktcap capture --hook``: a program, or a Python function, run for each record.

The datagrams come from the command's own sockets (``--listen``), so a hook
runs on this host on every platform. A hook is a real program from
``tmp_path``; what it is given and what a failure does are ``command_hook``'s
(``test_hook.py``), and here the command's options are what is tested.
"""

import json
import logging
import time

import pytest

pytest.importorskip("duho")

from duho.mcp import call_tool  # noqa: E402
from hook_programs import python_hook  # noqa: E402
from pktcap.cli import Capture, main  # noqa: E402
from pktcap.cli._root import Pktcap  # noqa: E402
from test_cli_listen import SAFETY, listen_and_send  # noqa: E402

RECORD = r"""
import sys
(HERE / "stdin.txt").write_bytes(sys.stdin.buffer.read())
"""
FAIL = r"""
import sys
sys.stderr.write("the hook did not like it\n")
sys.exit(3)
"""


def run(argv, caplog, payloads=(b"a",), **kwargs):
    argv = ["capture", "--listen", "127.0.0.1:0", *argv] + SAFETY
    return listen_and_send(argv, caplog, list(payloads), **kwargs)


def test_a_program_is_given_the_record_on_standard_input(
    caplog, capsys, tmp_path, monkeypatch
):
    hook = python_hook(monkeypatch, tmp_path, "record", RECORD)
    status, _ = run(["--count", "1", "--hook", hook, "--format", "text"], caplog)
    assert status == 0
    record = json.loads((tmp_path / "stdin.txt").read_text(encoding="ascii"))
    assert [layer["layer"] for layer in record["layers"]] == ["ipv4", "udp"]
    err = capsys.readouterr().err
    assert "hook failures" not in err


def test_a_failed_hook_is_counted_and_the_capture_goes_on(
    caplog, capsys, tmp_path, monkeypatch
):
    hook = python_hook(monkeypatch, tmp_path, "fail", FAIL)
    status, _ = run(["--count", "1", "--hook", hook, "--format", "text"], caplog)
    assert status == 0
    err = capsys.readouterr().err
    assert "1 frames read, 1 written, 1 hook failures" in err
    assert "the hook did not like it" in caplog.text


def test_fail_fast_ends_the_capture_with_status_1_and_one_line(
    caplog, capsys, tmp_path, monkeypatch
):
    hook = python_hook(monkeypatch, tmp_path, "fail", FAIL)
    argv = ["--count", "2", "--hook", hook, "--hook-fail-fast", "--format", "text"]
    status, _ = run(argv, caplog)
    assert status == 1
    err = capsys.readouterr().err
    assert "pktcap: error: hook command" in err and "exit status 3" in err


def test_a_hook_past_its_time_limit_is_killed_and_counted(
    caplog, capsys, tmp_path, monkeypatch
):
    hook = python_hook(monkeypatch, tmp_path, "slow", "import time\ntime.sleep(60)\n")
    started = time.monotonic()
    argv = ["--count", "1", "--hook", hook, "--hook-timeout", "0.5", "--format", "text"]
    status, _ = run(argv, caplog)
    assert status == 0 and time.monotonic() - started < 30
    assert "1 hook failures" in capsys.readouterr().err
    assert "ran past 0.5 seconds" in caplog.text


@pytest.fixture
def hook_module(tmp_path, monkeypatch):
    """A module named ``hookmod`` on ``sys.path`` whose ``keep`` appends the
    summary of each frame it is given to a list the test reads."""
    import importlib
    import sys

    directory = tmp_path / "mods"
    directory.mkdir()
    (directory / "hookmod.py").write_bytes(
        b"import pktcap\nseen = []\n\n"
        b"def keep(frame):\n"
        b"    assert isinstance(frame, pktcap.DissectedFrame)\n"
        b"    seen.append(frame.datagram().payload)\n\n"
        b"def broken(frame):\n"
        b"    raise RuntimeError('no\\x1b[31m')\n"
    )
    monkeypatch.syspath_prepend(str(directory))
    importlib.invalidate_caches()
    yield "hookmod"
    sys.modules.pop("hookmod", None)


def test_a_python_function_is_given_each_frame(caplog, hook_module):
    import sys

    status, _ = run(
        ["--count", "1", "--hook", "hookmod:keep", "--format", "text"],
        caplog,
        payloads=[b"seen by python"],
    )
    assert status == 0
    assert sys.modules["hookmod"].seen == [b"seen by python"]


def test_a_python_function_that_raises_is_counted_and_logged_escaped(
    caplog, capsys, hook_module
):
    run(["--count", "1", "--hook", "hookmod:broken", "--format", "text"], caplog)
    assert "1 hook failures" in capsys.readouterr().err
    messages = [r.getMessage() for r in caplog.records]
    assert any("RuntimeError" in m and "\\x1b" in m for m in messages)
    assert all("\x1b" not in m for m in messages)


def test_fail_fast_ends_the_capture_on_a_python_function_too(
    caplog, capsys, hook_module
):
    argv = ["--count", "2", "--hook", "hookmod:broken", "--hook-fail-fast"]
    status, _ = run(argv + ["--format", "text"], caplog)
    assert status == 1
    assert "hook function raised" in capsys.readouterr().err


def test_a_python_hook_is_found_where_the_interpreter_finds_it_and_nowhere_else(
    tmp_path, monkeypatch, capsys
):
    """The working directory is not added to the module path: a module that
    only the current directory holds is not found."""
    (tmp_path / "localmod.py").write_bytes(b"def keep(frame):\n    pass\n")
    monkeypatch.chdir(tmp_path)
    argv = ["capture", "--listen", "127.0.0.1:0", "--hook", "localmod:keep"]
    assert main(argv) == 2
    err = capsys.readouterr().err
    assert "no module of that name" in err and err.count("\n") == 1


@pytest.mark.parametrize(
    "spec, text",
    [
        ("a" * 300 + ":f", "two dotted Python names"),
        ("hookmod:missing", "no attribute"),
        ("hookmod:seen", "not callable"),
        ("no_such_module_at_all:f", "no module of that name"),
    ],
)
def test_a_python_hook_that_is_not_there_is_status_2_and_one_line(
    spec, text, hook_module, capsys
):
    assert main(["capture", "--listen", "127.0.0.1:0", "--hook", spec]) == 2
    err = capsys.readouterr().err
    assert text in err and err.count("\n") == 1


def test_a_program_that_does_not_exist_is_status_2_before_a_socket_is_bound(
    caplog, capsys
):
    assert main(["capture", "--listen", "127.0.0.1:0", "--hook", "no-such-hook"]) == 2
    assert capsys.readouterr().err.startswith("pktcap: error: ")
    assert "listening on" not in caplog.text


def test_the_hook_options_are_on_capture_alone():
    from pktcap.cli import Convert, Replay

    for command in (Convert, Replay):
        flags = {o for a in command._parser_()._actions for o in a.option_strings}
        assert not flags & {"--hook", "--hook-fail-fast", "--hook-timeout"}


class Served(Capture):
    """A subclass that offers capture as a tool: it is a program, and the
    tool's input may come from text a capture held."""

    _parsername_ = "capture"
    _mcp_ = True


class ServedRoot(Pktcap):
    _parsername_ = "pktcap"
    _subcommands_ = [Served]


def test_a_tool_call_cannot_name_a_hook(tmp_path):
    marker = tmp_path / "ran"
    result = call_tool(
        ServedRoot,
        "pktcap.capture",
        {"listen": ["127.0.0.1:0"], "count": 1, "hook": str(marker)},
    )
    assert result["isError"] is True
    assert "cannot name a hook" in result["content"][0]["text"]
    assert not marker.exists()


def test_logging_is_quiet_without_dash_v(caplog):
    caplog.set_level(logging.WARNING)
    assert [r for r in caplog.records if "listening" in r.getMessage()] == []
