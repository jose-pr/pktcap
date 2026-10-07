"""The command line as a whole: the entry points, the statuses, the missing extra.

Every test parses a real argument vector through the real parser, in process
or as a process; ``--help`` is not a check. The commands themselves are in
``test_cli_convert.py``, ``test_cli_replay.py`` and ``test_cli_capture.py``.
"""

import re
import subprocess
import sys

import pytest

pytest.importorskip("duho")

import pktcap  # noqa: E402
from pktcap.cli import main  # noqa: E402

HINT = (
    "pktcap: error: the command line needs the 'cli' extra: pip install \"pktcap[cli]\""
)


def _without_duho(body):
    """Run ``body`` in an interpreter where importing duho fails."""
    code = "import sys\nsys.modules['duho'] = None\n" + body
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )


def test_python_dash_m_prints_the_version():
    done = subprocess.run(
        [sys.executable, "-m", "pktcap", "--version"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0
    assert done.stdout.strip() == "pktcap %s" % pktcap.__version__
    assert re.fullmatch(r"pktcap \d+\.\d+\.\d+", done.stdout.strip())


def test_main_returns_the_status_and_never_exits(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == "pktcap " + pktcap.__version__


def test_importing_pktcap_loads_neither_duho_nor_the_command_line():
    done = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, pktcap; "
            "print('duho' in sys.modules, 'pktcap.cli' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.stdout.strip() == "False False", done.stderr


def test_the_command_package_imports_without_duho():
    done = _without_duho("import pktcap.cli\nprint(pktcap.cli.main.__name__)\n")
    assert done.returncode == 0 and done.stdout.strip() == "main", done.stderr


def test_without_duho_main_says_which_extra_in_one_line_and_returns_1():
    done = _without_duho(
        "from pktcap.cli import main\nprint('status', main(['--help']))\n"
    )
    assert done.stdout.strip() == "status 1"
    assert done.stderr.strip() == HINT
    assert "Traceback" not in done.stderr


def test_without_duho_python_dash_m_and_the_console_script_say_the_same():
    done = _without_duho(
        "import runpy\nrunpy.run_module('pktcap', run_name='__main__')\n"
    )
    assert done.returncode == 1 and done.stderr.strip() == HINT
    entry = _without_duho(
        "from importlib.metadata import entry_points\n"
        "found = entry_points()\n"
        "scripts = found.select(group='console_scripts') if hasattr(found, 'select')"
        " else found['console_scripts']\n"
        "(script,) = [e for e in scripts if e.name == 'pktcap']\n"
        "raise SystemExit(script.load()([]))\n"
    )
    assert entry.returncode == 1 and entry.stderr.strip() == HINT


def test_the_console_script_is_the_command_package_main():
    from importlib.metadata import entry_points

    found = entry_points()
    scripts = (
        found.select(group="console_scripts")
        if hasattr(found, "select")
        else found["console_scripts"]
    )
    assert {e.name: e.value for e in scripts if e.name == "pktcap"} == {
        "pktcap": "pktcap.cli:main"
    }


@pytest.mark.parametrize(
    "argv",
    [
        ["--bogus"],
        ["convert", "--bogus", "-i", "x"],
        ["convert"],
        ["replay", "-i", "x"],
        ["capture", "--count", "many"],
    ],
    ids=[
        "unknown-root-option",
        "unknown-option",
        "no-input",
        "no-destination",
        "bad-int",
    ],
)
def test_a_wrong_invocation_is_status_2_and_says_so(argv, capsys):
    assert main(argv) == 2
    assert "pktcap" in capsys.readouterr().err


def test_no_command_is_a_usage_error(capsys):
    assert main([]) == 2
    assert "required" in capsys.readouterr().err


def test_every_filter_key_is_in_the_help_of_the_option(capsys):
    """The help names the keys by hand; this keeps it the library's list."""
    from pktcap.cli._common import Base

    parser = Base._parser_()
    text = parser.format_help()
    assert all(key in text for key in pktcap.FRAME_FILTER_KEYS)


def test_an_exception_of_the_library_is_a_status_and_one_line(capsys, tmp_path):
    missing = tmp_path / "missing.pcap"
    assert main(["convert", "-i", str(missing), "-o", str(tmp_path / "o.json")]) == 1
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and err[0].startswith("pktcap: error: ")
    assert main(["convert", "-i", str(missing), "-f", "colour=red"]) == 2
    assert "colour" in capsys.readouterr().err


def test_a_closed_standard_output_is_a_status_and_no_traceback(monkeypatch, capsys):
    from pktcap.cli import _root

    def broken(cls, argv):
        raise BrokenPipeError()

    monkeypatch.setattr(_root, "run", broken)
    monkeypatch.setattr(_root, "_silence_stdout", lambda: None)
    assert _root.execute([]) == 1
    assert capsys.readouterr().err == ""
