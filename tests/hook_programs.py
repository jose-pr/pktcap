"""Real programs to run as hook commands, and a way to tell whether a process
lives. Nothing here replaces ``subprocess``.

A hook is a file the system starts by path with no argument. On POSIX that is
a ``#!/bin/sh`` launcher that runs a Python script from the same directory. On
Windows a ``.cmd`` file is refused as a hook, and there is no launcher to make
that a script can be started by path alone, so the program is this
interpreter itself: with no argument it would read its script from standard
input, so a ``sitecustomize`` module (found through ``PYTHONPATH``) runs the
test's script first and exits. Both give the script its own directory as
``HERE``, a ``pathlib.Path``, so it can leave files where the test looks.
"""

import ctypes
import os
import pathlib
import subprocess
import sys
import textwrap
import time

_SITECUSTOMIZE = """\
import os
import runpy
import sys

_script = os.environ.pop("PKTCAP_TEST_HOOK_SCRIPT", None)
# Started with no arguments and nothing else: not a child of the script's.
if _script and sys.argv in ([""], []):
    try:
        runpy.run_path(_script, run_name="__main__")
        _code = 0
    except SystemExit as _stop:
        _code = _stop.code if isinstance(_stop.code, int) else int(bool(_stop.code))
    except BaseException:
        import traceback

        traceback.print_exc()
        _code = 1
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_code)
"""


def python_hook(monkeypatch, directory: pathlib.Path, name: str, source: str) -> str:
    """A hook program that runs ``source``; the command that starts it.

    One program at a time on Windows, where the script is named through the
    environment the test's ``monkeypatch`` sets for the hook to inherit.
    """
    script = directory / (name + ".py")
    script.write_bytes(
        (
            "import pathlib\nHERE = pathlib.Path(__file__).resolve().parent\n"
            + textwrap.dedent(source)
        ).encode("utf-8")
    )
    if os.name == "nt":
        site = directory / ("site-" + name)
        site.mkdir()
        (site / "sitecustomize.py").write_bytes(_SITECUSTOMIZE.encode("utf-8"))
        monkeypatch.setenv("PYTHONPATH", str(site))
        monkeypatch.setenv("PKTCAP_TEST_HOOK_SCRIPT", str(script))
        return sys.executable
    launcher = directory / name
    launcher.write_bytes(
        ('#!/bin/sh\nexec "%s" "%s"\n' % (sys.executable, script)).encode("utf-8")
    )
    launcher.chmod(0o755)
    return str(launcher)


def alive(pid: int) -> bool:
    """Whether the process ``pid`` is running (a zombie is not)."""
    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    state = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True
    ).stdout.strip()
    return bool(state) and not state.startswith("Z")


def wait_until_dead(pid: int, seconds: float = 15.0) -> bool:
    """Whether ``pid`` ended within ``seconds``."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.1)
    return not alive(pid)


def kill(pid: int) -> None:
    """End ``pid`` and its children, a test's last resort."""
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, check=False
        )
    else:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
