"""A hook that runs a program for each captured item (internal).

The program gets the record on standard input and the values a caller chose in
a copy of the environment; nothing a sender wrote is an argument, a variable
name or reaches a shell. Every run is bounded, and when it runs past the bound
the program and the processes it started are killed.
"""

from __future__ import annotations

import logging
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Callable, Dict, Mapping, Optional, Tuple

from .._dissect import DissectedFrame
from .._exceptions import CaptureHookError
from .._formats import RecordFormat, record_format
from .._filenames import safe
from .._plugins._config import process_environment
from .._records import datagram_record, frame_record

__all__ = ["command_hook"]

_LOG = logging.getLogger(__name__)

#: What every variable the hook adds to the environment starts with.
_PREFIX = "PKTCAP_HOOK_"
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
#: Seconds to wait for a killed program's pipes to drain.
_REAP_SECONDS = 5.0
#: Characters of a failed program's standard error that an error or a log line
#: carries.
_STDERR_CHARS = 400
#: Seconds between two log lines about failures: a sender that makes the hook
#: fail must not choose how much is logged.
_LOG_INTERVAL = 60.0
#: Windows runs these through ``cmd.exe``, which reads its command line again.
_BATCH = (".bat", ".cmd")


def _brief(text: str, limit: int = _STDERR_CHARS) -> str:
    """Text a program wrote, made safe to log and to put in an error: escaped
    to printable ASCII, and cut at ``limit`` characters."""
    escaped = text.encode("unicode_escape", "backslashreplace").decode("ascii")
    if len(escaped) <= limit:
        return escaped
    return "...%s" % escaped[-limit:]


def _resolve(command: str) -> str:
    """The absolute path of a hook command, found once, when it is made.

    A name with a directory part (``./hook``, ``/usr/bin/hook``, ``sub/hook``)
    is that file, taken from the working directory as it is when the hook is made; a name with
    none is looked up on ``PATH``, as a shell would. Running the absolute path
    means ``./hook`` is never handed to the system as the bare ``hook``, which
    POSIX searches on ``PATH`` alone, and a later change of directory changes
    nothing.
    """
    if not isinstance(command, str):
        raise TypeError("command must be text")
    if not command or "\x00" in command:
        raise ValueError("command must be a program name or path")
    if "/" in command or "\\" in command:
        path = os.path.abspath(command)
        if not os.path.exists(path):
            raise ValueError("hook command does not exist: %s" % _brief(command))
    else:
        found = shutil.which(command)
        if found is None:
            raise ValueError(
                "hook command %s is not on PATH; a file in the working directory "
                "is named with a path, ./%s" % (_brief(command), _brief(command))
            )
        path = os.path.abspath(found)
    if not os.path.isfile(path):
        raise ValueError("hook command is not a file: %s" % _brief(command))
    if os.name == "posix" and not os.access(path, os.X_OK):
        raise ValueError("hook command is not executable: %s" % _brief(command))
    if sys.platform == "win32" and path.lower().endswith(_BATCH):
        raise ValueError(
            "hook command is a batch file, which cmd.exe runs by reading its "
            "command line again: name a program (.exe) instead"
        )
    return path


def _kill_tree(process: "subprocess.Popen[bytes]") -> None:
    """Kill ``process`` and everything it started."""
    if sys.platform == "win32":
        root = process_environment().get("SystemRoot", r"C:\Windows")
        taskkill = os.path.join(root, "System32", "taskkill.exe")
        try:
            subprocess.run(
                [taskkill, "/F", "/T", "/PID", str(process.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_REAP_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            # The program leads its own session (see _run), so its group is
            # exactly the tree to kill.
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        process.kill()
    except OSError:
        pass


def _run(
    path: str, payload: bytes, env: Mapping[str, str], timeout: float
) -> Tuple[Optional[int], str, str]:
    """Run ``path`` with ``payload`` on standard input: its status (``None``
    when it was killed for running past ``timeout``) and both streams.

    An argument list with no argument, never a shell. The streams are decoded
    as UTF-8 with ``errors="replace"``, whatever the platform's encoding is.
    """
    # sys.platform is tested here, not through a variable, so a type checker
    # narrows each branch to the platform that has the option.
    if sys.platform == "win32":
        process = subprocess.Popen(
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    else:
        process = subprocess.Popen(
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            start_new_session=True,
        )
    try:
        out, err = process.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        try:
            out, err = process.communicate(timeout=_REAP_SECONDS)
        except subprocess.TimeoutExpired:  # a pipe a grandchild still holds
            out = err = b""
        return None, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    except BaseException:
        _kill_tree(process)
        process.wait()
        raise
    return (
        process.returncode,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
    )


class _CommandHook:
    """What :func:`command_hook` returns: a callable that runs the program for
    one frame. ``failures`` counts the runs that failed or timed out."""

    def __init__(
        self,
        path: str,
        record: RecordFormat,
        timeout: float,
        fail_fast: bool,
        names: Optional[Callable[[DissectedFrame], Mapping[str, object]]],
        datagrams: bool,
    ) -> None:
        self._path = path
        self._timeout = timeout
        self._fail_fast = fail_fast
        self._names = names
        self._datagrams = datagrams
        self._record = record
        self._name = record.name
        self._last_logged: Optional[float] = None
        self.failures = 0

    def _text(self, frame: DissectedFrame) -> bytes:
        if self._datagrams:
            datagram = frame.datagram()
            if datagram is None:
                raise ValueError("the frame carries no UDP datagram to hand over")
            record = datagram_record(datagram)
        else:
            record = frame_record(frame)
        return self._record.dumps(record).encode("utf-8")

    def _environment(self, frame: DissectedFrame) -> Dict[str, str]:
        env = process_environment()
        env[_PREFIX + "FORMAT"] = self._name
        if self._names is None:
            return env
        values = self._names(frame)
        if not isinstance(values, Mapping):
            raise TypeError("names must give a mapping")
        added: Dict[str, str] = {}
        for key, value in values.items():
            if not isinstance(key, str) or not _FIELD_NAME.match(key):
                raise ValueError(
                    "a field name is letters, digits and underscores, not %s"
                    % _brief(str(key), 40)
                )
            variable = _PREFIX + key.upper()
            if variable == _PREFIX + "FORMAT" or variable in added:
                raise ValueError("the variable %s is set twice" % variable)
            added[variable] = safe(value)
        env.update(added)
        return env

    def __call__(self, frame: DissectedFrame) -> None:
        if not isinstance(frame, DissectedFrame):
            raise TypeError("a hook is given a DissectedFrame")
        payload = self._text(frame)
        env = self._environment(frame)
        status, out, err = _run(self._path, payload, env, self._timeout)
        _LOG.debug(
            "hook command wrote %d characters to stdout and %d to stderr",
            len(out),
            len(err),
        )
        if status == 0:
            return
        self.failures += 1
        timed_out = status is None
        tail = _brief(err.strip())
        if timed_out:
            what = "ran past %g seconds and was killed" % self._timeout
        else:
            what = "failed with exit status %s: %s" % (status, tail)
        self._log(what)
        if self._fail_fast:
            raise CaptureHookError(
                "hook command %s %s" % (self._path, what),
                status=status,
                timed_out=timed_out,
            )

    def _log(self, what: str) -> None:
        """One line about a failure: the first, then at most one every
        ``_LOG_INTERVAL`` seconds with the running count."""
        moment = time.monotonic()
        last = self._last_logged
        if last is not None and moment - last < _LOG_INTERVAL:
            return
        self._last_logged = moment
        note = ""
        if self.failures > 1:
            note = " [%d failures so far; at most one line per %g s]" % (
                self.failures,
                _LOG_INTERVAL,
            )
        _LOG.error("hook command %s %s%s", self._path, what, note)


def command_hook(
    command: str,
    *,
    format: str = "json",
    timeout: float = 10.0,
    fail_fast: bool = False,
    names: Optional[Callable[[DissectedFrame], Mapping[str, object]]] = None,
    datagrams: bool = False,
) -> Callable[[DissectedFrame], None]:
    """A hook that runs a program for each frame it is given.

    Pass it to :func:`copy_frames` as ``each``. The program is found once,
    here, as an absolute path: a name with a directory part is that file from
    the working directory then, a bare name is looked up on ``PATH``. It is
    started with no argument and no shell, in its own process group, with the
    record of the frame (:func:`frame_record`, or :func:`datagram_record` of
    its datagram with ``datagrams``) on standard input in ``format``, a copy of
    the environment, ``PKTCAP_HOOK_FORMAT`` and one ``PKTCAP_HOOK_<FIELD>``
    for each item ``names(frame)`` gives. A value passes the same rule as a
    field of a file name: no separator, no control character, at most 64
    characters. A field name is the caller's code: letters, digits and
    underscores.

    Past ``timeout`` seconds the program and everything it started are killed.
    A run that exits with a non-zero status or is killed is a failure: it is
    counted in the ``failures`` attribute of the returned callable and logged
    on ``pktcap._copy._hook`` at ``ERROR`` with a bounded, escaped tail of the error
    output, the first one and then at most one a minute. With ``fail_fast``
    the first failure raises :class:`CaptureHookError` and so ends a copy.

    :param command: a program name or path.
    :param format: the record format of standard input, one of
        :data:`RECORD_FORMATS`.
    :param timeout: seconds one run may take, positive and finite.
    :param names: fields for the environment, as for :func:`copy_frames`.
    :param datagrams: hand over the record of the frame's datagram.
    :raises ValueError: at the call, a command that does not exist, is not a
        file, is not executable, is a batch file on Windows or is empty; a
        ``timeout`` that is not positive and finite. On a call of the hook, a
        field name that is not a plain identifier or is set twice, or a frame
        with no datagram when ``datagrams`` is set.
    :raises TypeError: a ``command`` that is not text or a ``timeout`` that is
        not a number.
    :raises UnsupportedFormatError: ``format`` is no record format.
    :raises MissingExtraError: the format's extra is not installed.
    """
    path = _resolve(command)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number of seconds")
    if not (math.isfinite(timeout) and timeout > 0):
        raise ValueError("timeout must be above 0 seconds and finite")
    if names is not None and not callable(names):
        raise TypeError("names must be callable")
    record = record_format(format)
    record.require()
    return _CommandHook(path, record, float(timeout), bool(fail_fast), names, datagrams)
