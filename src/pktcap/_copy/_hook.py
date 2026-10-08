"""A hook that runs a program for each captured item (internal).

The program gets the record on standard input and the values a caller chose in
a copy of the environment; nothing a sender wrote is an argument, a variable
name or reaches a shell. Every run is bounded, and when it runs past the bound
the program and the processes it started are killed.
"""

from __future__ import annotations

import logging
import math
import re
from typing import Callable, Dict, Mapping, Optional

from .._dissect import DissectedFrame
from .._exceptions import CaptureHookError
from .._formats import RecordFormat, record_format
from .._filenames import safe
from .._plugins._config import process_environment
from .._records import datagram_record, frame_record
from ._find import brief, find_program
from ._limit import FailureLimit
from ._process import run_program

__all__ = ["command_hook"]

_LOG = logging.getLogger(__name__)

#: What every variable the hook adds to the environment starts with.
_PREFIX = "PKTCAP_HOOK_"
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


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
        self._limit = FailureLimit()
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
                    % brief(str(key), 40)
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
        outcome = run_program(self._path, payload, env, self._timeout)
        _LOG.debug("hook command wrote %d octets to standard error", outcome.written)
        if outcome.status == 0:
            return
        self.failures += 1
        if outcome.error is not None:
            what = "could not be started (%s)" % outcome.error
        elif outcome.timed_out:
            what = "ran past %g seconds and was killed" % self._timeout
        else:
            what = "failed with exit status %s: %s" % (
                outcome.status,
                brief(outcome.tail.strip()),
            )
        if self._limit.due():
            _LOG.error(
                "hook command %s %s%s",
                self._path,
                what,
                self._limit.note(self.failures),
            )
        if self._fail_fast:
            raise CaptureHookError(
                "hook command %s %s" % (self._path, what),
                status=outcome.status,
                timed_out=outcome.timed_out,
            )


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
    path = find_program(command)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number of seconds")
    if not (math.isfinite(timeout) and timeout > 0):
        raise ValueError("timeout must be above 0 seconds and finite")
    if names is not None and not callable(names):
        raise TypeError("names must be callable")
    record = record_format(format)
    record.require()
    return _CommandHook(path, record, float(timeout), bool(fail_fast), names, datagrams)
