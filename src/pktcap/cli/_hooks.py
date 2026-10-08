"""The hook ``--hook`` names: a program, or a Python ``MODULE:FUNCTION``."""

from __future__ import annotations

import logging
import re
import sys
from typing import Callable, Mapping, Optional

from .._copy import command_hook
from .._copy._limit import FailureLimit
from .._dissect import DissectedFrame
from .._exceptions import CaptureHookError
from .._plugins._load import load_hook

__all__ = ["make_hook"]

_LOG = logging.getLogger(__name__)

#: Two dotted names around one colon. A Windows path (``C:\hook.exe``) and a
#: URL-like name never match: the character after the colon is a name's.
_PYTHON = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z"
)


def _is_drive(spec: str) -> bool:
    """Whether ``spec`` starts with a Windows drive letter and a colon
    (``C:hook.exe``), which is a path there and never ``MODULE:FUNCTION``."""
    return sys.platform == "win32" and len(spec.partition(":")[0]) == 1


class _PythonHook:
    """A Python callable run for each frame, with the failure rules of a
    program's: an exception is counted and logged, and with ``fail_fast`` it
    ends the capture as a :class:`CaptureHookError`."""

    def __init__(self, function: Callable[..., object], fail_fast: bool) -> None:
        self._function = function
        self._fail_fast = fail_fast
        self._limit = FailureLimit()
        self.failures = 0

    def __call__(self, frame: DissectedFrame) -> None:
        try:
            self._function(frame)
        except Exception as exc:
            self.failures += 1
            what = "%s: %s" % (type(exc).__name__, exc)
            if self._limit.due():
                _LOG.error(
                    "the hook function raised (%s)%s",
                    what.encode("unicode_escape").decode("ascii")[:400],
                    self._limit.note(self.failures),
                )
            if self._fail_fast:
                raise CaptureHookError("the hook function raised an exception") from exc


def make_hook(
    spec: str,
    *,
    format: str,
    timeout: float,
    fail_fast: bool,
    names: Optional[Callable[[DissectedFrame], Mapping[str, object]]],
    datagrams: bool,
) -> Callable[[DissectedFrame], object]:
    """The hook ``spec`` names: ``MODULE:FUNCTION`` is imported as written
    (nothing is added to ``sys.path``) and given each frame; anything else is
    a program, run as :func:`command_hook` runs one."""
    if _PYTHON.match(spec) and not _is_drive(spec):
        return _PythonHook(load_hook(spec), fail_fast)
    return command_hook(
        spec,
        format=format,
        timeout=timeout,
        fail_fast=fail_fast,
        names=names,
        datagrams=datagrams,
    )
