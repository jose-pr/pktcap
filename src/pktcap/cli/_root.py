"""The root parser, and the run around it: exceptions become statuses."""

from __future__ import annotations

import errno
import os
import pathlib
import sys
from typing import Any, Dict, Optional, Sequence

from duho import AUTO, Cli, ConfigArgs, DefaultsFormatter, LoggingArgs
from duho import main as run
from duho.config import user_path

from .._exceptions import MissingExtraError
from ._common import error
from ._loader import read_settings
from ._settings import check_variable, forget
from .capture import Capture
from .convert import Convert
from .plugins import Plugins
from .replay import Replay

__all__ = ["Pktcap", "execute"]


def _settings_of(root: Any, path: pathlib.Path, source: str) -> Dict[str, Any]:
    """The settings file ``--config``, ``PKTCAP_CONFIG`` or the user's own
    names, read for ``root`` (a subclass of :class:`Pktcap` included);
    ``source`` says which."""
    return read_settings(path, source, root)


class Pktcap(ConfigArgs, LoggingArgs, Cli):
    """Capture, replay and convert packet captures (pcap and pcapng), with the protocol plugins you name."""

    _parsername_ = "pktcap"
    _logger_name_ = "pktcap"
    _config_env_ = "PKTCAP_CONFIG"
    _config_ = user_path("pktcap", "pktcap.ini")
    _config_loader_ = classmethod(_settings_of)
    _config_validate_ = "strict"
    _version_ = AUTO
    _distribution_ = "pktcap"
    _help_formatter_ = DefaultsFormatter
    _subcommands_ = [Capture, Replay, Convert, Plugins]


#: Windows reports a pipe closed by its reader as ``EINVAL`` on a write, not as
#: a broken pipe (measured 2026-10-12, Windows 11, Python 3.9 and 3.14).
_WINDOWS = sys.platform == "win32"


def _closed_pipe(exc: OSError, windows: Optional[bool] = None) -> bool:
    """Whether ``exc`` is standard output closed by its reader: a broken pipe,
    or on Windows an ``EINVAL`` while standard output fails again when flushed
    (its data is kept, so the retry fails the same way). An ``EINVAL`` of a
    file or a socket is an error with its line."""
    if isinstance(exc, BrokenPipeError):
        return True
    if not (_WINDOWS if windows is None else windows) or exc.errno != errno.EINVAL:
        return False
    try:
        getattr(sys.stdout, "flush", lambda: None)()
    except (OSError, ValueError):
        return True
    return False


def _silence_stdout() -> None:
    """Nobody reads stdout any more: point it at the null device so the flush
    at exit does not fail again."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def _flushed(status: int) -> int:
    """``status``, after the flush of standard output the interpreter would
    make at exit, where a reader that left is found too: status 1 and no
    line."""
    flush = getattr(sys.stdout, "flush", None)
    if flush is None:
        return status
    try:
        flush()
    except OSError as exc:
        if _closed_pipe(exc):
            _silence_stdout()
        else:
            error(str(exc))
        return 1
    except ValueError:  # standard output is closed: nothing to flush
        pass
    return status


def execute(argv: Optional[Sequence[str]]) -> int:
    """Run the command line and return its exit status.

    ``0`` done, ``1`` the operation failed (a file, a socket, a missing extra,
    a writer's file budget), ``2`` the invocation was wrong (the parser's own
    errors, and a ``ValueError`` from the library: a bad filter, an unknown
    format, a damaged capture), ``130`` interrupted outside ``capture``.
    Standard output closed by the reader is ``1`` with no line.
    """
    return _flushed(_execute(argv))


def _execute(argv: Optional[Sequence[str]]) -> int:
    try:
        check_variable()
        status = run(Pktcap, argv)
    except SystemExit as stop:
        # The parser exits through SystemExit: 0 after --help and --version, 2
        # on a usage error.
        if isinstance(stop.code, int) or stop.code is None:
            return stop.code or 0
        error(str(stop.code))
        return 1
    except KeyboardInterrupt:
        error("interrupted")
        return 130
    except MissingExtraError as exc:
        error(str(exc))
        return 1
    except ValueError as exc:
        error(str(exc))
        return 2
    except OSError as exc:
        # A closed pipe is found again, and silenced, by the flush that follows.
        if not _closed_pipe(exc):
            error(str(exc))
        return 1
    finally:
        forget()
    return 0 if status is None else int(status)
