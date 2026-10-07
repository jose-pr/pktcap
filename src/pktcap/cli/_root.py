"""The root parser, and the run around it: exceptions become statuses."""

from __future__ import annotations

import os
import sys
from typing import Optional, Sequence

from duho import AUTO, Cli, DefaultsFormatter, LoggingArgs
from duho import main as run

from .._exceptions import MissingExtraError
from ._common import error
from .capture import Capture
from .convert import Convert
from .replay import Replay

__all__ = ["Pktcap", "execute"]


class Pktcap(LoggingArgs, Cli):
    """Capture, replay and convert packet captures (pcap and pcapng)."""

    _parsername_ = "pktcap"
    _logger_name_ = "pktcap"
    _version_ = AUTO
    _distribution_ = "pktcap"
    # capture runs until stopped and needs a privilege, and replay puts
    # datagrams on a network: neither is a call a program makes by accident.
    _mcp_ = False
    _help_formatter_ = DefaultsFormatter
    _subcommands_ = [Capture, Replay, Convert]


def _silence_stdout() -> None:
    """Nobody reads stdout any more: point it at the null device so the flush
    at exit does not fail again."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def execute(argv: Optional[Sequence[str]]) -> int:
    """Run the command line and return its exit status.

    ``0`` done, ``1`` the operation failed (a file, a socket, a missing extra,
    a writer's file budget), ``2`` the invocation was wrong (the parser's own
    errors, and a ``ValueError`` from the library: a bad filter, an unknown
    format, a damaged capture), ``130`` interrupted outside ``capture``.
    """
    try:
        status = run(Pktcap, argv)
    except SystemExit as stop:
        # The parser exits through SystemExit: 0 after --help and --version, 2
        # on a usage error.
        if isinstance(stop.code, int) or stop.code is None:
            return stop.code or 0
        error(str(stop.code))
        return 1
    except BrokenPipeError:
        _silence_stdout()
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
        error(str(exc))
        return 1
    return 0 if status is None else int(status)
