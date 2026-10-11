"""The root parser, and the run around it: exceptions become statuses."""

from __future__ import annotations

import os
import pathlib
import sys
from typing import Any, Dict, Optional, Sequence

from duho import AUTO, Cli, ConfigArgs, DefaultsFormatter, LoggingArgs
from duho import main as run

from .._exceptions import MissingExtraError
from ._common import error
from ._loader import read_settings
from ._settings import check_variable, choose_default, forget
from .capture import Capture
from .convert import Convert
from .plugins import Plugins
from .replay import Replay

__all__ = ["Pktcap", "execute"]


def _settings_of(path: pathlib.Path) -> Dict[str, Any]:
    """The settings file ``--config``, ``PKTCAP_CONFIG`` or the user's own
    names, read for :class:`Pktcap`."""
    return read_settings(path, Pktcap) or {}


class Pktcap(ConfigArgs, LoggingArgs, Cli):  # type: ignore[misc]
    """Capture, replay and convert packet captures (pcap and pcapng), with the protocol plugins you name."""

    _parsername_ = "pktcap"
    _logger_name_ = "pktcap"
    _config_env_ = "PKTCAP_CONFIG"
    _config_loader_ = staticmethod(_settings_of)
    _version_ = AUTO
    _distribution_ = "pktcap"
    _help_formatter_ = DefaultsFormatter
    _subcommands_ = [Capture, Replay, Convert, Plugins]


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
    tokens = list(sys.argv[1:] if argv is None else argv)
    try:
        check_variable()
        # The user's own file is the default for this run, and only for it.
        Pktcap._config_ = choose_default(
            tokens, {command._parsername_ for command in Pktcap._subcommands_}
        )
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
    finally:
        Pktcap._config_ = None
        forget()
    return 0 if status is None else int(status)
