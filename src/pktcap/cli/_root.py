"""The root parser, and the run around it: exceptions become statuses."""

from __future__ import annotations

import pathlib
from typing import Any, Dict, Optional, Sequence

from duho import AUTO, Cli, ConfigArgs, DefaultsFormatter, LoggingArgs, run
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


def _report(message: str, code: int) -> None:
    """duho's report of an error a command ends with: one escaped line."""
    error(message)


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
    _errors_ = {MissingExtraError: 1, ValueError: 2, OSError: 1}
    _report_error_ = staticmethod(_report)


def execute(argv: Optional[Sequence[str]]) -> int:
    """Run the command line and return its exit status.

    ``0`` done, ``1`` the operation failed (a file, a socket, a missing extra,
    a writer's file budget), ``2`` the invocation was wrong (the parser's own
    errors, and a ``ValueError`` from the library: a bad filter, an unknown
    format, a damaged capture), ``130`` interrupted outside ``capture``.
    Standard output closed by the reader is ``1`` with no line.
    """
    try:
        check_variable()
    except ValueError as exc:
        error(str(exc))
        return 2
    try:
        return run(Pktcap, argv, exit=False)
    finally:
        forget()
