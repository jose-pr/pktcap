"""Reading a settings file for the root (internal): duho's layout, checked.

``duho.config`` reads the document in whichever format its name says and, with
``_config_validate_ = "strict"``, refuses a key or table nobody has. This module
adds what that leaves to the program: the file found by default is checked
before it is read, a ``config`` key and a ``[pktcap]`` table are answered with
a line of their own, and a top-level ``load`` is the plugin list of every
command that has none of its own.
"""

from __future__ import annotations

import io
import pathlib
from typing import Any, Dict, Mapping

from ._settings import SettingsError, note_read, read_octets

__all__ = ["read_settings"]

#: The key that is the list of every command, written once.
LOAD = "load"


def _shown(text: object) -> str:
    """``text`` as one short quoted line: a key from a file is bounded and its
    control characters escaped."""
    shown = str(text)
    return repr(shown if len(shown) <= 40 else shown[:40] + "...")


class _Document(io.BytesIO):
    """The octets read once, named, for ``duho.config``: the file is opened
    and checked here and not a second time there."""

    def __init__(self, octets: bytes, name: str) -> None:
        super().__init__(octets)
        self.name = name


def _names(cls: Any) -> set:  # type: ignore[type-arg]
    return {builder.name for builder in cls._getargs_()}


def _shaped(data: Any, name: str, root: Any) -> Dict[str, Any]:
    """``data`` with the top-level ``load`` copied into the table of each
    command that takes one and names none. A key nobody has is left for duho's
    strict validation; the two that are answered here are refused."""
    if not isinstance(data, Mapping):
        raise SettingsError(name, None, "the top level must be a table")
    commands = {command._parsername_: command for command in root._subcommands_}
    result: Dict[str, Any] = {}
    for key, value in data.items():
        if key == "config":
            raise SettingsError(name, None, "unknown key %s" % _shown(key))
        if key == root._parsername_ and isinstance(value, Mapping):
            raise SettingsError(
                name,
                None,
                "the table [%s] is not a settings table: write load at the top "
                "level, or in the table of a command" % key,
            )
        result[key] = (
            dict(value) if key in commands and isinstance(value, Mapping) else value
        )
    if LOAD in result:
        everywhere = result.pop(LOAD)
        for key, command in commands.items():
            table = result.get(key, {})
            if LOAD in _names(command) and isinstance(table, dict):
                result[key] = table
                table.setdefault(LOAD, everywhere)
    return result


def read_settings(path: pathlib.Path, source: str, root: Any) -> Dict[str, Any]:
    """The settings ``path`` holds, in the layout duho reads: top-level keys
    for ``root``, a table for each of its commands.

    ``source`` is where duho got the path: ``"default"`` is the user's own
    file, which is checked first (it must be the user's own or root's, and not
    writable by everyone, on POSIX); any other is a file the user named, read
    as it is. The file is read once, at most 65,536 octets.

    :raises SettingsError: a ``config`` key, a ``[pktcap]`` table, or a file
        that is not trusted. A document that is not valid is duho's
        ``ConfigError``, whose message holds the position and never the text;
        both are ``ValueError``.
    """
    from duho.config import backend_for

    octets = read_octets(path, source != "default")
    if octets is None:
        return {}
    backend = backend_for(path)
    note_read(path)
    return _shaped(backend.load(_Document(octets, str(path))), str(path), root)
