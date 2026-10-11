"""Reading a settings file for the root (internal): duho's layout, checked.

``duho.config`` reads the document in whichever format its name says; this
module adds what that reader leaves to the program: the default file is checked
before it is read, an unknown key or table is refused, and a top-level ``load``
is the plugin list of every command that has none of its own.
"""

from __future__ import annotations

import io
import pathlib
from typing import Any, Dict, Mapping, Optional

from ._settings import SettingsError, is_default, note_read, read_octets

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


def _checked(data: Any, name: str, root: Any) -> Dict[str, Any]:
    """``data`` with every key known to the root or one of its commands, and
    the top-level ``load`` copied into the table of each command that takes
    one and names none."""
    if not isinstance(data, Mapping):
        raise SettingsError(name, None, "the top level must be a table")
    commands = {command._parsername_: command for command in root._subcommands_}
    known = _names(root) - {"config"}
    result: Dict[str, Any] = {}
    for key, value in data.items():
        if key in commands:
            if not isinstance(value, Mapping):
                raise SettingsError(name, None, "%s must be a table" % _shown(key))
            unknown = [k for k in value if k not in _names(commands[key])]
            if unknown:
                raise SettingsError(
                    name,
                    None,
                    "unknown key %s in [%s]" % (_shown(unknown[0]), key),
                )
            result[key] = dict(value)
        elif key == root._parsername_ and isinstance(value, Mapping):
            raise SettingsError(
                name,
                None,
                "the table [%s] is not a settings table: write load at the top "
                "level, or in the table of a command" % key,
            )
        elif key in known or key == LOAD:
            result[key] = value
        else:
            kind = "table" if isinstance(value, Mapping) else "key"
            raise SettingsError(name, None, "unknown %s %s" % (kind, _shown(key)))
    if LOAD in result:
        everywhere = result.pop(LOAD)
        for key, command in commands.items():
            if LOAD in _names(command):
                result.setdefault(key, {}).setdefault(LOAD, everywhere)
    return result


def read_settings(path: pathlib.Path, root: Any) -> Optional[Dict[str, Any]]:
    """The settings ``path`` holds, in the layout duho reads: top-level keys
    for ``root``, a table for each of its commands.

    The file is read once, at most 65,536 octets. The file this run found by
    default is checked first (it must be the user's own or root's, and not
    writable by everyone, on POSIX); a file named is read as it is.

    :raises SettingsError: a key or table nobody has, or a file that is not
        trusted. A document that is not valid is duho's ``ConfigError``, whose
        message holds the position and never the text; both are ``ValueError``.
    """
    from duho.config import backend_for

    octets = read_octets(path, not is_default(path))
    if octets is None:
        return {}
    backend = backend_for(path)
    note_read(path)
    return _checked(backend.load(_Document(octets, str(path))), str(path), root)
