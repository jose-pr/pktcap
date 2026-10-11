"""Where the user's settings file is, and reading it safely (internal).

The default file is ``pktcap/pktcap.ini`` under the user's configuration
directory. It is found by this module alone and checked before it is read; a
file the user names (``--config``, ``PKTCAP_CONFIG``) is theirs and is read as
it is. This is the one module of the command line that reads the process
environment, and only when asked, never at import.
"""

from __future__ import annotations

import os
import pathlib
import stat
from typing import Container, Dict, List, Optional, Sequence

__all__ = [
    "SettingsError",
    "check_variable",
    "choose_default",
    "default_path",
    "file_read",
    "forget",
    "is_default",
    "names_a_file",
    "note_read",
    "read_octets",
]

#: The most octets read from a settings file.
MAX_OCTETS = 65536


class SettingsError(ValueError):
    """A settings file cannot be used. The message names the file and never
    holds a line of it.

    :ivar path: the file's path, or ``None`` when the problem is not a file's.
    :ivar lineno: the 1-based line of the problem, or ``None``.
    """

    def __init__(
        self,
        path: Optional[str],
        lineno: Optional[int],
        problem: str,
    ) -> None:
        if path is None:
            message = problem
        elif lineno is None:
            message = "%s: %s" % (path, problem)
        else:
            message = "%s:%d: %s" % (path, lineno, problem)
        super().__init__(message)
        self.path = path
        self.lineno = lineno


def _home() -> Optional[str]:
    home = os.path.expanduser("~")
    return None if home == "~" else home


def default_path() -> Optional[pathlib.Path]:
    """``pktcap/pktcap.ini`` under the user's configuration directory: a
    relative ``APPDATA`` or ``XDG_CONFIG_HOME`` is ignored, so neither can
    point into the working directory. ``None`` where the platform gives no
    home."""
    if os.name == "nt":
        base = os.environ.get("APPDATA", "")
        if not os.path.isabs(base):
            home = _home()
            if home is None:
                return None
            base = os.path.join(home, "AppData", "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME", "")
        if not os.path.isabs(base):
            home = _home()
            if home is None:
                return None
            base = os.path.join(home, ".config")
    return pathlib.Path(base) / "pktcap" / "pktcap.ini"


def read_octets(path: pathlib.Path, named: bool) -> Optional[bytes]:
    """The file's octets, or ``None`` when the default file is absent. The
    file found by default is checked on POSIX: it must be the user's own or
    root's, and not writable by everyone, since a run as root must not take
    its plugin list from another user's file. A file the user named is read
    as it is, and must exist."""
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except (FileNotFoundError, NotADirectoryError):
        if named:
            raise
        return None
    try:
        info = os.fstat(descriptor)
        owner = getattr(os, "geteuid", None)
        if not named and owner is not None:
            if not stat.S_ISREG(info.st_mode):
                raise SettingsError(
                    str(path), None, "not read: it is not a regular file"
                )
            if info.st_uid not in (owner(), 0):
                raise SettingsError(
                    str(path),
                    None,
                    "not read: another user owns it (name it with --config to read it)",
                )
            if info.st_mode & stat.S_IWOTH:
                raise SettingsError(
                    str(path),
                    None,
                    "not read: everyone may write it (name it with --config to read it)",
                )
        chunks: List[bytes] = []
        total = 0
        while total <= MAX_OCTETS:
            chunk = os.read(descriptor, MAX_OCTETS + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    if total > MAX_OCTETS:
        raise SettingsError(str(path), None, "over %d octets" % MAX_OCTETS)
    return b"".join(chunks)


# -- the run -------------------------------------------------------------------

#: What this run set as the root's default file, and the file the root read.
_state: Dict[str, Optional[str]] = {"default": None, "read": None}


def check_variable() -> None:
    """``PKTCAP_CONFIG`` must be an absolute path: a variable outlives the
    directory it was set in."""
    text = os.environ.get("PKTCAP_CONFIG", "").strip()
    if text and not os.path.isabs(text):
        raise SettingsError(
            None,
            None,
            "PKTCAP_CONFIG must be an absolute path: a variable outlives the "
            "directory it was set in",
        )


def names_a_file(tokens: Sequence[str], commands: Container[str]) -> bool:
    """Whether the user names the settings file: ``PKTCAP_CONFIG``, or
    ``-c``/``--config`` (or an abbreviation of it) before the command's name.
    A false answer leaves the user's own file in force, checked."""
    if os.environ.get("PKTCAP_CONFIG", "").strip():
        return True
    for token in tokens:
        if token == "--" or token in commands:
            return False
        if token.startswith("--c") or token.startswith("-c"):
            return True
    return False


def choose_default(tokens: Sequence[str], commands: Container[str]) -> Optional[str]:
    """The user's own file as the root's default for this run, or ``None``: a
    served tree is given no settings file (``PKTCAP_MCP``), and a file the
    user names makes the default moot. Remembered, so the loader knows which
    file to check."""
    _state["read"] = None
    _state["default"] = None
    if os.environ.get("PKTCAP_MCP", "").strip() or names_a_file(tokens, commands):
        return None
    path = default_path()
    if path is not None:
        _state["default"] = str(path)
    return _state["default"]


def forget() -> None:
    """End the run's state: no default file, no file read."""
    _state["default"] = _state["read"] = None


def is_default(path: pathlib.Path) -> bool:
    """Whether ``path`` is the file :func:`choose_default` set."""
    return _state["default"] is not None and str(path) == _state["default"]


def note_read(path: pathlib.Path) -> None:
    _state["read"] = str(path)


def file_read() -> Optional[str]:
    """The settings file the root read in this run, or ``None``."""
    return _state["read"]
