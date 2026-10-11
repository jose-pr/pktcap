"""Where the user's settings file is, and reading it safely (internal).

The default file is ``pktcap/pktcap.ini`` under the user's configuration
directory. It is found by this module alone and checked before it is read; a
file the user names (``--config``, ``PKTCAP_CONFIG``) is theirs and is read as
it is. This and :mod:`._legacy` are the modules of the command line that read
the process environment, and only when asked, never at import.
"""

from __future__ import annotations

import os
import pathlib
import stat
from typing import List, Optional

__all__ = ["SettingsError", "default_path", "read_octets"]

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
