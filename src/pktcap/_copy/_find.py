"""Finding the program a hook runs, once (internal)."""

from __future__ import annotations

import os
import sys
from typing import List, Optional

from .._plugins._config import process_environment

__all__ = ["brief", "find_program"]

#: Characters of a program's text that an error or a log line carries.
STDERR_CHARS = 400
#: Windows runs these through ``cmd.exe``, which reads its command line again.
_BATCH = (".bat", ".cmd")
#: The endings Windows tries on a bare name when ``PATHEXT`` is not set.
_PATHEXT = ".COM;.EXE;.BAT;.CMD"


def brief(text: str, limit: int = STDERR_CHARS) -> str:
    """Text a program wrote, made safe to log and to put in an error: escaped
    to printable ASCII, and cut at ``limit`` characters."""
    escaped = text.encode("unicode_escape", "backslashreplace").decode("ascii")
    if len(escaped) <= limit:
        return escaped
    return "...%s" % escaped[-limit:]


def _on_path(name: str) -> Optional[str]:
    """``name`` in the directories ``PATH`` lists, in order, and nowhere else:
    the working directory only when ``PATH`` lists it. On Windows the endings
    of ``PATHEXT`` are tried, as the system does."""
    env = process_environment()
    names: List[str] = [name]
    if sys.platform == "win32":
        endings = [e for e in env.get("PATHEXT", _PATHEXT).split(";") if e]
        if not any(name.lower().endswith(e.lower()) for e in endings):
            names = [name + e for e in endings]
    for directory in env.get("PATH", "").split(os.pathsep):
        directory = directory.strip('"')
        if not directory:
            continue
        for candidate in names:
            path = os.path.join(directory, candidate)
            if os.path.isfile(path) and (
                sys.platform == "win32" or os.access(path, os.X_OK)
            ):
                return os.path.abspath(path)
    return None


def find_program(command: str) -> str:
    """The absolute path of a hook command, found once, when it is made.

    A name with a directory part (``./hook``, ``/usr/bin/hook``, ``sub/hook``)
    or a drive (``C:hook.exe``) is that file, taken from the working directory
    as it is when the hook is made; a name with none is looked up on ``PATH``,
    as a shell would. Running the absolute path means ``./hook`` is never
    handed to the system as the bare ``hook``, which POSIX searches on ``PATH``
    alone, and a later change of directory changes nothing.
    """
    if not isinstance(command, str):
        raise TypeError("command must be text")
    if not command or "\x00" in command:
        raise ValueError("command must be a program name or path")
    if "/" in command or "\\" in command or os.path.splitdrive(command)[0]:
        path = os.path.abspath(command)
        if not os.path.exists(path):
            raise ValueError("hook command does not exist: %s" % brief(command))
    else:
        found = _on_path(command)
        if found is None:
            raise ValueError(
                "hook command %s is not on PATH; a file in the working directory "
                "is named with a path, ./%s" % (brief(command), brief(command))
            )
        path = found
    if not os.path.isfile(path):
        raise ValueError("hook command is not a file: %s" % brief(command))
    if os.name == "posix" and not os.access(path, os.X_OK):
        raise ValueError("hook command is not executable: %s" % brief(command))
    if sys.platform == "win32" and path.lower().endswith(_BATCH):
        raise ValueError(
            "hook command is a batch file, which cmd.exe runs by reading its "
            "command line again: name a program (.exe) instead"
        )
    return path
