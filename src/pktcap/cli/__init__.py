"""The ``pktcap`` command line, built on duho, installed by the ``cli`` extra.

    pktcap convert -i trace.pcap -o trace.jsonl
    pktcap replay -i trace.pcap --to 127.0.0.1:9000 --no-delay
    sudo pktcap capture -i eth0 -o live.pcapng

Importing this package needs neither duho nor the rest of the command line:
the console script is installed either way, and :func:`main` is what reports
the missing extra. ``main`` is the entry point; the command classes
(:class:`Loading`, :class:`Selecting`, :class:`Writing`, :class:`Capture`,
:class:`Convert`, :class:`Replay`, :class:`Plugins`) are the base a library
that has its own protocol subclasses, and are bound on first use.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, List, Optional, Sequence

from .._exceptions import MissingExtraError

if TYPE_CHECKING:
    from ._common import Loading, Selecting
    from ._writing import Writing
    from .capture import Capture
    from .convert import Convert
    from .plugins import Plugins
    from .replay import Replay

__all__ = [
    "main",
    "Loading",
    "Selecting",
    "Writing",
    "Capture",
    "Convert",
    "Replay",
    "Plugins",
]

_NEEDS_EXTRA = (
    "pktcap: error: the command line needs the 'cli' extra: pip install \"pktcap[cli]\""
)


def _bind(name: str) -> Any:
    """The command class ``name``, imported when first asked for."""
    if name in ("Loading", "Selecting"):
        from . import _common

        return getattr(_common, name)
    if name == "Writing":
        from ._writing import Writing

        return Writing
    if name == "Capture":
        from .capture import Capture

        return Capture
    if name == "Convert":
        from .convert import Convert

        return Convert
    if name == "Replay":
        from .replay import Replay

        return Replay
    from .plugins import Plugins

    return Plugins


def __getattr__(name: str) -> Any:
    if name == "main" or name not in __all__:
        raise AttributeError("module %r has no attribute %r" % (__name__, name))
    try:
        import duho  # noqa: F401
    except ImportError:
        raise MissingExtraError(
            "%s needs the 'cli' extra: pip install \"pktcap[cli]\"" % name,
            format="cli",
            extra="cli",
        ) from None
    value = _bind(name)
    globals()[name] = value
    return value


def __dir__() -> List[str]:
    return sorted(set(globals()) | set(__all__))


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the command line and return its exit status.

    ``0`` done, ``1`` the operation failed or the ``cli`` extra is missing,
    ``2`` the invocation was wrong. ``argv`` is the arguments after the
    program name; ``None`` reads ``sys.argv``.
    """
    try:
        import duho  # noqa: F401
    except ImportError:
        print(_NEEDS_EXTRA, file=sys.stderr)
        return 1
    from ._root import execute

    return execute(argv)
