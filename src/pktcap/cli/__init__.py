"""The ``pktcap`` command line, built on duho, installed by the ``cli`` extra.

    pktcap convert -i trace.pcap -o trace.jsonl
    pktcap replay -i trace.pcap --to 127.0.0.1:9000 --no-delay
    sudo pktcap capture -i eth0 -o live.pcapng

Importing this package needs neither duho nor the rest of the command line:
the console script is installed either way, and :func:`main` is what reports
the missing extra. It is not part of the library's API.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence

__all__ = ["main"]

_NEEDS_EXTRA = (
    "pktcap: error: the command line needs the 'cli' extra: pip install \"pktcap[cli]\""
)


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
