"""Every exception the package raises on its own account (internal).

:class:`PktcapError` is the one base: a caller who wants "anything pktcap
reported" catches it. Each class also inherits the builtin a caller would
already catch for that kind of failure, so existing ``except`` clauses keep
working.

A caller's own mistake, such as a bad option or a wrong argument type, is not
here: it raises plain :class:`ValueError` or :class:`TypeError`.

Re-exported from :mod:`pktcap`.
"""

from __future__ import annotations

__all__ = ["PktcapError"]


class PktcapError(Exception):
    """The base of every exception pktcap raises on its own account."""
