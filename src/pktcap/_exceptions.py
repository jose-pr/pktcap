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

from typing import Optional

__all__ = ["PktcapError", "CaptureFormatError", "CaptureFilterError"]


class PktcapError(Exception):
    """The base of every exception pktcap raises on its own account."""


class CaptureFormatError(PktcapError, ValueError):
    """The input is not a pcap or pcapng capture, or it is a damaged one.

    The one type every malformed container raises: a wrong magic number, a
    record or block cut short, a length over its ceiling, a block that
    contradicts itself. The message never quotes the file.

    :ivar offset: how many octets of the input had been read when the problem
        was found, or ``None`` when that is not known.
    """

    def __init__(self, message: str, *, offset: Optional[int] = None) -> None:
        if offset is not None:
            message = "%s (at octet %d)" % (message, offset)
        super().__init__(message)
        self.offset = offset


class CaptureFilterError(PktcapError, ValueError):
    """A capture-filter expression that cannot be compiled.

    Raised when the filter is parsed or compiled, never while it is applied:
    a clause that is not ``key=value``, an ``or``, or a key or value that the
    protocol library's own builder refused (its ``ValueError`` is chained).
    """
