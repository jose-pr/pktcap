"""What every record format provides (internal).

A record is plain data a protocol library made from one of its messages: a
mapping of text keys to ``dict``, ``list``, ``str``, ``int``, ``float``,
``bool`` and ``None`` values. A format turns one record into text.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

from .._exceptions import MissingExtraError

__all__ = ["RecordFormat", "missing_extra"]


def missing_extra(format: str, extra: str, use: str = "output") -> MissingExtraError:
    """The error for a format whose optional dependency is not installed;
    ``use`` is ``"output"`` for writing it and ``"input"`` for reading it."""
    return MissingExtraError(
        '%s %s needs the %r extra: pip install "pktcap[%s]"'
        % (format.upper(), use, extra, extra),
        format=format,
        extra=extra,
    )


class RecordFormat:
    """One way of writing a record as text, and of reading one back.

    A subclass sets :attr:`name` and :attr:`suffixes` and implements
    :meth:`dumps` and :meth:`loads`. It overrides :meth:`require` and
    :meth:`require_loads` when it needs a library that an extra installs, and
    :attr:`separator` and :attr:`streamable` when a file of several records
    needs something between them or cannot exist.
    """

    #: The name a caller selects the format by: lower case, stable.
    name: str = ""
    #: File-name endings that select the format, lower case, with the dot.
    suffixes: Tuple[str, ...] = ()
    #: The extra that installs what the format needs, or ``None``.
    extra: Optional[str] = None
    #: Whether one file can hold several records.
    streamable: bool = True
    #: What precedes each record in a file of several.
    separator: str = ""

    def require(self) -> None:
        """Raise ``MissingExtraError`` when the format cannot be
        used on this installation. The default needs nothing."""

    def require_loads(self) -> None:
        """Raise ``MissingExtraError`` when the format cannot be read on this
        installation. The default needs nothing."""

    def dumps(self, record: Mapping[str, Any]) -> str:
        """``record`` as text, ending in a newline.

        Raises ``TypeError`` for a value the format cannot represent and
        ``ValueError`` for one it must refuse; the message never quotes the
        record. An exception of the library that does the writing is
        translated to one of the two.
        """
        raise NotImplementedError

    def loads(self, text: str) -> Dict[str, Any]:
        """The one record ``text`` holds: the inverse of :meth:`dumps`.

        Raises ``RecordFormatError`` for text that is not one record; the
        message never quotes the text, and no exception of the library that
        does the reading is chained.
        """
        raise NotImplementedError
