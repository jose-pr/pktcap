"""The output formats, by name (internal).

A closed set: the capture formats, which write frames and datagrams, the
record formats, each of which writes one record as text, and ``text``, which
writes a line a person reads. One private module per record format; the
contract they share is :class:`RecordFormat`.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from .._exceptions import UnsupportedFormatError
from ._contract import RecordFormat
from ._ini import INIFormat
from ._json import JSONFormat
from ._toml import TOMLFormat
from ._yaml import YAMLFormat

__all__ = [
    "CAPTURE_FORMATS",
    "OUTPUT_FORMATS",
    "RECORD_FORMATS",
    "RecordFormat",
    "TEXT_FORMAT",
    "dumps_record",
    "has_output_format",
    "infer_format",
    "loads_record",
    "record_format",
]

#: The capture formats, which hold frames and datagrams, and their endings.
CAPTURE_FORMATS: Tuple[str, ...] = ("pcap", "pcapng")
_CAPTURE_SUFFIXES = ((".pcap", "pcap"), (".cap", "pcap"), (".pcapng", "pcapng"))

_RECORD_FORMATS: Dict[str, RecordFormat] = {
    fmt.name: fmt for fmt in (JSONFormat(), YAMLFormat(), TOMLFormat(), INIFormat())
}

#: The formats that write a record as text, by name.
RECORD_FORMATS: Tuple[str, ...] = tuple(_RECORD_FORMATS)
#: The format that writes a line for a person. It is not a record format: it
#: holds no mapping, so it cannot be read back.
TEXT_FORMAT = "text"
_TEXT_SUFFIXES = ((".txt", TEXT_FORMAT), (".log", TEXT_FORMAT))
#: Every format a :class:`CaptureWriter` writes, by name.
OUTPUT_FORMATS: Tuple[str, ...] = CAPTURE_FORMATS + RECORD_FORMATS + (TEXT_FORMAT,)


def _unsupported(name: object, known: Tuple[str, ...]) -> UnsupportedFormatError:
    return UnsupportedFormatError(
        "%r is not an output format; the formats are %s" % (name, ", ".join(known))
    )


def _normalised(name: object, known: Tuple[str, ...]) -> str:
    if not isinstance(name, str):
        raise TypeError("a format is named by text")
    lowered = name.strip().lower()
    if lowered not in known:
        raise _unsupported(name, known)
    return lowered


def record_format(name: str) -> RecordFormat:
    """The record format of that name; ``UnsupportedFormatError`` otherwise."""
    return _RECORD_FORMATS[_normalised(name, RECORD_FORMATS)]


def infer_format(
    target: Union[str, "os.PathLike[str]", object], name: Optional[str]
) -> str:
    """The format to write ``target`` in: the name given, else the one its
    file name ends with. The longest matching ending wins; letter case is
    ignored for both."""
    if name is not None:
        return _normalised(name, OUTPUT_FORMATS)
    if isinstance(target, (str, os.PathLike)):
        text = os.fspath(target).lower()
        endings = list(_CAPTURE_SUFFIXES) + list(_TEXT_SUFFIXES)
        for fmt in _RECORD_FORMATS.values():
            endings += [(suffix, fmt.name) for suffix in fmt.suffixes]
        matches = [
            (len(suffix), found) for suffix, found in endings if text.endswith(suffix)
        ]
        if matches:
            return max(matches)[1]
    raise UnsupportedFormatError(
        "the format cannot be told from the target; name one of %s"
        % ", ".join(OUTPUT_FORMATS)
    )


def has_output_format(name: str) -> bool:
    """Whether the format of that name can be written on this installation.

    ``False`` for a format whose extra is not installed; the name stays in
    :data:`OUTPUT_FORMATS` either way. An unknown name raises
    ``UnsupportedFormatError``.
    """
    lowered = _normalised(name, OUTPUT_FORMATS)
    if lowered in CAPTURE_FORMATS or lowered == TEXT_FORMAT:
        return True
    try:
        _RECORD_FORMATS[lowered].require()
    except ImportError:
        return False
    return True


def dumps_record(record: Mapping[str, Any], format: str = "json") -> str:
    """One record as text in a named format, ending in a newline.

    :param record: a mapping of text keys to plain data: ``dict``, ``list``,
        ``str``, ``int``, ``float``, ``bool``, ``None``.
    :param format: one of :data:`RECORD_FORMATS`.
    :raises UnsupportedFormatError: no record format of that name.
    :raises MissingExtraError: the format's extra is not installed; it is an
        ``ImportError`` and its message names the extra.
    :raises TypeError: ``record`` is not a mapping, or holds a value the
        format cannot represent.
    :raises ValueError: a value the format must refuse, such as a NaN.
    """
    fmt = record_format(format)
    if not isinstance(record, Mapping):
        raise TypeError("a record is a mapping")
    return fmt.dumps(record)


def loads_record(text: str, format: str = "json") -> Dict[str, Any]:
    """The one record ``text`` holds, as written by :func:`dumps_record`.

    :param text: the content (never a file name) of one record.
    :param format: one of :data:`RECORD_FORMATS`.
    :raises UnsupportedFormatError: no record format of that name.
    :raises MissingExtraError: the format cannot be read on this installation
        (``yaml`` without PyYAML; ``toml`` on Python before 3.11 without
        ``tomli``); it is an ``ImportError`` and its message names the extra.
    :raises TypeError: ``text`` is not a ``str``.
    :raises RecordFormatError: ``text`` is not one record in that format. The
        message says what is wrong and where and never quotes the text.
    """
    fmt = record_format(format)
    if not isinstance(text, str):
        raise TypeError("the text of a record is a str")
    return fmt.loads(text)
