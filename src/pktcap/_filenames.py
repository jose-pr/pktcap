"""File names from what a capture holds (internal).

A value a peer chose becomes part of a path only through :func:`safe`; the
pattern a caller writes is checked by :func:`pattern_fields`.
"""

from __future__ import annotations

import datetime
import hashlib
import math
import os
import re
import string
from typing import FrozenSet, Set

__all__ = [
    "BUILT_IN_FIELDS",
    "FIELD_NAME",
    "no_devices",
    "pattern_fields",
    "safe",
    "timestamp",
]

#: The name-pattern fields the writer fills in itself.
BUILT_IN_FIELDS = ("timestamp", "index", "format")
FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")
#: The most characters one field value contributes to a file name.
_MAX_VALUE_LENGTH = 64
#: Hexadecimal digits of the SHA-256 of a cut value that follow its first
#: characters and a hyphen, so two long values with one start name two files.
_DIGEST_LENGTH = 8
#: What separates the parts of a path on this platform.
_SEPARATOR = re.compile("([%s])" % re.escape(os.sep + (os.altsep or "")))
#: Names Windows opens as devices, whatever follows the first dot.
_DEVICES = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + ["COM%d" % n for n in range(1, 10)]
    + ["LPT%d" % n for n in range(1, 10)]
)


def safe(value: object) -> str:
    """A field value as part of a file name: no separator, no ``..``, at most
    ``_MAX_VALUE_LENGTH`` characters. A longer one is cut and ends in a hyphen
    and a digest of the whole value as given."""
    original = str(value)
    text = _UNSAFE.sub("_", original).strip("._") or "unknown"
    if len(text) <= _MAX_VALUE_LENGTH:
        return text
    digest = hashlib.sha256(original.encode("utf-8", "surrogatepass")).hexdigest()
    kept = text[: _MAX_VALUE_LENGTH - _DIGEST_LENGTH - 1].rstrip("._")
    return "%s-%s" % (kept, digest[:_DIGEST_LENGTH])


def no_devices(path: str, pattern: str) -> str:
    """``path``, made by filling ``pattern``, with an underscore before each
    part a field value made a Windows device name. A part the pattern spells
    out is the caller's and is kept."""
    spelled = set(_SEPARATOR.split(pattern))
    parts = _SEPARATOR.split(path)
    for at in range(0, len(parts), 2):  # the odd ones are the separators
        part = parts[at]
        if part not in spelled and part.split(".", 1)[0].upper() in _DEVICES:
            parts[at] = "_" + part
    return "".join(parts)


def timestamp(time: float) -> str:
    """``time`` as UTC text for a file name. The capture controls ``time``, so
    one outside any calendar is written as a count of seconds."""
    try:
        moment = datetime.datetime.fromtimestamp(time, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        if math.isfinite(time) and abs(time) < 1 << 63:
            return "t%d" % int(time)
        return "unknown"
    return moment.strftime("%Y%m%dT%H%M%S.%fZ")


def pattern_fields(pattern: str) -> FrozenSet[str]:
    """The fields a name pattern uses; ``ValueError`` for one that is
    malformed or that names anything but a bare field."""
    found: Set[str] = set()

    def scan(text: str) -> None:
        try:
            parts = list(string.Formatter().parse(text))
        except ValueError as exc:
            raise ValueError("the name pattern is malformed: %s" % exc) from None
        for _literal, field, spec, _conversion in parts:
            if field is None:
                continue
            if not FIELD_NAME.match(field):
                raise ValueError(
                    "the name pattern may use bare field names only, not {%s}" % field
                )
            found.add(field)
            if spec:
                scan(spec)  # a spec may nest one level of fields

    scan(pattern)
    return frozenset(found)
