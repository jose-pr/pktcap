"""Records as INI files (internal)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping
from urllib.parse import quote

from ._contract import RecordFormat
from ._json import json_text

__all__ = ["INIFormat"]

_PLAIN = re.compile(r"[A-Za-z0-9_.-]+\Z")
#: The section that takes a record's top-level values that are not mappings.
_MAIN_SECTION = "record"


def _name(key: object) -> str:
    """A section or option name that every INI reader takes as one token."""
    text = key if isinstance(key, str) else str(key)
    if not _PLAIN.match(text):
        # A name may come from the wire: no bracket, separator, comment mark
        # or line break of it reaches the file.
        text = quote(text, safe="")
    if text.upper() == "DEFAULT":  # configparser reads that section as defaults
        text = "%%%02X%s" % (ord(text[0]), text[1:])
    return text


class INIFormat(RecordFormat):
    """One INI file per record.

    Each top-level key whose value is a mapping becomes a section of that
    name, its items the options; every other top-level key becomes an option
    of the section ``[record]``. Each value is written as JSON on one line, so
    it reads back with its type. A name outside ``A-Z a-z 0-9 _ . -`` is
    percent-encoded. A second section of the same name would be an error to
    every reader, so a file holds exactly one record.
    """

    name = "ini"
    suffixes = (".ini",)
    streamable = False

    def dumps(self, record: Mapping[str, Any]) -> str:
        sections: Dict[str, Dict[str, str]] = {}
        main: Dict[str, str] = {}
        for key, value in record.items():
            if isinstance(value, Mapping):
                options: Dict[str, str] = {}
                for name, item in value.items():
                    self._put(options, name, item)
                if _name(key) in sections:
                    raise ValueError("INI cannot hold two sections of one name")
                sections[_name(key)] = options
            else:
                self._put(main, key, value)
        if main:
            if _MAIN_SECTION in sections:
                raise ValueError(
                    "INI keeps top-level values in [%s], which this record also "
                    "uses as a section" % _MAIN_SECTION
                )
            sections = {_MAIN_SECTION: main, **sections}
        lines: List[str] = []
        for section, options in sections.items():
            lines.append("[%s]" % section)
            lines.extend("%s = %s" % item for item in options.items())
            lines.append("")
        return "\n".join(lines) if lines else "\n"

    @staticmethod
    def _put(options: Dict[str, str], key: object, value: Any) -> None:
        name = _name(key)
        if name in options:
            raise ValueError("INI cannot hold two options of one name in a section")
        options[name] = json_text(value, "INI")
