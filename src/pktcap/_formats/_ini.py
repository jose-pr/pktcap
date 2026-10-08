"""Records as INI files (internal)."""

from __future__ import annotations

import configparser
import json
import re
from typing import Any, Dict, List, Mapping
from urllib.parse import quote, unquote

from ._contract import RecordFormat
from ._json import NotJSON, json_loads, json_text
from ._read import Refusal, read

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


def _unname(name: str) -> str:
    """The key a section or option name stands for: its percent escapes
    decoded, a sequence that is not UTF-8 refused."""
    try:
        return unquote(name, errors="strict")
    except UnicodeDecodeError:
        raise Refusal("an INI name holds a percent escape that is not UTF-8") from None


def _value(raw: str) -> Any:
    """An option's value: JSON when it is JSON, else its text, so a file
    somebody wrote by hand reads."""
    try:
        return json_loads(raw, NotJSON())
    except (json.JSONDecodeError, NotJSON):
        return raw


def _sections(text: str) -> "configparser.RawConfigParser":
    # default_section="" names no section a header can spell, so `[DEFAULT]`
    # is an ordinary section and no option is inherited.
    parser = configparser.RawConfigParser(
        strict=True, interpolation=None, default_section=""
    )
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    try:
        parser.read_string(text)
    except configparser.DuplicateSectionError as caught:
        raise Refusal("an INI section is written twice", caught.lineno) from None
    except configparser.DuplicateOptionError as caught:
        raise Refusal(
            "an INI option is written twice in a section", caught.lineno
        ) from None
    except configparser.MissingSectionHeaderError as caught:
        raise Refusal(
            "the INI text has a line before its first section", caught.lineno
        ) from None
    except configparser.ParsingError as caught:
        lineno = caught.errors[0][0] if caught.errors else None
        raise Refusal("an INI line is no section, option or comment", lineno) from None
    return parser


def _document(text: str) -> Dict[str, Any]:
    if not text:
        raise Refusal("the INI text is empty")
    parser = _sections(text)
    if not parser.sections():
        if text.strip():
            raise Refusal("the INI text holds no section")
        return {}  # what the writer writes for a record with nothing in it
    record: Dict[str, Any] = {}
    for section in parser.sections():
        options: Dict[str, Any] = {}
        for name, raw in parser.items(section):
            key = _unname(name)
            if key in options:
                raise Refusal("an INI option is written twice in a section")
            options[key] = _value(raw)
        if section == _MAIN_SECTION:
            top: Dict[str, Any] = options
        else:
            key = _unname(section)
            top = {key: options}
        for key in top:
            if key in record:
                raise Refusal("an INI top-level key is written twice")
        record.update(top)
    return record


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

    def loads(self, text: str) -> Dict[str, Any]:
        return read("ini", lambda: _document(text))
