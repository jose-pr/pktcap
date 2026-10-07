"""Records as TOML documents (internal). Needs the ``toml`` extra."""

from __future__ import annotations

import re
from typing import Any, Mapping

from ._contract import RecordFormat, missing_extra

__all__ = ["TOMLFormat"]

_NOT_ASCII = re.compile(r"[^\x00-\x7e]")


def _escape(match: "re.Match[str]") -> str:
    code = ord(match.group())
    if 0xD800 <= code <= 0xDFFF:
        # Half of a surrogate pair is not a character and TOML has no way to
        # write one: the replacement character stands in for it.
        code = 0xFFFD
    return "\\u%04X" % code if code <= 0xFFFF else "\\U%08X" % code


class TOMLFormat(RecordFormat):
    """One TOML document per record, written by tomli-w.

    TOML has no separator between documents, so a file holds exactly one
    record, and it has no null: a record holding ``None`` is refused. Every
    character outside ASCII is written as a ``\\u`` escape, so the output does
    not depend on an encoding; text that is not Unicode (a lone surrogate) is
    written as U+FFFD.
    """

    name = "toml"
    suffixes = (".toml",)
    extra = "toml"
    streamable = False

    def require(self) -> None:
        try:
            import tomli_w  # noqa: F401
        except ImportError:
            raise missing_extra("toml", "toml") from None

    def dumps(self, record: Mapping[str, Any]) -> str:
        self.require()
        import tomli_w

        try:
            text: str = tomli_w.dumps(dict(record))
        except TypeError:
            raise TypeError(
                "TOML holds dict, list, str, int, float and bool only, with text "
                "keys; it has no null"
            ) from None
        except ValueError:
            raise ValueError("TOML cannot hold this record") from None
        except RecursionError:
            raise ValueError("TOML cannot hold a record nested this deeply") from None
        # tomli-w writes every string and every quoted key as a basic string,
        # the one place a TOML document accepts these escapes.
        text = _NOT_ASCII.sub(_escape, text)
        return text if text.endswith("\n") else text + "\n"
