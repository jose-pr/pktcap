"""Records as TOML documents (internal). Needs the ``toml`` extra."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional

from ._contract import RecordFormat, has_surrogate, missing_extra
from ._read import Refusal, check_plain, read

__all__ = ["TOMLFormat"]

_SCALARS = (str, int, float, bool)
#: The position tomli and tomllib end a message with, when they keep none.
_AT_LINE = re.compile(r"\(at line (\d+), column \d+\)\Z")

_NOT_ASCII = re.compile(r"[^\x00-\x7e]")


def _escape(match: "re.Match[str]") -> str:
    code = ord(match.group())
    if 0xD800 <= code <= 0xDFFF:
        # Half of a surrogate pair is not a character and TOML has no way to
        # write one: the replacement character stands in for it in a value.
        code = 0xFFFD
    return "\\u%04X" % code if code <= 0xFFFF else "\\U%08X" % code


def _check_names(record: Mapping[str, Any]) -> None:
    """``ValueError`` for a key, at any depth, that holds half of a surrogate
    pair: it would be written as U+FFFD, and two such keys as one. Run on a
    record that was written, so it holds no cycle."""
    stack: List[Any] = [record]
    while stack:
        node = stack.pop()
        if isinstance(node, Mapping):
            if any(isinstance(key, str) and has_surrogate(key) for key in node):
                raise ValueError("TOML cannot hold a lone surrogate in a key")
            stack.extend(node.values())
        elif isinstance(node, (list, tuple)):
            stack.extend(node)


def _toml_module() -> Any:
    """``tomllib`` where the interpreter has it, else ``tomli``, else the
    error that names the extra."""
    try:
        import tomllib  # type: ignore[import-not-found,unused-ignore]

        return tomllib
    except ImportError:
        pass
    try:
        import tomli  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        raise missing_extra("toml", "toml", "input") from None
    return tomli


def _lineno(caught: Exception) -> Optional[int]:
    lineno = getattr(caught, "lineno", None)
    if isinstance(lineno, int):
        return lineno
    found = _AT_LINE.search(str(caught))
    return int(found.group(1)) if found else None


class TOMLFormat(RecordFormat):
    """One TOML document per record, written by tomli-w.

    TOML has no separator between documents, so a file holds exactly one
    record, and it has no null: a record holding ``None`` is refused. Every
    character outside ASCII is written as a ``\\u`` escape, so the output does
    not depend on an encoding; a value that is not Unicode (a lone surrogate) is
    written as U+FFFD, and a key that holds one is refused.
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
        _check_names(record)
        # tomli-w writes every string and every quoted key as a basic string,
        # the one place a TOML document accepts these escapes.
        text = _NOT_ASCII.sub(_escape, text)
        return text if text.endswith("\n") else text + "\n"

    def require_loads(self) -> None:
        _toml_module()

    def loads(self, text: str) -> Dict[str, Any]:
        module = _toml_module()

        def parse() -> Any:
            if not text:
                raise Refusal("the TOML text is empty")
            try:
                value = module.loads(text)
            except module.TOMLDecodeError as caught:
                message = str(caught)
                twice = any(w in message for w in ("twice", "overwrite", "Duplicate"))
                raise Refusal(
                    (
                        "a TOML key or table is written twice"
                        if twice
                        else "the text is not valid TOML"
                    ),
                    _lineno(caught),
                )
            # A date or a time is TOML's own type, not plain data.
            check_plain(value, _SCALARS, "TOML")
            return value

        return read("toml", parse)
