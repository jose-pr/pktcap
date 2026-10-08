"""Records as JSON, one per line (internal)."""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Mapping, Tuple

from ._contract import RecordFormat
from ._read import Refusal, read

__all__ = ["JSONFormat", "NotJSON", "json_loads", "json_text"]


class NotJSON(Exception):
    """The text holds a constant the standard decoder reads and this library
    does not: ``NaN``, an infinity."""


def _object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    found = dict(pairs)
    if len(found) != len(pairs):
        raise Refusal("a key is written twice in one JSON object")
    return found


def json_loads(text: str, constants: Exception) -> Any:
    """``text`` as one JSON value, decoded strictly.

    A repeated key raises :class:`Refusal`. ``NaN``, an infinity (written or
    produced by a number too large for a float) raises ``constants``. Other
    errors are the decoder's own.
    """

    def constant(name: str) -> Any:
        raise constants

    def number(digits: str) -> float:
        value = float(digits)
        if not math.isfinite(value):
            raise constants
        return value

    return json.loads(
        text, object_pairs_hook=_object, parse_constant=constant, parse_float=number
    )


def json_text(value: Any, what: str = "JSON") -> str:
    """``value`` as one line of ASCII JSON, with the errors of the standard
    encoder narrowed to two types and stripped of the value."""
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False)
    except RecursionError:
        raise ValueError("%s cannot hold a record nested this deeply" % what) from None
    except ValueError:
        # A NaN, an infinity, or a container that holds itself.
        raise ValueError(
            "%s cannot hold a NaN, an infinity or a circular value" % what
        ) from None
    except TypeError:
        raise TypeError(
            "%s holds plain data only: dict, list, str, int, float, bool, None" % what
        ) from None


class JSONFormat(RecordFormat):
    """Newline-delimited JSON: one record, one line.

    ASCII only (every other character is a ``\\u`` escape), so the output is
    the same under any console encoding and carries no control character.
    ``NaN`` and the infinities are refused, as JSON has no way to write them.
    """

    name = "json"
    suffixes = (".json", ".jsonl", ".ndjson")

    def dumps(self, record: Mapping[str, Any]) -> str:
        return json_text(dict(record)) + "\n"

    def loads(self, text: str) -> Dict[str, Any]:
        def parse() -> Any:
            if not text.strip():
                raise Refusal("the JSON text is empty")
            try:
                return json_loads(text, Refusal("JSON holds a NaN or an infinity"))
            except json.JSONDecodeError as caught:
                if caught.msg.startswith("Extra data"):
                    raise Refusal(
                        "the JSON text holds more than one value, or text after it",
                        caught.lineno,
                    )
                raise Refusal("the text is not valid JSON", caught.lineno)

        return read("json", parse)
