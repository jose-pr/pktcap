"""Records as JSON, one per line (internal)."""

from __future__ import annotations

import json
from typing import Any, Mapping

from ._contract import RecordFormat

__all__ = ["JSONFormat", "json_text"]


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
