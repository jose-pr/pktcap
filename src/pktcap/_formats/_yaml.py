"""Records as YAML documents (internal). Needs the ``yaml`` extra."""

from __future__ import annotations

from typing import Any, Mapping

from ._contract import RecordFormat, missing_extra

__all__ = ["YAMLFormat"]


class YAMLFormat(RecordFormat):
    """One YAML document per record, written by PyYAML's safe dumper.

    Block style, keys in the record's own order, non-ASCII and control
    characters escaped. In a file of several records each document is led by
    ``---``, the first one included, so a file that is appended to stays a
    valid stream.
    """

    name = "yaml"
    suffixes = (".yaml", ".yml")
    extra = "yaml"
    separator = "---\n"

    def require(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            raise missing_extra("yaml", "yaml") from None

    def dumps(self, record: Mapping[str, Any]) -> str:
        self.require()
        import yaml

        try:
            text: str = yaml.safe_dump(dict(record), sort_keys=False)
        except yaml.YAMLError:
            # PyYAML's message quotes the object it could not represent.
            raise TypeError(
                "YAML holds plain data only: dict, list, str, int, float, bool, None"
            ) from None
        except RecursionError:
            raise ValueError("YAML cannot hold a record nested this deeply") from None
        return text
