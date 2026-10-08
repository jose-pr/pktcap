"""Records as YAML documents (internal). Needs the ``yaml`` extra."""

from __future__ import annotations

from typing import Any, Dict, Mapping

from ._contract import RecordFormat, missing_extra
from ._read import Refusal, check_plain, line_of, read

__all__ = ["YAMLFormat"]

#: What a YAML value may be besides a mapping and a list. ``bytes`` is what
#: ``!!binary`` reads as, the one tag the writer produces beyond plain data.
_SCALARS = (str, int, float, bool, type(None), bytes)

_loader: Any = None


def _safe_loader() -> Any:
    """PyYAML's safe loader, made to refuse what a record must not hold.

    Built on first use because PyYAML is an optional import.
    """
    global _loader
    if _loader is not None:
        return _loader
    import yaml

    class RecordLoader(yaml.SafeLoader):
        def compose_node(self, parent: Any, index: Any) -> Any:
            # An alias makes a short text stand for a structure of any size:
            # reading it costs little, and whoever then walks the record
            # pays for the whole expansion. The writer writes none.
            if self.check_event(yaml.AliasEvent):  # type: ignore[no-untyped-call,unused-ignore]
                event = self.peek_event()  # type: ignore[no-untyped-call,unused-ignore]
                raise Refusal("a YAML alias is not read", event.start_mark.line + 1)
            return super().compose_node(parent, index)  # type: ignore[no-untyped-call,unused-ignore]

        def flatten_mapping(self, node: Any) -> None:
            # A merge key copies the mapping it names into this one, and a
            # chain of them doubles at every link: the text grows linearly
            # and what it builds exponentially.
            for key_node, _ in node.value:
                if key_node.tag == "tag:yaml.org,2002:merge":
                    raise Refusal(
                        "a YAML merge key is not read", key_node.start_mark.line + 1
                    )
            super().flatten_mapping(node)

        def construct_mapping(self, node: Any, deep: bool = False) -> Any:
            seen: Dict[Any, bool] = {}
            for key_node, _ in node.value if isinstance(node, yaml.MappingNode) else ():
                try:
                    key = self.construct_object(  # type: ignore[no-untyped-call,unused-ignore]
                        key_node, deep=True
                    )
                    known = key in seen
                except Exception:
                    break  # a key that cannot be one: the constructor says so
                if known:
                    raise Refusal(
                        "a key is written twice in one YAML mapping",
                        key_node.start_mark.line + 1,
                    )
                seen[key] = True
            return super().construct_mapping(node, deep)

    _loader = RecordLoader
    return RecordLoader


def _document(text: str) -> Any:
    import yaml

    loader = None
    try:
        loader = _safe_loader()(text)
        if not loader.check_data():
            raise Refusal("the YAML text holds no document")
        value = loader.get_data()
        if loader.check_data():
            raise Refusal("the YAML text holds more than one document")
    except yaml.reader.ReaderError as caught:
        raise Refusal(
            "the YAML text holds a character YAML forbids",
            line_of(text, caught.position),
        )
    except yaml.MarkedYAMLError as caught:
        mark = caught.problem_mark or caught.context_mark
        lineno = None if mark is None else mark.line + 1
        if isinstance(caught, yaml.constructor.ConstructorError):
            raise Refusal("a YAML tag, key or value is not plain data", lineno)
        raise Refusal("the text is not valid YAML", lineno)
    finally:
        if loader is not None:
            loader.dispose()
    check_plain(value, _SCALARS, "YAML")
    return value


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

        class Dumper(yaml.SafeDumper):
            # An object a record holds twice is written twice: an anchor and
            # an alias are not plain data, and the reader refuses them.
            def ignore_aliases(self, data: Any) -> bool:
                return True

        try:
            text: str = yaml.dump(dict(record), Dumper=Dumper, sort_keys=False)
        except yaml.YAMLError:
            # PyYAML's message quotes the object it could not represent.
            raise TypeError(
                "YAML holds plain data only: dict, list, str, int, float, bool, None"
            ) from None
        except RecursionError:
            raise ValueError("YAML cannot hold a record nested this deeply") from None
        return text

    def require_loads(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            raise missing_extra("yaml", "yaml", "input") from None

    def loads(self, text: str) -> Dict[str, Any]:
        self.require_loads()
        return read("yaml", lambda: _document(text))
