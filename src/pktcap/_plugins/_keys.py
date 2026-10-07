"""Which layer and field a filter key names, and the test it becomes (internal).

A key is ``LAYER.KEY`` or ``LAYER.FIELD`` for a layer a registry declares or
that is built in, or the bare ``KEY`` of a registered key that exactly one
layer has. The built-in keys (``port``, ``proto``, ...) are the filter's own
and are answered before anything here.
"""

from __future__ import annotations

import logging
import re
import types
import typing
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

from .._filter import FilterClause
from .._layers import BUILTIN_LAYERS
from ._compare import MAX_SEGMENTS, Wanted, parse_boolean, parse_number, parse_octets

if TYPE_CHECKING:
    from .._dissect import DissectedFrame
    from .._dissectors import DissectorRegistry

__all__ = ["Guard", "build_test", "list_keys"]

_LOG = logging.getLogger(__name__)

#: How many registered keys one filter build logs a failing test for.
_MAX_LOGGED = 8
#: The most names an error lists before it says "...".
_MAX_LISTED = 32
_KEY_TEXT = re.compile(r"[A-Za-z0-9_.-]+\Z")

Test = Callable[["DissectedFrame"], bool]


class Guard:
    """Logs a registered test that raised, once per key, for the first
    :data:`_MAX_LOGGED` keys."""

    def __init__(self) -> None:
        self._logged: Set[str] = set()

    def failed(self, label: str, error: BaseException) -> None:
        if label in self._logged or len(self._logged) >= _MAX_LOGGED:
            return
        self._logged.add(label)
        _LOG.warning(
            "the filter key %s raised %s; it is false for that layer",
            label,
            type(error).__name__,
        )


def _known(registry: "Optional[DissectorRegistry]") -> Dict[str, type]:
    known = dict(BUILTIN_LAYERS)
    if registry is not None:
        known.update(registry.layers())
    return known


def _registered(registry: "Optional[DissectorRegistry]", name: str) -> Dict[str, Any]:
    if registry is None or name not in registry.layers():
        return {}
    return dict(registry._registered_keys(name))


def _listed(names: List[str]) -> str:
    shown = names[:_MAX_LISTED]
    return ", ".join(shown) + (", ..." if len(names) > _MAX_LISTED else "")


def _fields(layer: type) -> Tuple[str, ...]:
    fields = getattr(layer, "_fields", ())
    return tuple(f for f in fields if isinstance(f, str)) if fields else ()


def _bare_keys(
    registry: "Optional[DissectorRegistry]", builtin_keys: Tuple[str, ...]
) -> Dict[str, List[str]]:
    """Each registered key a built-in key does not shadow, with the layers
    that have it, in name order."""
    found: Dict[str, List[str]] = {}
    if registry is not None:
        for name in sorted(registry.layers()):
            for key in registry._registered_keys(name):
                if key not in builtin_keys:
                    found.setdefault(key, []).append(name)
    return found


def build_test(
    clause: FilterClause,
    registry: "Optional[DissectorRegistry]",
    builtin_keys: Tuple[str, ...],
    guard: Optional[Guard] = None,
) -> Test:
    """The test of a clause whose key is not a built-in one.

    :raises ValueError: an unknown layer, key or field, an ambiguous bare key,
        a key of too many segments, a value that can never match.
    """
    guard = guard if guard is not None else Guard()
    segments = clause.key.split(".")
    if len(segments) > MAX_SEGMENTS:
        raise ValueError(
            "%s has %d segments; a key has at most %d"
            % (clause.key, len(segments), MAX_SEGMENTS)
        )
    if not all(segments):
        raise ValueError("%s has an empty segment" % clause.key)
    known = _known(registry)
    first = segments[0].lower()
    if first in known:
        if len(segments) == 1:
            raise ValueError(
                "%s names a layer: write %s.KEY, one of %s"
                % (
                    clause.key,
                    first,
                    _listed(_layer_keys(registry, first, known[first])),
                )
            )
        return _layer_test(first, known[first], segments[1:], clause, registry, guard)
    bare = _bare_keys(registry, builtin_keys).get(first)
    if bare is not None and registry is not None:
        if len(bare) > 1:
            raise ValueError(
                "%s is ambiguous: write %s"
                % (first, " or ".join("%s.%s" % (name, first) for name in bare))
            )
        return _layer_test(
            bare[0], known[bare[0]], [first] + segments[1:], clause, registry, guard
        )
    raise ValueError(_unknown(clause.key, registry, builtin_keys))


def _unknown(
    key: str, registry: "Optional[DissectorRegistry]", builtin_keys: Tuple[str, ...]
) -> str:
    keys = list(builtin_keys) + sorted(_bare_keys(registry, builtin_keys))
    layers = sorted(_known(registry))
    shown = keys[:_MAX_LISTED]
    room = _MAX_LISTED - len(shown)
    text = "unknown filter key %r (known: %s" % (key, ", ".join(shown))
    if len(keys) > _MAX_LISTED:
        text += ", ..."
    if room > 0:
        text += "; layers: %s%s" % (
            ", ".join(layers[:room]),
            ", ..." if len(layers) > room else "",
        )
    return text + ")"


def _layer_keys(
    registry: "Optional[DissectorRegistry]", name: str, layer: type
) -> List[str]:
    names = set(_fields(layer)) | set(_registered(registry, name))
    return sorted(names)


def _layer_test(
    name: str,
    layer: type,
    rest: List[str],
    clause: FilterClause,
    registry: "Optional[DissectorRegistry]",
    guard: Guard,
) -> Test:
    head = rest[0].lower()
    label = "%s.%s" % (name, head)
    builder = _registered(registry, name).get(head)
    if builder is not None:
        sub = FilterClause(".".join([head] + rest[1:]), clause.value, clause.negated)
        test = builder(sub)
        if not callable(test):
            raise TypeError(
                "the builder of the key %s returned something not callable" % label
            )
        return _over_layers(layer, test, label, guard)
    fields = _fields(layer)
    field = next((f for f in fields if f == rest[0]), None) or next(
        (f for f in fields if f.lower() == head), None
    )
    if field is None:
        raise ValueError(
            "%s has no key or field %r (it has: %s)"
            % (name, rest[0], _listed(_layer_keys(registry, name, layer)))
        )
    texts = clause.values
    if not texts:
        raise ValueError("%s has no value" % clause.key)
    path = tuple(rest[1:])
    if not path:
        _refuse_by_hint(layer, name, field, texts)
    wanted = Wanted(texts)
    return _over_layers(
        layer, lambda record: wanted.matches(getattr(record, field), path), label, guard
    )


def _over_layers(
    layer: type, test: Callable[[Any], bool], label: str, guard: Guard
) -> Test:
    """The clause holds when any layer of that class in the frame passes; a
    test that raises is false for that layer and logged."""

    def frame_test(frame: "DissectedFrame") -> bool:
        for record in frame.layers:
            if isinstance(record, layer):
                try:
                    if test(record):
                        return True
                except Exception as exc:
                    guard.failed(label, exc)
        return False

    return frame_test


_NONE_TYPES = (type(None),)
_UNION_ORIGINS: Tuple[Any, ...] = (typing.Union,) + (
    (types.UnionType,) if hasattr(types, "UnionType") else ()
)


def _declared_type(layer: type, field: str) -> Any:
    """The field's annotation with ``Optional`` removed, or ``None`` when the
    hints do not resolve or leave more than one type."""
    try:
        hint = typing.get_type_hints(layer)[field]
    except Exception:
        return None
    if typing.get_origin(hint) in _UNION_ORIGINS:
        rest = [arg for arg in typing.get_args(hint) if arg not in _NONE_TYPES]
        if len(rest) != 1:
            return None
        hint = rest[0]
    return hint


def _refuse_by_hint(layer: type, name: str, field: str, texts: Tuple[str, ...]) -> None:
    """A field declared exactly ``int``, ``bool`` or ``bytes`` takes values of
    that type alone: any other is refused when the filter is compiled."""
    declared = _declared_type(layer, field)
    label = "%s.%s" % (name, field)
    for text in texts:
        if declared is bool and parse_boolean(text) is None:
            raise ValueError(
                "%s takes yes or no (1, true, yes, on, 0, false, no, off), not %r"
                % (label, text)
            )
        if declared is int and parse_number(text) is None:
            raise ValueError("%s takes an integer, not %r" % (label, text))
        if declared is bytes and parse_octets(text) is None:
            raise ValueError("%s takes hexadecimal octets, not %r" % (label, text))


def list_keys(
    registry: "Optional[DissectorRegistry]", builtin_keys: Tuple[str, ...]
) -> Tuple[str, ...]:
    """Every key that compiles, sorted: the built-in ones, each ``LAYER.KEY``
    and ``LAYER.FIELD``, and the bare form of a registered key exactly one
    layer has."""
    names: Set[str] = set(builtin_keys)
    for name, layer in _known(registry).items():
        for key in _layer_keys(registry, name, layer):
            if _KEY_TEXT.match(key):
                names.add("%s.%s" % (name, key))
    for key, owners in _bare_keys(registry, builtin_keys).items():
        if len(owners) == 1:
            names.add(key)
    return tuple(sorted(names))
