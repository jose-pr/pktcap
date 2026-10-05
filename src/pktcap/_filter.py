"""The capture-filter expression: its grammar, and nothing about its keys
(internal).

Clauses ``key=value`` or ``key!=value`` joined by ``and``::

    op=RRQ,WRQ and host=10.0.0.0/8
    msg_type=DHCPDISCOVER and option.53!=DHCPOFFER

What a key means, how a value is converted and how a clause is matched belong
to the protocol library, which passes a callable. This module owns the split
into clauses, the negation and the conjunction.
"""

from __future__ import annotations

import re
from typing import Callable, List, NamedTuple, Optional, Tuple, TypeVar

from ._exceptions import CaptureFilterError

__all__ = ["FilterClause", "parse_capture_filter", "compile_capture_filter"]

_T = TypeVar("_T")

#: The longest expression accepted, in characters.
_MAX_FILTER_LENGTH = 4096
_AND = re.compile(r"(?:^|\s+)and(?:\s+|$)", re.IGNORECASE)
_OR = re.compile(r"(?:^|\s)or(?:\s|$)", re.IGNORECASE)
_KEY = re.compile(r"[A-Za-z0-9_.-]+\Z")


class FilterClause(NamedTuple):
    """One ``key=value`` or ``key!=value`` clause of a capture filter.

    :ivar key: the text before the operator, as written: case is kept.
    :ivar value: the text after it, surrounding space removed.
    :ivar negated: the operator was ``!=``.
    """

    key: str
    value: str
    negated: bool = False

    @property
    def values(self) -> Tuple[str, ...]:
        """``value`` split on commas, each item stripped and empty ones left
        out, for a key that reads a comma as "any of"."""
        return tuple(item.strip() for item in self.value.split(",") if item.strip())

    def __str__(self) -> str:
        return "%s%s%s" % (self.key, "!=" if self.negated else "=", self.value)


def parse_capture_filter(text: Optional[str]) -> Tuple[FilterClause, ...]:
    """The clauses of a capture-filter expression, in order.

    :param text: the expression. ``None``, empty or blank is no clause at all.
    :raises CaptureFilterError: a clause that is not ``key=value`` or
        ``key!=value``, an ``or``, an expression over 4,096 characters.
    :raises TypeError: ``text`` is neither ``str`` nor ``None``.
    """
    if text is None:
        return ()
    if not isinstance(text, str):
        raise TypeError("a capture filter is text")
    if len(text) > _MAX_FILTER_LENGTH:
        raise CaptureFilterError(
            "a capture filter of %d characters is over the limit of %d"
            % (len(text), _MAX_FILTER_LENGTH)
        )
    if not text.strip():
        return ()
    clauses: List[FilterClause] = []
    for part in _AND.split(text.strip()):
        clause = part.strip()
        key, operator, value = clause.partition("=")
        negated = key.endswith("!")
        key, value = key[: -1 if negated else None].strip(), value.strip()
        if _OR.search(clause) or key.lower() == "or":
            raise CaptureFilterError("capture filters join clauses with 'and' only")
        if not operator or not value or not _KEY.match(key):
            raise CaptureFilterError(
                "expected key=value or key!=value, got %r" % clause
            )
        clauses.append(FilterClause(key, value, negated))
    return tuple(clauses)


def _everything(item: object) -> bool:
    return True


def compile_capture_filter(
    text: Optional[str], build: Callable[[FilterClause], Callable[[_T], bool]]
) -> Callable[[_T], bool]:
    """One predicate for a capture-filter expression.

    ``build`` is called once per clause, here and never per item, and returns
    the test for that clause's key and value; a ``!=`` clause is inverted for
    it, and the predicate is true when every clause holds. So a key this
    library has never heard of, or a value that does not convert, is one
    error when the filter is compiled and not one per packet.

    :param text: the expression; ``None`` or blank matches everything.
    :param build: turns one :class:`FilterClause` into a test. It should
        raise ``ValueError`` for an unknown key or a bad value.
    :raises CaptureFilterError: the expression is malformed, or ``build``
        raised ``ValueError`` (which is chained, the clause named).
    :raises TypeError: ``build`` returned something that cannot be called.
    """
    checks: List[Tuple[Callable[[_T], bool], bool]] = []
    for clause in parse_capture_filter(text):
        try:
            test = build(clause)
        except CaptureFilterError:
            raise
        except ValueError as exc:
            raise CaptureFilterError("%s: %s" % (clause, exc)) from exc
        if not callable(test):
            raise TypeError("build must return a callable for %s" % (clause,))
        checks.append((test, clause.negated))
    if not checks:
        return _everything

    def predicate(item: _T) -> bool:
        for test, negated in checks:
            if bool(test(item)) is negated:
                return False
        return True

    return predicate
