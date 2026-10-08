"""What the record readers share (internal).

The text a reader is given is untrusted, so a reader raises :class:`Refusal`
for what it will not take, and :func:`read` turns that, and anything the
parsing library raises, into one :class:`~pktcap.RecordFormatError` that
quotes nothing and chains nothing.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from .._exceptions import RecordFormatError

__all__ = ["Refusal", "check_plain", "line_of", "read"]


class Refusal(Exception):
    """A reader will not take the text: what is wrong, and the line if known."""

    def __init__(self, message: str, lineno: Optional[int] = None) -> None:
        super().__init__(message)
        self.message = message
        self.lineno = lineno


def line_of(text: str, position: int) -> int:
    """The 1-based line of the character at ``position`` in ``text``."""
    return text.count("\n", 0, max(position, 0)) + 1


def read(format: str, parse: Callable[[], Any]) -> Dict[str, Any]:
    """The mapping ``parse()`` returns, or a :class:`RecordFormatError`.

    The error is raised after the ``try`` has ended, so it carries no
    ``__context__``: the parsing library's own messages quote the text, and
    nothing of them survives on the exception.
    """
    label = format.upper()
    failure: Refusal
    try:
        value = parse()
        if isinstance(value, dict):
            return value
        failure = Refusal("the %s document is not a mapping" % label)
    except Refusal as caught:
        failure = Refusal(caught.message, caught.lineno)
    except RecursionError:
        failure = Refusal("the %s text is nested too deeply" % label)
    except MemoryError:
        raise
    except ValueError as caught:
        if "integer string conversion" in str(caught):
            # The interpreter's own limit on the digits of an integer.
            failure = Refusal("the %s text holds a number too long to convert" % label)
        else:
            failure = Refusal("the text is not valid %s" % label)
    except Exception:
        # Each parsing library has its own exceptions, and none promises a
        # closed set for hostile text.
        failure = Refusal("the text is not valid %s" % label)
    raise RecordFormatError(failure.message, format=format, lineno=failure.lineno)


def _children(node: Any) -> Iterator[Any]:
    return iter(node.values()) if isinstance(node, dict) else iter(node)


def check_plain(root: Any, scalars: Tuple[type, ...], label: str) -> None:
    """Refuse a value that is not plain data: raises :class:`Refusal`.

    A container is ``dict`` or ``list``; ``scalars`` are the other types that
    may be a value or a key. The value is a tree: a reader whose format has
    aliases refuses them before it gets here, so each container is met once
    and the work is the size of the document. Iterative, so the depth of a
    document costs no recursion.
    """
    if not isinstance(root, (dict, list)):
        raise Refusal("the %s document is not a mapping" % label)
    stack = [root]
    while stack:
        node = stack.pop()
        _check_keys(node, scalars, label)
        for child in _children(node):
            if isinstance(child, (dict, list)):
                stack.append(child)
            elif not isinstance(child, scalars):
                raise Refusal("a %s value is not plain data" % label)


def _check_keys(node: Any, scalars: Tuple[type, ...], label: str) -> None:
    if isinstance(node, dict):
        for key in node:
            if not isinstance(key, scalars):
                raise Refusal("a %s key is not plain data" % label)
