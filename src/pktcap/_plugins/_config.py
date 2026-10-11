"""What a plugin list is made of (internal): the separators, the checks of an
item, the items a caller's code always loads.

The list itself is given to :func:`~pktcap._plugins._load.load_plugins`; this
module reads no file. It is the one module that reads the environment, and
only when asked, never at import: for the copy a hook command's process starts
from (:func:`process_environment`).
"""

from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Union

from .._exceptions import CapturePluginError

__all__ = [
    "ALWAYS_ARGUMENT",
    "PLUGINS_ARGUMENT",
    "always_list",
    "describe",
    "is_dotted_name",
    "named_list",
    "process_environment",
]

#: The source of a list given as an argument.
PLUGINS_ARGUMENT = "argument"
#: The source of the plugins a caller's code always loads.
ALWAYS_ARGUMENT = "always"

#: The most items in a list, and the most characters in one.
_MAX_ITEMS = 64
_MAX_ITEM_LENGTH = 255
_SEPARATORS = re.compile(r"[,;:\s]+")
_DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")


def process_environment() -> Dict[str, str]:
    """A copy of this process's environment, for a child process to start from."""
    return dict(os.environ)


def describe(source: str) -> str:
    """How an error names the source of a list."""
    if source == PLUGINS_ARGUMENT:
        return "the plugins argument"
    if source == ALWAYS_ARGUMENT:
        return "the always argument"
    return source


def _shown(text: str) -> str:
    """``text`` as one short quoted line: a name from a file is bounded and
    its control characters escaped."""
    return repr(text if len(text) <= 40 else text[:40] + "...")


def is_dotted_name(text: str) -> bool:
    """Whether ``text`` is a dotted Python name of a plugin item's length."""
    return len(text) <= _MAX_ITEM_LENGTH and bool(_DOTTED_NAME.match(text))


# -- the list -----------------------------------------------------------------


def _items(texts: Iterable[str]) -> List[str]:
    items: List[str] = []
    for text in texts:
        items.extend(part for part in _SEPARATORS.split(text) if part)
    if len(items) == 1 and items[0].lower() == "none":
        return []
    return items


def _problem(item: str, source: str, problem: str) -> CapturePluginError:
    return CapturePluginError(
        "%s names %s: %s" % (describe(source), _shown(item), problem),
        plugin=item,
        source=source,
    )


def _checked(items: List[str], source: str) -> List[str]:
    """Each item is a dotted Python name, at most 64 items and none twice,
    before anything is imported: a path or a relative name never reaches the
    import system. An argument's mistake is a plain ``ValueError``."""
    seen = set()
    for index, item in enumerate(items):
        if index >= _MAX_ITEMS:
            problem = "more than %d plugins" % _MAX_ITEMS
        elif len(item) > _MAX_ITEM_LENGTH or not _DOTTED_NAME.match(item):
            problem = (
                "not a dotted Python name of at most %d characters" % _MAX_ITEM_LENGTH
            )
        elif item in seen:
            problem = "named twice"
        else:
            seen.add(item)
            continue
        error = _problem(item, source, problem)
        if source in (PLUGINS_ARGUMENT, ALWAYS_ARGUMENT):
            raise ValueError(str(error))
        raise error
    return items


def _argument_items(plugins: Union[str, Iterable[str]]) -> List[str]:
    if isinstance(plugins, str):
        return _items([plugins])
    texts = list(plugins)
    if not all(isinstance(text, str) for text in texts):
        raise TypeError("plugins is a text or an iterable of texts")
    return _items(texts)


def always_list(always: Union[str, Iterable[str]]) -> List[str]:
    """The items a caller's code always loads, checked as an argument is: a
    mistake is a plain ``ValueError`` or ``TypeError``. Never read from the
    variable or the file."""
    return _checked(_argument_items(always), ALWAYS_ARGUMENT)


def named_list(plugins: Union[str, Iterable[str]], source: str) -> List[str]:
    """The items ``plugins`` names, checked as a list from ``source`` is: a
    mistake in a list that is not the ``"argument"`` is a
    :class:`CapturePluginError`, and in the argument a plain ``ValueError``."""
    return _checked(_argument_items(plugins), source)
