"""Loading a library's plugin by the name a user gave (internal).

This is the one module that imports a module because a string names it, which
runs that module's code: it is imported by the package root and by the command
line, and its list comes from :mod:`._config` alone.
"""

from __future__ import annotations

import inspect
import logging
from importlib import import_module
from typing import Any, Callable, Iterable, List, NamedTuple, Optional, Tuple, Union

from .._dissectors import DissectorRegistry
from .._dissectors._contract import Selector
from .._exceptions import CapturePluginError
from ._config import (
    ALWAYS_ARGUMENT,
    ConfigArgument,
    always_list,
    describe,
    plugin_list,
)

__all__ = ["LoadedPlugin", "load_plugins"]

_LOG = logging.getLogger(__name__)

#: The attribute a plugin module offers: ``pktcap_plugin(registry)``.
_HOOK = "pktcap_plugin"


class LoadedPlugin(NamedTuple):
    """One plugin :func:`load_plugins` loaded.

    :ivar name: the item as written.
    :ivar source: where the list came from: ``"argument"``,
        ``"PKTCAP_LOAD"``, the configuration file's path, or ``"always"`` for
        a plugin the caller's code loads whatever the user listed.
    :ivar selectors: the selectors its hook registered a dissector under.
    :ivar layers: the names of the layers its hook declared.
    """

    name: str
    source: str
    selectors: Tuple[Selector, ...]
    layers: Tuple[str, ...]


def _error(item: str, source: str, problem: str) -> CapturePluginError:
    shown = repr(item)
    return CapturePluginError(
        "%s names %s: %s" % (describe(source), shown, problem),
        plugin=item,
        source=source,
    )


class _NoSuchModule(Exception):
    """``name`` is not a module: nothing of that name is there to import."""


def _import(name: str, item: str, source: str) -> Any:
    """The module ``name``. :class:`_NoSuchModule` when there is none;
    the plugin's error when there is one and importing it fails."""
    try:
        return import_module(name)
    except ModuleNotFoundError as exc:
        # Only the plain error about this very name says "no such module". A
        # subclass, or another name, is a module that exists failing to import.
        if type(exc) is ModuleNotFoundError and exc.name == name:
            raise _NoSuchModule(name) from exc
        raise _error(
            item, source, "importing it failed (%s: %s)" % (type(exc).__name__, exc)
        ) from exc
    except Exception as exc:
        raise _error(
            item, source, "importing it failed (%s: %s)" % (type(exc).__name__, exc)
        ) from exc


def _find_hook(item: str, source: str) -> Callable[[DissectorRegistry], Any]:
    """The module named ``item`` and its ``pktcap_plugin``, or, when the last
    part is not a module, the callable of that name in the module before it.

    Imported from the top down, one package at a time: a package that fails to
    import ends the search, so a submodule its failed import left in
    ``sys.modules`` is never taken for a plugin.
    """
    parts = item.split(".")
    module: Any = None
    for depth in range(1, len(parts) + 1):
        name = ".".join(parts[:depth])
        try:
            module = _import(name, item, source)
        except _NoSuchModule as exc:
            if module is None or depth != len(parts):
                raise _error(item, source, "no module of that name") from exc
            hook = getattr(module, parts[-1], None)
            if hook is None:
                raise _error(
                    item,
                    source,
                    "no module of that name, and %r has no attribute %r"
                    % (".".join(parts[:-1]), parts[-1]),
                ) from exc
            if not callable(hook):
                raise _error(item, source, "%s is not callable" % item) from exc
            return hook  # type: ignore[no-any-return]
    hook = getattr(module, _HOOK, None)
    if not callable(hook):
        raise _error(
            item,
            source,
            "the module has no %s: name a callable as MODULE.NAME" % _HOOK,
        )
    return hook  # type: ignore[no-any-return]


def _load_one(
    registry: DissectorRegistry,
    item: str,
    source: str,
    hook: Callable[[DissectorRegistry], Any],
) -> LoadedPlugin:
    try:
        inspect.signature(hook).bind(registry)
    except TypeError as exc:
        raise _error(
            item, source, "the hook takes no single argument: it is given the registry"
        ) from exc
    except ValueError:
        pass  # a callable with no signature to check
    selectors, layers = set(registry.selectors()), set(registry.layers())
    try:
        hook(registry)
    except Exception as exc:
        raise _error(
            item, source, "the hook raised (%s: %s)" % (type(exc).__name__, exc)
        ) from exc
    _LOG.info("loaded the plugin %s from %s", item, describe(source))
    return LoadedPlugin(
        item,
        source,
        tuple(sorted(set(registry.selectors()) - selectors)),
        tuple(sorted(set(registry.layers()) - layers)),
    )


def load_plugins(
    registry: DissectorRegistry,
    plugins: Union[None, str, Iterable[str]] = None,
    *,
    config: Optional[ConfigArgument] = None,
    always: Union[str, Iterable[str]] = (),
) -> Tuple[LoadedPlugin, ...]:
    """Import the plugins a list names and call each one's hook with ``registry``.

    The list is the first of these that names one: ``plugins``, the variable
    ``PKTCAP_LOAD``, the ``load`` key of the configuration file
    (:func:`capture_config_path`). Lists never add up. An item is a dotted
    Python name: a module with a ``pktcap_plugin(registry)`` function, or
    ``MODULE.CALLABLE`` for any callable taking the registry. Items are
    separated by ``,`` ``;`` ``:`` or white space; ``none`` alone is the empty
    list. Importing a module runs its code, so these three places are the
    only ones a list is ever read from.

    :param registry: where the hooks register. There is no default one.
    :param plugins: ``None`` (as configured), one text, or an iterable of texts.
    :param config: ``None``, the path of a configuration file, or ``none``. A
        file named here is read, and checked, even when ``plugins`` is given.
    :param always: items a caller's code loads whatever the user listed, as
        dotted names written as for ``plugins``. They load first, with the
        source ``"always"``, and are never read from the variable or the file.
        An item of the user's list that resolves to the same hook callable is
        skipped, not loaded twice and not an error; a different callable that
        claims a selector already taken is the plugin error.
    :returns: one :class:`LoadedPlugin` per item loaded, in order.
    :raises CapturePluginError: an item cannot be loaded. The registry is left
        as it was before the call; modules already imported stay imported.
    :raises CaptureConfigError: the configuration file is malformed, or not
        trusted.
    :raises ValueError: a malformed item given as ``plugins`` or ``always``.
    :raises TypeError: ``registry`` is not a :class:`DissectorRegistry`.
    :raises OSError: a named configuration file that cannot be read.
    """
    if not isinstance(registry, DissectorRegistry):
        raise TypeError("load_plugins takes a DissectorRegistry to register into")
    items, source = plugin_list(plugins, config)
    fixed = always_list(always)
    snapshot = registry._snapshot()
    loaded = []
    taken: List[Callable[[DissectorRegistry], Any]] = []
    try:
        for item in fixed:
            hook = _find_hook(item, ALWAYS_ARGUMENT)
            taken.append(hook)
            loaded.append(_load_one(registry, item, ALWAYS_ARGUMENT, hook))
        for item in items:
            hook = _find_hook(item, source)
            if any(hook is known or hook == known for known in taken):
                continue
            loaded.append(_load_one(registry, item, source, hook))
    except BaseException:
        registry._restore(snapshot)
        raise
    return tuple(loaded)
