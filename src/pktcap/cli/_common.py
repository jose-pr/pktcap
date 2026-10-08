"""What the commands share: the plugins, the filter and the diagnostic line."""

from __future__ import annotations

import sys
from typing import (
    Callable,
    ClassVar,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
)

from duho import Cmd, LoggingArgs, value_sources

from .._dissect import DissectedFrame
from .._dissectors import DissectorRegistry
from .._filter import compile_capture_filter
from .._frame_filter import frame_filter_for
from .._plugins._load import LoadedPlugin, load_plugins

__all__ = ["Counted", "Loading", "Selecting", "error"]


def error(text: str) -> None:
    """One diagnostic line on stderr; a control character in it is escaped."""
    safe = "".join(c if c.isprintable() else repr(c)[1:-1] for c in text)
    print("pktcap: error: %s" % safe, file=sys.stderr)


class Counted:
    """``frames`` as they are, ``count`` counting each one taken, so a copy
    that ends by an exception still knows how far it got. ``close()`` closes
    the source, started or not."""

    def __init__(self, frames: Iterable[DissectedFrame]) -> None:
        self._frames = frames
        self._iterator: Iterator[DissectedFrame] = iter(frames)
        self.count = 0

    def __iter__(self) -> "Counted":
        return self

    def __next__(self) -> DissectedFrame:
        frame = next(self._iterator)
        self.count += 1
        return frame

    def close(self) -> None:
        sources: List[object] = [self._iterator]
        if self._frames is not self._iterator:
            sources.append(self._frames)
        for source in sources:
            close = getattr(source, "close", None)
            if close is not None:
                close()


class Loading(LoggingArgs, Cmd):
    """The options of a command that loads plugins into a registry of its own."""

    _logger_name_ = "pktcap"
    #: Plugins this command always loads, before the user's list: dotted names
    #: as ``--load`` takes them. Code's, never read from an argument.
    _plugins_: ClassVar[Tuple[str, ...]] = ()

    plugins: Optional[List[str]] = None
    "Plugins to load, each a dotted module name or MODULE.CALLABLE; repeat the option, or separate by , ; : or space; none for no plugin. Omitted: PKTCAP_LOAD, then the configuration file, then none. A tool call cannot name it"
    ("--load",)

    plugin_config: Optional[str] = None
    "The configuration file whose load key lists the plugins, read as it is; none for no file. Omitted: PKTCAP_CONFIG, then the user's own pktcap/pktcap.ini if there is one. A tool call cannot name it"
    ("--config", "-c")

    def served(self) -> bool:
        """Whether this is a tool call: duho runs one with standard output
        replaced by a text stream, which has no ``buffer``."""
        return getattr(sys.stdout, "buffer", None) is None

    def _origin(self, field: str) -> str:
        """Where the value of a field came from, by duho's record of the
        layers: ``"environment"`` (a variable a root reads), ``"file"`` (a
        settings file a root reads) or ``"argument"``, which also covers a
        value the class or the code that built the command gave."""
        layer = value_sources(self).get(field)
        return {"env": "environment", "config": "file"}.get(layer or "", "argument")

    def _taken_from(self, field: str, layers: Tuple[str, ...]) -> None:
        """``ValueError`` unless the field's value came from one of ``layers``."""
        layer = self._origin(field)
        if layer not in layers:
            raise ValueError(
                "--%s was set from the %s layer of a root's configuration; this "
                "command takes it from: %s" % (field, layer, ", ".join(layers))
            )

    def _registry(self) -> DissectorRegistry:
        """A registry of this run's own, with the plugins loaded into it:
        ``_plugins_`` first, then the user's list.

        A tool call's arguments may come from text a capture held, so a tool
        call names no plugin and no file: the server's own variable and the
        user's own file decide. A root's own settings file or variable is no
        more the user's than a tool call is, so a list that reached the field
        from one is refused too.
        """
        for field in ("plugins", "plugin_config"):
            layer = self._origin(field)
            if getattr(self, field) is not None and layer != "argument":
                raise ValueError(
                    "%s was set from the %s layer of a root's configuration: the "
                    "plugin list comes from --load, PKTCAP_LOAD or pktcap's own "
                    "file" % (field, layer)
                )
        if self.served() and (
            self.plugins is not None or self.plugin_config is not None
        ):
            raise ValueError(
                "a tool call cannot name plugins or a configuration file: the "
                "server's PKTCAP_LOAD and the user's own file decide"
            )
        registry = DissectorRegistry()
        self.loaded: Tuple[LoadedPlugin, ...] = load_plugins(
            registry,
            self.plugins,
            config=self.plugin_config,
            always=self._plugins_,
        )
        return registry


class Selecting(Loading):
    """The options every command that selects frames has."""

    #: The subclass's own clauses, in the filter's grammar; ANDed with
    #: ``--filter``.
    _filter_: ClassVar[Optional[str]] = None

    filter: Optional[str] = None
    "Keep only frames matching `key=value and key!=value` clauses over src, dst, host, sport, dport, port, proto, vlan, linktype and LAYER.FIELD; the plugins command lists every key. Omitted: every frame"
    ("--filter", "-f")

    def _select(self, registry: DissectorRegistry) -> Callable[[DissectedFrame], bool]:
        """The compiled ``--filter`` over the registry's layers and keys, and
        ``_filter_`` with it; a bad expression is a usage error."""
        frame_filter = frame_filter_for(registry)
        own = compile_capture_filter(self._filter_, frame_filter)
        user = compile_capture_filter(self.filter, frame_filter)
        if self._filter_ is None:
            return user
        return lambda frame: own(frame) and user(frame)
