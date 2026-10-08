"""What the commands share: the plugins, the filter and the diagnostic line."""

from __future__ import annotations

import sys
from typing import Callable, Generator, Iterable, List, Optional, Tuple

from duho import Cmd, LoggingArgs

from .._dissect import DissectedFrame
from .._dissectors import DissectorRegistry
from .._filter import compile_capture_filter
from .._frame_filter import frame_filter_for
from .._plugins._load import LoadedPlugin, load_plugins

__all__ = ["Base", "Loading", "counted", "error"]


def error(text: str) -> None:
    """One diagnostic line on stderr; a control character in it is escaped."""
    safe = "".join(c if c.isprintable() else repr(c)[1:-1] for c in text)
    print("pktcap: error: %s" % safe, file=sys.stderr)


def counted(
    frames: Iterable[DissectedFrame], tally: List[int]
) -> Generator[DissectedFrame, None, None]:
    """``frames`` as they are, ``tally[0]`` counting each one taken, so a copy
    that ends by an exception still knows how far it got."""
    try:
        for frame in frames:
            tally[0] += 1
            yield frame
    finally:
        close = getattr(frames, "close", None)
        if close is not None:
            close()


class Loading(LoggingArgs, Cmd):
    """The options of a command that loads plugins into a registry of its own."""

    _logger_name_ = "pktcap"

    plugins: Optional[List[str]] = None
    "Plugins to load, each a dotted module name or MODULE.CALLABLE; repeat the option, or separate by , ; : or space; none for no plugin. Omitted: PKTCAP_LOAD, then the configuration file, then none. A tool call cannot name it"
    ("--load",)

    config: Optional[str] = None
    "The configuration file whose load key lists the plugins, read as it is; none for no file. Omitted: PKTCAP_CONFIG, then the user's own pktcap/pktcap.ini if there is one. A tool call cannot name it"
    ("--config", "-c")

    def served(self) -> bool:
        """Whether this is a tool call: duho runs one with standard output
        replaced by a text stream, which has no ``buffer``."""
        return getattr(sys.stdout, "buffer", None) is None

    def _registry(self) -> DissectorRegistry:
        """A registry of this run's own, with the plugins loaded into it.

        A tool call's arguments may come from text a capture held, so a tool
        call names no plugin and no file: the server's own variable and the
        user's own file decide.
        """
        if self.served() and (self.plugins is not None or self.config is not None):
            raise ValueError(
                "a tool call cannot name plugins or a configuration file: the "
                "server's PKTCAP_LOAD and the user's own file decide"
            )
        registry = DissectorRegistry()
        self.loaded: Tuple[LoadedPlugin, ...] = load_plugins(
            registry, self.plugins, config=self.config
        )
        return registry


class Base(Loading):
    """The options every command has."""

    filter: Optional[str] = None
    "Keep only frames matching `key=value and key!=value` clauses over src, dst, host, sport, dport, port, proto, vlan, linktype and LAYER.FIELD; the plugins command lists every key. Omitted: every frame"
    ("--filter", "-f")

    def _select(self, registry: DissectorRegistry) -> Callable[[DissectedFrame], bool]:
        """The compiled ``--filter`` over the registry's layers and keys; a bad
        expression is a usage error."""
        return compile_capture_filter(self.filter, frame_filter_for(registry))
