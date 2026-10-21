"""What the commands share: the plugins, the filter and the diagnostic line."""

from __future__ import annotations

import sys
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
)

from duho import Cmd, LoggingArgs, Meta, app_name, running_mode, value_sources

from .._dissect import DissectedFrame
from .._dissectors import DissectorRegistry
from .._filter import compile_capture_filter
from .._frame_filter import frame_filter_for
from .._plugins._config import PLUGINS_ARGUMENT
from .._plugins._load import LoadedPlugin, load_named
from ._settings import file_read

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
    #: The layers ``--load`` may come from: ``"argument"``, ``"environment"``
    #: (``PKTCAP_LOAD``) and ``"file"`` (the settings file the root read). A
    #: list is code a module will run, so a class names the layers it trusts.
    _load_from_: ClassVar[Tuple[str, ...]] = ("argument", "environment", "file")
    #: When set (``"MYPROG_CAPTURE_"``), every option of the class that names no
    #: variable of its own, inherited ones among them, takes the variable made
    #: of this prefix and its field name in upper case, as duho's
    #: ``_env_prefix_`` does. The logging options are the root's and get none.
    _env_prefix_: ClassVar[Optional[str]] = None

    load: Annotated[Optional[List[str]], Meta(env="PKTCAP_LOAD")] = None
    "Plugins to load, each a dotted module name or MODULE.CALLABLE; repeat the option, or separate by , ; : or space; none for no plugin. Omitted: PKTCAP_LOAD, then the settings file, then none. A tool call cannot name it"
    ("--load",)

    def served(self) -> bool:
        """Whether this is a tool call: duho's ``running_mode()`` says ``"mcp"``."""
        return bool(running_mode() == "mcp")

    def _pk_program(self) -> str:
        """The name of the program that runs this command, as duho gives it."""
        words = app_name(self).split()
        return words[0] if words else "the program"

    def _pk_origin(self, field: str) -> str:
        """Where the value of a field came from, by duho's record of the
        layers: ``"environment"`` (a variable), ``"file"`` (the settings file
        the root read) or ``"argument"``, which also covers a value the class
        or the code that built the command gave."""
        layer = value_sources(self).get(field)
        return {"env": "environment", "config": "file"}.get(layer or "", "argument")

    def _pk_taken_from(self, field: str, layers: Tuple[str, ...]) -> None:
        """``ValueError`` unless the field's value came from one of ``layers``."""
        layer = self._pk_origin(field)
        if layer not in layers:
            raise ValueError(
                "--%s was set from the %s layer of a root's configuration; this "
                "command takes it from: %s" % (field, layer, ", ".join(layers))
            )

    def _pk_list_source(self) -> str:
        """How the list names where it came from: ``argument``, the variable's
        name, or the settings file's path."""
        layer = self._pk_origin("load")
        if layer == "environment":
            return str(next(b.env for b in type(self)._getargs_() if b.name == "load"))
        if layer == "file":
            return file_read() or "file"
        return PLUGINS_ARGUMENT

    def _pk_registry(self) -> DissectorRegistry:
        """A registry of this run's own, with the plugins loaded into it:
        ``_plugins_`` first, then the user's list.

        A tool call's arguments may come from text a capture held, so a tool
        call names no list: the server's own variable decides. A list from a
        layer ``_load_from_`` does not name is refused before anything is
        imported.
        """
        if self.load is not None:
            if self.served() and self._pk_origin("load") == "argument":
                raise ValueError(
                    "a tool call cannot name plugins: the server's PKTCAP_LOAD decides"
                )
            self._pk_taken_from("load", self._load_from_)
        registry = DissectorRegistry()
        self.loaded: Tuple[LoadedPlugin, ...] = load_named(
            registry, self.load, self._pk_list_source(), self._plugins_
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
