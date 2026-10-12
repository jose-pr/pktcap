"""``pktcap capture``: frames seen live on Linux, or datagrams arriving at
sockets, written as they arrive."""

from __future__ import annotations

import time
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Iterator,
    List,
    Optional,
    Tuple,
    Union,
)

from duho import Meta
from netimps import ListenLike, UDPEndpoint, bind_listen, parse_listen

from .._dissect import DissectedFrame, FrameDissector
from .._exceptions import LiveCaptureError
from .._formats import RECORD_FORMATS
from .._live import has_live_capture, sniff_frames
from .._sources import sniff_udp
from ._binding import bound, permitted
from ._hooks import make_hook
from ._writing import Writing

__all__ = ["Capture"]

_NOT_LINUX = (
    "live capture needs Linux (AF_PACKET); pipe a capture tool's output in "
    "instead: tcpdump -w - | %s convert --input -"
)


class Capture(Writing):
    """Capture frames live from an interface (Linux, needs CAP_NET_RAW) or the datagrams that arrive at UDP ports (any platform, no privilege) and write them; Ctrl-C ends it with status 0. It sends nothing."""

    _parsername_ = "capture"
    # Runs until stopped and needs a privilege or a port: not a call a program
    # makes by accident.
    _mcp_ = False
    _interruptible_ = True
    #: The port ``--listen`` gives a value that names none: an ``int``, a tuple
    #: of them, or ``None`` for no default (such a value is then refused).
    _default_port_: ClassVar[Union[None, int, Tuple[int, ...]]] = None
    #: What the command listens on when neither ``--listen`` nor ``--interface``
    #: is given, as ``--listen`` reads it; ``None``: capture from every
    #: interface.
    _listen_: ClassVar[ListenLike] = None
    #: The layers ``--hook`` may come from: ``"argument"``, ``"environment"``
    #: (a variable a root reads) and ``"file"`` (a settings file a root reads).
    #: A hook runs code, so by default the command line is the only one.
    _hook_from_: ClassVar[Tuple[str, ...]] = ("argument",)

    interface: Annotated[Optional[str], Meta(conflicts="source")] = None
    "The interface to capture on, by name, address or MAC. Omitted: every interface. Cannot be combined with another source of datagrams"
    ("--interface",)

    listen: Annotated[Optional[List[str]], Meta(conflicts="source")] = None
    "Capture the datagrams that arrive at this address and port instead of an interface: HOST:PORT, [V6]:PORT, *:PORT, an adapter name or a MAC; repeat the option or separate by commas. Excludes --interface"
    ("--listen",)

    count: Optional[int] = None
    "Stop once this many records are written. Omitted: run until stopped"
    ("--count",)

    duration: Optional[float] = None
    "Stop after this many seconds, within a second of it. Omitted: run until stopped"
    ("--duration", "-d")

    hook: Optional[str] = None
    "Run this program (or MODULE:FUNCTION) for each record written, with the record on standard input. A tool call cannot name it. Omitted: none"
    ("--hook",)

    hook_fail_fast: bool = False
    "End the capture, status 1, at the first failed hook. Omitted: count the failures and go on"
    ("--hook-fail-fast",)

    hook_timeout: float = 10.0
    "Seconds a hook program may run before it and what it started are killed. A Python MODULE:FUNCTION is not bounded by it"
    ("--hook-timeout",)

    # -- the points a subclass overrides ---------------------------------

    def _limit(self) -> Optional[int]:
        return self.count

    def _stop(self) -> bool:
        """Whether the ``--duration`` has passed; called between datagrams and
        at least once a second on a quiet source."""
        if self._pk_until is None:
            self._pk_until = self._pk_deadline()
        return self._pk_until is not None and time.monotonic() >= self._pk_until

    def _endpoints(self, dissector: FrameDissector) -> Tuple[UDPEndpoint, ...]:
        """The sockets to listen on, bound by ``netimps.bind_listen`` and owned
        by the capture from the moment they are returned. ``dissector`` reads
        the frames they feed: register a protocol on a bound port in its
        registry."""
        return bind_listen(self._pk_listening())

    def _frames(self, dissector: FrameDissector) -> Iterator[DissectedFrame]:
        self._pk_until = self._pk_deadline()
        stop = self._stop
        if self.listen is not None or (
            self.interface is None and self._listen_ is not None
        ):
            endpoints = self._pk_bound(dissector)
            try:
                self._pk_source = sniff_udp(endpoints, stop=stop, dissector=dissector)
            except BaseException:
                for endpoint in endpoints:  # the source turned them away
                    getattr(endpoint, "close", lambda: None)()
                raise
            return self._pk_source  # type: ignore[no-any-return]
        if not has_live_capture():
            raise LiveCaptureError(_NOT_LINUX % self._pk_program())
        return permitted(sniff_frames(self.interface, stop=stop, dissector=dissector))

    def _hook(self) -> Optional[Callable[[DissectedFrame], object]]:
        if self.hook is None:
            return None
        if self.served():
            raise ValueError("a tool call cannot name a hook")
        self._pk_taken_from("hook", self._hook_from_)
        name = self._pk_written()
        self._pk_hooked = make_hook(
            self.hook,
            format=name if name in RECORD_FORMATS else "json",
            timeout=self.hook_timeout,
            fail_fast=self.hook_fail_fast,
            names=self._names,
            datagrams=self.datagrams,
        )
        hooked: Callable[[DissectedFrame], object] = self._pk_hooked
        return hooked

    # -- private ----------------------------------------------------------

    _pk_until: Optional[float] = None
    _pk_hooked: Any = None
    _pk_source: Any = None

    def _pk_deadline(self) -> Optional[float]:
        if self.duration is None:
            return None
        if not self.duration >= 0:
            raise ValueError("--duration must not be below zero")
        return time.monotonic() + self.duration

    def _pk_listening(self) -> Any:
        """The specification to listen on, read but not bound: ``--listen``,
        else ``_listen_``."""
        ports = self._default_port_
        spec = self._listen_ if self.listen is None else self.listen
        return parse_listen(spec, () if ports is None else ports)

    def _pk_bound(self, dissector: FrameDissector) -> Tuple[UDPEndpoint, ...]:
        """``_endpoints()``, a failure of which is one line naming what was
        asked for."""
        asked = self.listen if self.listen is not None else self._listen_
        if isinstance(asked, (list, tuple)):
            asked = ", ".join(str(item) for item in asked)
        return bound(lambda: self._endpoints(dissector), str(asked))

    def _pk_noted(self) -> List[str]:
        parts = []
        for attribute, text in (
            ("not_admitted", "%d not admitted"),
            ("truncated", "%d over the size limit"),
        ):
            count = getattr(self._pk_source, attribute, 0)
            if count:
                parts.append(text % count)
        failures = getattr(self._pk_hooked, "failures", 0)
        if failures:
            parts.append("%d hook failures" % failures)
        return parts
