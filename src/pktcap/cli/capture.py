"""``pktcap capture``: frames seen live on Linux, or datagrams arriving at
sockets, written as they arrive."""

from __future__ import annotations

import logging
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
from netimps import UDPEndpoint, bind_error_hint, bind_listen, parse_listen

from .._dissect import DissectedFrame, FrameDissector
from .._exceptions import LiveCaptureError
from .._formats import RECORD_FORMATS
from .._live import has_live_capture, sniff_frames
from .._sources import sniff_udp
from ._hooks import make_hook
from ._writing import Writing

__all__ = ["Capture"]

_LOG = logging.getLogger(__name__)

_NOT_LINUX = (
    "live capture needs Linux (AF_PACKET); pipe a capture tool's output in "
    "instead: tcpdump -w - | pktcap convert --input -"
)
_NO_PERMISSION = (
    "opening a packet socket needs the CAP_NET_RAW capability: run as root, or "
    "grant it to the interpreter (setcap cap_net_raw+ep)"
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
    #: The layers ``--hook`` may come from: ``"argument"``, ``"environment"``
    #: (a variable a root reads) and ``"file"`` (a settings file a root reads).
    #: A hook runs code, so by default the command line is the only one.
    _hook_from_: ClassVar[Tuple[str, ...]] = ("argument",)

    interface: Annotated[Optional[str], Meta(conflicts="source")] = None
    "The interface to capture on, by name, address or MAC. Omitted: every interface. Excludes --listen"
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
        if self._until is None:
            self._until = self._deadline()
        return self._until is not None and time.monotonic() >= self._until

    def _endpoints(self) -> Tuple[UDPEndpoint, ...]:
        """The sockets ``--listen`` names, bound by ``netimps.bind_listen`` and
        owned by the capture from the moment they are returned."""
        return bind_listen(self._listening())

    def _frames(self, dissector: FrameDissector) -> Iterator[DissectedFrame]:
        self._until = self._deadline()
        stop = self._stop
        if self.listen is not None:
            endpoints = self._bound()
            try:
                self._source = sniff_udp(endpoints, stop=stop, dissector=dissector)
            except BaseException:
                for endpoint in endpoints:  # the source turned them away
                    getattr(endpoint, "close", lambda: None)()
                raise
            return self._source  # type: ignore[no-any-return]
        if not has_live_capture():
            raise LiveCaptureError(_NOT_LINUX)
        return self._permitted(
            sniff_frames(self.interface, stop=stop, dissector=dissector)
        )

    def _hook(self) -> Optional[Callable[[DissectedFrame], object]]:
        if self.hook is None:
            return None
        if self.served():
            raise ValueError("a tool call cannot name a hook")
        self._taken_from("hook", self._hook_from_)
        name = self._written()
        self._hooked = make_hook(
            self.hook,
            format=name if name in RECORD_FORMATS else "json",
            timeout=self.hook_timeout,
            fail_fast=self.hook_fail_fast,
            names=self._names,
            datagrams=self.datagrams,
        )
        hooked: Callable[[DissectedFrame], object] = self._hooked
        return hooked

    # -- private ----------------------------------------------------------

    _until: Optional[float] = None
    _hooked: Any = None
    _source: Any = None

    def _deadline(self) -> Optional[float]:
        if self.duration is None:
            return None
        if not self.duration >= 0:
            raise ValueError("--duration must not be below zero")
        return time.monotonic() + self.duration

    def _listening(self) -> Any:
        """The specification ``--listen`` writes, read but not bound."""
        ports = self._default_port_
        return parse_listen(self.listen, () if ports is None else ports)

    def _bound(self) -> Tuple[UDPEndpoint, ...]:
        """``_endpoints()``, a failure of which is one line naming what was
        asked for."""
        try:
            endpoints = self._endpoints()
        except OSError as exc:
            asked = (
                self.listen
                if isinstance(self.listen, str)
                else ", ".join(str(item) for item in self.listen or ())
            )
            raise OSError(
                "cannot listen on %s: %s" % (asked, bind_error_hint(exc) or exc)
            ) from exc
        _LOG.info(
            "listening on %s",
            ", ".join("%s:%d" % e.socket.getsockname()[:2] for e in endpoints),
        )
        return endpoints

    def _permitted(self, frames: Iterator[DissectedFrame]) -> Iterator[DissectedFrame]:
        try:
            yield from frames
        except PermissionError:
            raise PermissionError(_NO_PERMISSION) from None

    def _noted(self) -> List[str]:
        parts = []
        for attribute, text in (
            ("not_admitted", "%d not admitted"),
            ("truncated", "%d over the size limit"),
        ):
            count = getattr(self._source, attribute, 0)
            if count:
                parts.append(text % count)
        failures = getattr(self._hooked, "failures", 0)
        if failures:
            parts.append("%d hook failures" % failures)
        return parts
