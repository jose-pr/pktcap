"""What a capture does around the sockets it binds and the packet socket it opens."""

from __future__ import annotations

import logging
from typing import Callable, Iterator, Tuple

from netimps import UDPEndpoint, bind_error_hint

from .._dissect import DissectedFrame

__all__ = ["bound", "permitted"]

_LOG = logging.getLogger(__name__)

_NO_PERMISSION = (
    "opening a packet socket needs the CAP_NET_RAW capability: run as root, or "
    "grant it to the interpreter (setcap cap_net_raw+ep)"
)


def bound(
    endpoints: Callable[[], Tuple[UDPEndpoint, ...]], asked: str
) -> Tuple[UDPEndpoint, ...]:
    """``endpoints()``, an ``OSError`` of which is one line naming ``asked``."""
    try:
        found = endpoints()
    except OSError as exc:
        raise OSError(
            "cannot listen on %s: %s" % (asked, bind_error_hint(exc) or exc)
        ) from exc
    _LOG.info(
        "listening on %s",
        ", ".join("%s:%d" % e.socket.getsockname()[:2] for e in found),
    )
    return found


def permitted(frames: Iterator[DissectedFrame]) -> Iterator[DissectedFrame]:
    """``frames``, a ``PermissionError`` of which says what the capture needs."""
    try:
        yield from frames
    except PermissionError:
        raise PermissionError(_NO_PERMISSION) from None
