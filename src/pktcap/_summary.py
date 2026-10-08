"""A line a person reads for a frame or a datagram (internal).

A layer may say what it holds in one line with a ``summary()`` method; this
module puts the frame's time, its socket addresses, the name of its innermost
layer and that layer's summary together. Everything a capture can choose
ends up escaped to printable ASCII and the line is cut at a fixed length, so
it is safe on a terminal and in a log.
"""

from __future__ import annotations

import datetime
import logging
import math
import weakref
from typing import List, Optional, Tuple

from netimps import join_host

from ._captured import CapturedDatagram
from ._dissect import DissectedFrame
from ._layers import IPv4Layer, IPv6Layer, TCPLayer, UDPLayer, layer_name

__all__ = ["datagram_summary", "frame_summary"]

_LOG = logging.getLogger(__name__)

#: The most characters of a line.
MAX_LINE = 512
#: What a cut line ends with.
_MARK = "..."
#: How many layer classes whose summary failed are logged.
_MAX_LOGGED = 64
_LOGGED: "weakref.WeakSet[type]" = weakref.WeakSet()


def _escaped(character: str) -> str:
    if " " <= character <= "~" and character != "\\":
        return character
    return character.encode("unicode_escape").decode("ascii")


def _line(text: str) -> str:
    """``text`` as printable ASCII on one line, at most ``MAX_LINE``
    characters: a longer one ends in ``...`` after a whole escape. Only the
    first ``MAX_LINE + 1`` characters are looked at, since each is at least
    one character of the result."""
    pieces = [_escaped(character) for character in text[: MAX_LINE + 1]]
    whole = "".join(pieces)
    if len(whole) <= MAX_LINE:
        return whole
    kept: List[str] = []
    room = MAX_LINE - len(_MARK)
    for piece in pieces:
        if len(piece) > room:
            break
        kept.append(piece)
        room -= len(piece)
    return "".join(kept) + _MARK


def _time_text(time: float) -> str:
    """``time`` as UTC text. The capture controls it, so one outside any
    calendar is a count of seconds, and one that is no number ``unknown``."""
    try:
        moment = datetime.datetime.fromtimestamp(time, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        if math.isfinite(time) and abs(time) < 1 << 63:
            return "t%d" % int(time)
        return "unknown"
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _addresses(frame: DissectedFrame) -> str:
    """Both socket addresses of the outermost IP packet and its transport,
    hosts alone when there is no transport, and nothing without IP."""
    network: Optional[object] = None
    transport: Optional[object] = None
    for layer in frame.layers:
        if network is None and isinstance(layer, (IPv4Layer, IPv6Layer)):
            network = layer
        elif network is not None and isinstance(layer, (UDPLayer, TCPLayer)):
            transport = layer
            break
    if not isinstance(network, (IPv4Layer, IPv6Layer)):
        return ""
    if isinstance(transport, (UDPLayer, TCPLayer)):
        return "%s > %s" % (
            join_host(network.source, transport.source_port),
            join_host(network.destination, transport.destination_port),
        )
    return "%s > %s" % (network.source, network.destination)


def _failed(layer: object, what: str) -> None:
    """Log, once for the layer's class, that its summary failed."""
    kind = type(layer)
    if kind in _LOGGED or len(_LOGGED) >= _MAX_LOGGED:
        return
    _LOGGED.add(kind)
    _LOG.warning(
        "the summary of a %s layer %s; it is described by its name instead",
        _line(kind.__name__)[:60],
        what,
    )


def _summary_of(layer: object) -> str:
    """What the layer's ``summary()`` says, or ``""`` when it has none or it
    failed (raised, or gave something that is no text)."""
    method = getattr(layer, "summary", None)
    if not callable(method):
        return ""
    try:
        result = method()
    except Exception as exc:
        _failed(layer, "raised %s" % type(exc).__name__)
        return ""
    if not isinstance(result, str):
        _failed(layer, "returned %s" % type(result).__name__)
        return ""
    return result


def frame_summary(frame: DissectedFrame) -> str:
    """One line for a frame: its time (UTC), its two socket addresses when it
    has them, the name of its innermost layer and that layer's ``summary()``.

    A layer with no ``summary`` method, or whose ``summary()`` raises or gives
    something that is not text, is described by its name; the failure is
    logged once for the layer's class. Everything is escaped to printable
    ASCII on one line and cut at 512 characters (``...`` ends a cut line).

    :raises TypeError: ``frame`` is not a :class:`DissectedFrame`.
    """
    if not isinstance(frame, DissectedFrame):
        raise TypeError("frame must be a DissectedFrame")
    parts: Tuple[str, ...] = (_time_text(frame.frame.time), _addresses(frame))
    if frame.layers:
        layer = frame.layers[-1]
        name, text = layer_name(layer), _summary_of(layer)
        parts += ("%s: %s" % (name, text) if text else name,)
    else:
        parts += (
            "linktype %d, %d octets" % (frame.frame.linktype, len(frame.frame.data)),
        )
    return _line(" ".join(part for part in parts if part))


def datagram_summary(datagram: CapturedDatagram) -> str:
    """One line for a datagram: its time, both socket addresses and its size,
    and ``fragmented`` or ``truncated`` when it is partial. Escaped and cut as
    :func:`frame_summary` is."""
    size = len(datagram.payload)
    flags = ""
    if datagram.fragmented:
        flags += ", fragmented"
    if datagram.truncated:
        flags += ", truncated"
    return _line(
        "%s %s > %s udp %d octet%s%s"
        % (
            _time_text(datagram.time),
            join_host(datagram.source[0], datagram.source[1]),
            join_host(datagram.destination[0], datagram.destination[1]),
            size,
            "" if size == 1 else "s",
            flags,
        )
    )
