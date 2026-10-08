"""The default records: a datagram, or a dissected frame, as plain data
(internal).

For a caller with no protocol of its own to describe what was captured. A
protocol library passes its own record instead.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

from netimps import join_host

from ._captured import CapturedDatagram
from ._dissect import DissectedFrame
from ._layers import layer_name

__all__ = ["datagram_record", "frame_record"]


def datagram_record(datagram: CapturedDatagram) -> Dict[str, Any]:
    """The record of a datagram for a caller with no protocol to decode it:
    ``time``, ``source``, ``destination``, ``length`` and ``payload`` as hex,
    plus ``fragmented`` or ``truncated`` when the datagram is partial.

    ``source`` and ``destination`` are ``host:port`` text, an IPv6 host in
    brackets. ``time`` is the number of seconds the capture states.
    """
    record: Dict[str, Any] = {
        "time": datagram.time,
        "source": join_host(datagram.source[0], datagram.source[1]),
        "destination": join_host(datagram.destination[0], datagram.destination[1]),
        "length": len(datagram.payload),
        "payload": datagram.payload.hex(),
    }
    if datagram.fragmented:
        record["fragmented"] = True
    if datagram.truncated:
        record["truncated"] = True
    return record


def _plain(value: object) -> Any:
    """A layer field as plain data: octets become hex text."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return str(value)


def _layer_record(layer: object) -> Dict[str, Any]:
    record: Dict[str, Any] = {"layer": layer_name(layer)}
    as_dict = getattr(layer, "_asdict", None)
    if callable(as_dict):  # a named tuple, as the built-in layers are
        fields = as_dict()
    elif isinstance(layer, Mapping):
        fields = layer
    else:
        fields = {"value": layer}
    for key, value in fields.items():
        record[str(key)] = _plain(value)
    return record


def frame_record(frame: DissectedFrame) -> Dict[str, Any]:
    """The record of a dissected frame: ``time``, ``linktype``, ``length``
    (of the captured frame), ``layers`` and ``payload``.

    ``layers`` is a list, outermost first, of one mapping per layer: ``layer``
    is its name (``ethernet``, ``ipv4``, ``udp``: the class name without
    ``Layer``, in lower case) and the rest are its fields, octets as hex.
    ``payload`` is the hex of what no dissector read. ``interface``,
    ``error`` and ``reassembled`` appear only when they say something.
    """
    record: Dict[str, Any] = {
        "time": frame.frame.time,
        "linktype": frame.frame.linktype,
        "length": len(frame.frame.data),
        "layers": [_layer_record(layer) for layer in frame.layers],
        "payload": frame.payload.hex(),
    }
    if frame.frame.interface is not None:
        record["interface"] = frame.frame.interface
    if frame.error is not None:
        record["error"] = frame.error
    if frame.reassembled:
        record["reassembled"] = True
    return record
