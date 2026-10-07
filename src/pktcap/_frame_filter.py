"""The filter keys the built-in layers answer (internal).

:func:`frame_filter` is a ready ``build`` for
:func:`pktcap.compile_capture_filter` over dissected frames, so a caller is
not made to write the obvious keys. :func:`frame_filter_for` is the same for
a registry whose layers and keys a plugin declared.
"""

from __future__ import annotations

from typing import Callable, FrozenSet, List, Optional, Tuple

from netimps import IPNetwork, parse, unmap

from ._dissect import DissectedFrame
from ._dissectors import DissectorRegistry
from ._filter import FilterClause
from ._layers import IPv4Layer, IPv6Layer, TCPLayer, UDPLayer, VLANLayer
from ._plugins._keys import Guard, build_test, list_keys

__all__ = [
    "FRAME_FILTER_KEYS",
    "frame_filter",
    "frame_filter_for",
    "frame_filter_keys",
]

#: The keys :func:`frame_filter` knows.
FRAME_FILTER_KEYS: Tuple[str, ...] = (
    "src",
    "dst",
    "host",
    "sport",
    "dport",
    "port",
    "proto",
    "vlan",
    "linktype",
)

Predicate = Callable[[DissectedFrame], bool]


def _numbers(clause: FilterClause, most: int) -> FrozenSet[int]:
    numbers = set()
    for value in clause.values:
        if not (value.isascii() and value.isdigit()) or int(value) > most:
            raise ValueError(
                "%s takes numbers from 0 to %d, not %r" % (clause.key, most, value)
            )
        numbers.add(int(value))
    return frozenset(numbers)


def _addresses(frame: DissectedFrame) -> Optional[Tuple[str, str]]:
    for layer in frame.layers:
        if isinstance(layer, (IPv4Layer, IPv6Layer)):
            return layer.source, layer.destination
    return None


def _ports(frame: DissectedFrame) -> Optional[Tuple[int, int]]:
    for layer in frame.layers:
        if isinstance(layer, (UDPLayer, TCPLayer)):
            return layer.source_port, layer.destination_port
    return None


def _layer_name(layer: object) -> str:
    name = type(layer).__name__
    return (name[:-5] if name.endswith("Layer") and len(name) > 5 else name).lower()


def _address_test(clause: FilterClause) -> Predicate:
    networks: List[IPNetwork] = [parse(value, IPNetwork) for value in clause.values]
    which = clause.key.lower()

    def inside(text: str) -> bool:
        # A v4-mapped address is the IPv4 host it stands for.
        address = unmap(text)
        return any(
            address.version == network.version and address in network
            for network in networks
        )

    def test(frame: DissectedFrame) -> bool:
        ends = _addresses(frame)
        if ends is None:
            return False
        if which == "src":
            return inside(ends[0])
        if which == "dst":
            return inside(ends[1])
        return inside(ends[0]) or inside(ends[1])

    return test


def _answer(
    clause: FilterClause, registry: Optional[DissectorRegistry], guard: Guard
) -> Predicate:
    if not clause.values:
        raise ValueError("%s has no value" % clause.key)
    if clause.key.lower() not in FRAME_FILTER_KEYS:
        return build_test(clause, registry, FRAME_FILTER_KEYS, guard)
    return _builtin(clause)


def frame_filter(clause: FilterClause) -> Predicate:
    """The test of one filter clause against a :class:`DissectedFrame`.

    A comma in the value means "any of". The keys:

    ``src``, ``dst``, ``host``
        the source, the destination, or either address of the outermost IP
        layer: an address or a network (``10.0.0.5``, ``10.0.0.0/8``,
        ``2001:db8::/32``).
    ``sport``, ``dport``, ``port``
        the source, the destination, or either port of the UDP or TCP layer.
    ``proto``
        a layer the frame has, by name (``udp``, ``tcp``, ``ipv4``, ``ipv6``,
        ``vlan``, ``ethernet``, or the name of a registered dissector's layer:
        its class name in lower case, without a trailing ``Layer``), or an IP
        protocol number (``17``).
    ``vlan``
        a VLAN identifier on any tag of the frame.
    ``linktype``
        the capture's link-type number.
    ``LAYER.FIELD``
        a field of a built-in layer (``ipv4.ttl``, ``udp.destination_port``),
        compared by the type of its value.

    :raises ValueError: a key that is none of these, or a value that is not
        what the key takes. :func:`compile_capture_filter` turns it into a
        ``CaptureFilterError`` naming the clause.
    """
    return _answer(clause, None, Guard())


def frame_filter_for(
    registry: DissectorRegistry,
) -> Callable[[FilterClause], Predicate]:
    """The ``build`` of :func:`compile_capture_filter` for a registry: the
    keys of :func:`frame_filter`, plus ``LAYER.KEY`` and ``LAYER.FIELD`` of
    every layer the registry declares, and a registered key by its bare name
    while exactly one layer has it.

    :raises TypeError: ``registry`` is not a :class:`DissectorRegistry`.
    """
    if not isinstance(registry, DissectorRegistry):
        raise TypeError("frame_filter_for takes a DissectorRegistry")
    guard = Guard()

    def build(clause: FilterClause) -> Predicate:
        return _answer(clause, registry, guard)

    return build


def frame_filter_keys(registry: Optional[DissectorRegistry] = None) -> Tuple[str, ...]:
    """Every filter key that compiles, sorted: the built-in ones, each
    ``LAYER.KEY`` and ``LAYER.FIELD`` of the built-in layers and of the
    registry's, and the bare form of a registered key exactly one layer has.

    :raises TypeError: ``registry`` is neither ``None`` nor a registry.
    """
    if registry is not None and not isinstance(registry, DissectorRegistry):
        raise TypeError("frame_filter_keys takes a DissectorRegistry or None")
    return list_keys(registry, FRAME_FILTER_KEYS)


def _builtin(clause: FilterClause) -> Predicate:
    key = clause.key.lower()
    if key in ("src", "dst", "host"):
        return _address_test(clause)
    if key in ("sport", "dport", "port"):
        ports = _numbers(clause, 65535)

        def port_test(frame: DissectedFrame) -> bool:
            ends = _ports(frame)
            if ends is None:
                return False
            if key == "sport":
                return ends[0] in ports
            if key == "dport":
                return ends[1] in ports
            return ends[0] in ports or ends[1] in ports

        return port_test
    if key == "proto":
        names = frozenset(value.lower() for value in clause.values)
        numbers = frozenset(int(v) for v in names if v.isascii() and v.isdigit())

        def proto_test(frame: DissectedFrame) -> bool:
            for layer in frame.layers:
                if _layer_name(layer) in names:
                    return True
                if isinstance(layer, IPv4Layer) and layer.protocol in numbers:
                    return True
                if isinstance(layer, IPv6Layer) and layer.next_header in numbers:
                    return True
            return False

        return proto_test
    if key == "vlan":
        identifiers = _numbers(clause, 4095)
        return lambda frame: any(
            isinstance(layer, VLANLayer) and layer.id in identifiers
            for layer in frame.layers
        )
    if key == "linktype":
        linktypes = _numbers(clause, 65535)
        return lambda frame: frame.frame.linktype in linktypes
    raise AssertionError(key)  # pragma: no cover - _answer passes the nine keys only
