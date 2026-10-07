"""How the text of a filter clause is compared with a layer field (internal).

A field is compared by the type of the value it holds in the frame. The value
comes from a capture, so every walk into it is bounded: a path of at most
:data:`MAX_SEGMENTS` segments, at most :data:`MAX_ITEMS` list items or mapping
keys looked at, and nothing is evaluated, imported or formatted into a path.
"""

from __future__ import annotations

import enum
import itertools
import re
from typing import Any, FrozenSet, List, Mapping, Optional, Tuple

from netimps import IPNetwork, parse, unmap

__all__ = ["MAX_ITEMS", "MAX_SEGMENTS", "Wanted"]

#: The most segments in a filter key, the layer's name included.
MAX_SEGMENTS = 8
#: The most items of a list, and keys of a mapping, one comparison looks at.
MAX_ITEMS = 1024
#: The longest text read as a number, and as an address from a field.
_MAX_NUMBER_TEXT = 64
_MAX_ADDRESS_TEXT = 64

_BOOLEANS = {
    "1": True,
    "true": True,
    "yes": True,
    "on": True,
    "0": False,
    "false": False,
    "no": False,
    "off": False,
}
_NUMBER = re.compile(r"(?:0[xX]([0-9a-fA-F]+)|0[oO]([0-7]+)|0[bB]([01]+)|([0-9]+))\Z")
_OCTET_GROUP = re.compile(r"(?:[0-9a-fA-F]{2})+\Z")
_MISSING = object()


def parse_number(text: str) -> Optional[int]:
    """``text`` as an integer: decimal (leading zeros allowed) or with a
    ``0x``, ``0o`` or ``0b`` prefix; ``None`` for anything else."""
    if len(text) > _MAX_NUMBER_TEXT or not text.isascii():
        return None
    found = _NUMBER.match(text)
    if found is None:
        return None
    for group, base in zip(found.groups(), (16, 8, 2, 10)):
        if group is not None:
            return int(group, base)
    return None  # pragma: no cover - the pattern has four groups


def parse_boolean(text: str) -> Optional[bool]:
    """``text`` as a flag: ``1 true yes on`` or ``0 false no off``, any case."""
    return _BOOLEANS.get(text.lower())


def parse_octets(text: str) -> Optional[bytes]:
    """``text`` as octets: hexadecimal, ``:``, ``-`` or ``.`` allowed between
    groups of two digits or more; ``None`` for anything else."""
    if not text.isascii():
        return None
    groups = re.split(r"[:.\-]", text)
    if not all(_OCTET_GROUP.match(group) for group in groups):
        return None
    return bytes.fromhex("".join(groups))


def _network(text: str) -> Optional[IPNetwork]:
    try:
        return parse(text, IPNetwork)
    except ValueError:
        return None


class Wanted:
    """The values of one clause, converted once, to compare with field values."""

    def __init__(self, texts: Tuple[str, ...]) -> None:
        self.lowered: FrozenSet[str] = frozenset(text.lower() for text in texts)
        self.numbers: FrozenSet[int] = frozenset(
            number for number in map(parse_number, texts) if number is not None
        )
        self.booleans: FrozenSet[bool] = frozenset(
            flag for flag in map(parse_boolean, texts) if flag is not None
        )
        self.octets: FrozenSet[bytes] = frozenset(
            raw for raw in map(parse_octets, texts) if raw is not None
        )
        networks: List[IPNetwork] = []
        for text in texts:
            network = _network(text)
            if network is not None:
                networks.append(network)
        self.networks: Tuple[IPNetwork, ...] = tuple(networks)

    def matches(self, value: Any, path: Tuple[str, ...] = ()) -> bool:
        """Whether ``value``, reached through ``path`` (the segments of the
        key after the field), is one of the wanted values."""
        if isinstance(value, bool):
            return not path and value in self.booleans
        if isinstance(value, enum.Enum):
            return not path and (
                value.name.lower() in self.lowered or self.matches(value.value)
            )
        if isinstance(value, int):
            return not path and value in self.numbers
        if isinstance(value, str):
            return not path and self._text(value)
        if isinstance(value, (bytes, bytearray)):
            return not path and bytes(value) in self.octets
        if isinstance(value, Mapping):
            if not path:
                return False
            found = _lookup(value, path[0])
            return found is not _MISSING and self.matches(found, path[1:])
        if isinstance(value, (list, tuple)):
            if path:
                head = path[0]
                if not (head.isascii() and head.isdigit() and len(head) <= 9):
                    return False
                index = int(head)
                return index < len(value) and self.matches(value[index], path[1:])
            return any(
                self.matches(item)
                for item in itertools.islice(value, MAX_ITEMS)
                if not isinstance(item, (list, tuple, Mapping))
            )
        if value is None:
            return False
        return not path and str(value).lower() in self.lowered

    def _text(self, value: str) -> bool:
        if value.lower() in self.lowered:
            return True
        if not self.networks or len(value) > _MAX_ADDRESS_TEXT:
            return False
        try:
            # A v4-mapped address is the IPv4 host it stands for.
            address = unmap(value)
        except ValueError:
            return False
        return any(
            address.version == network.version and address in network
            for network in self.networks
        )


def _lookup(mapping: Mapping[Any, Any], name: str) -> Any:
    """The value under ``name``: the key exactly, else ignoring case among the
    first :data:`MAX_ITEMS` keys, compared as text."""
    if name in mapping:
        return mapping[name]
    lowered = name.lower()
    for key in itertools.islice(mapping, MAX_ITEMS):
        if str(key).lower() == lowered:
            return mapping[key]
    return _MISSING
