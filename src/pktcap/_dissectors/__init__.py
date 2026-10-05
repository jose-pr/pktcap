"""The dissectors and where they are found (internal).

A registry maps a selector, ``(kind, number)``, to the dissector that reads
what it selects. The built-in dissectors are one private module per layer; any
other protocol is registered by whoever needs it. Entry points are not read: a
capture decodes the same whatever else is installed, and a dissector is in a
registry only because some code put it there.
"""

from __future__ import annotations

import random
from typing import Dict, Iterable, Optional, Tuple

from ._contract import Dissected, Dissector, Fragment, Selector
from ._link import LINK_DISSECTORS
from ._network import NETWORK_DISSECTORS
from ._transport import TRANSPORT_DISSECTORS

__all__ = [
    "DissectorRegistry",
    "check_dissector",
    "default_registry",
    "register_dissector",
]


def _selector(kind: object, value: object) -> Selector:
    if not isinstance(kind, str) or not kind:
        raise TypeError("a selector's kind is a name, such as 'udp'")
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("a selector's value is an int, such as a port")
    return (kind, value)


class DissectorRegistry:
    """The dissectors one :class:`FrameDissector` chooses from.

    A selector is a kind and a number. The built-in kinds are ``linktype``
    (a capture's ``LINKTYPE_`` number), ``ethertype``, ``ip`` (an IP protocol
    number), ``udp`` and ``tcp`` (a port, the destination tried before the
    source). A dissector may name selectors of any other kind for what
    follows it, and whoever registers one of that kind is found.

    Two registries share nothing, so two users in one process do not collide:
    build one, register into it, and pass it to :class:`FrameDissector`.

    :param builtins: start with the built-in dissectors. ``False`` starts
        empty, for a caller that wants nothing decoded it did not choose.
    """

    def __init__(self, *, builtins: bool = True) -> None:
        self._dissectors: Dict[Selector, Dissector] = {}
        if builtins:
            for table in (LINK_DISSECTORS, NETWORK_DISSECTORS, TRANSPORT_DISSECTORS):
                self._dissectors.update(table)

    def register(
        self, kind: str, value: int, dissector: Dissector, *, replace: bool = False
    ) -> None:
        """Make ``dissector`` the one that reads what ``(kind, value)`` selects.

        :param replace: take the place of the dissector already there. Without
            it a selector that is taken is an error: two libraries claiming
            one port should find out when they register, not when a capture
            decodes as the wrong protocol.
        :raises ValueError: the selector is taken and ``replace`` is false.
        :raises TypeError: ``dissector`` cannot be called.
        """
        selector = _selector(kind, value)
        if not callable(dissector):
            raise TypeError("a dissector is a callable taking the layer's octets")
        if selector in self._dissectors and not replace:
            raise ValueError(
                "a dissector is already registered for %s %d; pass replace=True "
                "to take its place" % selector
            )
        self._dissectors[selector] = dissector

    def unregister(self, kind: str, value: int) -> None:
        """Forget the dissector for ``(kind, value)``; what it selected comes
        back undecoded. ``ValueError`` when there is none."""
        selector = _selector(kind, value)
        if selector not in self._dissectors:
            raise ValueError("no dissector is registered for %s %d" % selector)
        del self._dissectors[selector]

    def get(self, kind: str, value: int) -> Optional[Dissector]:
        """The dissector for ``(kind, value)``, or ``None``: a selector with
        no dissector is the ordinary end of a dissection, not an error."""
        return self._dissectors.get((kind, value))

    def selectors(self) -> Tuple[Selector, ...]:
        """Every selector with a dissector, sorted."""
        return tuple(sorted(self._dissectors))

    def copy(self) -> "DissectorRegistry":
        """A registry with the same dissectors that then changes on its own."""
        clone = DissectorRegistry(builtins=False)
        clone._dissectors.update(self._dissectors)
        return clone


_DEFAULT = DissectorRegistry()


def default_registry() -> DissectorRegistry:
    """The registry a :class:`FrameDissector` uses when given none.

    One object for the process: what is registered into it is seen by every
    caller that did not pass a registry of its own.
    """
    return _DEFAULT


def register_dissector(
    kind: str, value: int, dissector: Dissector, *, replace: bool = False
) -> None:
    """Register ``dissector`` in :func:`default_registry`. See
    :meth:`DissectorRegistry.register`."""
    _DEFAULT.register(kind, value, dissector, replace=replace)


def check_dissector(
    dissector: Dissector,
    samples: Iterable[bytes],
    *,
    rounds: int = 2000,
    seed: int = 0,
) -> None:
    """Assert that ``dissector`` keeps the contract whatever it is given.

    Each sample is tried as it is and then ``rounds`` times damaged (octets
    changed, the tail cut off). For every input the dissector must return a
    :class:`Dissected` whose payload is ``bytes`` and not longer than the
    input, or raise ``ValueError``. The suite the built-in dissectors pass, for a
    protocol library to run on its own.

    :raises AssertionError: the first input that broke the contract, as hex,
        and what came out of it.
    :raises ValueError: no sample was given.
    """
    seeds = [bytes(sample) for sample in samples]
    if not seeds:
        raise ValueError("check_dissector needs at least one sample")
    chooser = random.Random(seed)
    inputs = list(seeds)
    for _ in range(rounds):
        damaged = bytearray(chooser.choice(seeds))
        for _ in range(chooser.randint(1, 3)):
            if damaged and chooser.random() < 0.7:
                damaged[chooser.randrange(len(damaged))] = chooser.randrange(256)
            else:
                del damaged[chooser.randrange(len(damaged) + 1) :]
        inputs.append(bytes(damaged))
    for data in inputs:
        try:
            result = dissector(data)
        except ValueError:
            continue
        except Exception as exc:
            raise AssertionError(
                "the dissector raised %s, not ValueError, for %s"
                % (type(exc).__name__, data.hex())
            ) from exc
        problem = _contract_problem(result, data)
        if problem:
            raise AssertionError("%s, for %s" % (problem, data.hex()))


def _contract_problem(result: object, data: bytes) -> Optional[str]:
    if not isinstance(result, Dissected):
        return "the dissector returned %s, not Dissected" % type(result).__name__
    if not isinstance(result.payload, bytes):
        return "the payload is %s, not bytes" % type(result.payload).__name__
    if len(result.payload) > len(data):
        return "the payload is longer than the octets given"
    for selector in result.next:
        try:
            _selector(*selector)
        except (TypeError, ValueError):
            return "a next selector is not a (kind, number) pair"
    fragment = result.fragment
    if fragment is not None:
        if not isinstance(fragment, Fragment) or fragment.offset < 0:
            return "the fragment is not a Fragment with an offset of zero or more"
    return None
