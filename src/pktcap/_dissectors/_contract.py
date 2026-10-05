"""What a dissector is (internal). Re-exported from :mod:`pktcap`.

A dissector reads the octets of one layer and says what follows. It is a
plain callable, holds no state, performs no I/O, and may be given anything: the
octets come from a capture.
"""

from __future__ import annotations

from typing import Callable, Hashable, NamedTuple, Optional, Tuple

__all__ = ["Dissected", "Dissector", "Fragment", "Selector"]

#: What chooses a dissector: a kind and a number, such as ``("linktype", 1)``,
#: ``("ethertype", 0x0800)``, ``("ip", 17)`` or ``("udp", 67)``.
Selector = Tuple[str, int]


class Fragment(NamedTuple):
    """Says that a dissector's ``payload`` is one piece of a larger unit.

    The frame dissector puts the pieces together, within its bounds, and
    carries on with the whole once it is complete.

    :ivar key: what identifies the unit: equal for every piece of it and for
        nothing else (addresses and an identification number, for IP).
    :ivar offset: where this piece's octets start in the unit.
    :ivar last: this piece ends the unit.
    """

    key: Hashable
    offset: int
    last: bool


class Dissected(NamedTuple):
    """What a dissector returns for the octets it was given.

    :ivar layer: the record of this layer: any immutable value, the built-in
        ones being named tuples. ``None`` for a step that only chooses what
        follows and has nothing to report.
    :ivar payload: the octets left for the next layer: a part of what the
        dissector was given, never more.
    :ivar next: the selectors to try for the next dissector, in order; the
        first one registered is used. Empty when nothing follows.
    :ivar fragment: set when ``payload`` is a piece of a larger unit.
    """

    layer: object
    payload: bytes
    next: Tuple[Selector, ...] = ()
    fragment: Optional[Fragment] = None


#: A dissector: ``dissector(data) -> Dissected``. It raises ``ValueError`` (the
#: built-in ones raise :class:`pktcap.DissectError`) for octets it cannot read.
Dissector = Callable[[bytes], Dissected]
