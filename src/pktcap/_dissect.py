"""Dissecting captured frames, layer by layer (internal).

A frame is handed to the dissector its link type selects; each dissector
reads one layer and names what may follow; the walk ends when nothing is
registered for what follows, when the octets run out, or when a dissector
cannot read what it was given. Whatever was not dissected comes back as the
frame's payload: nothing is dropped, and nothing here raises for a frame.

A frame is untrusted. The built-in dissectors check every length before they
use it; this module bounds what no single dissector can: how many layers one
frame may have, and how much IP reassembly may hold.
"""

from __future__ import annotations

import logging
from types import MappingProxyType
from typing import (
    Dict,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
)

from ._captured import CapturedDatagram, CapturedFrame
from ._container import CaptureSource, read_frames
from ._dissectors import DissectorRegistry, default_registry
from ._dissectors._contract import Dissected, Selector
from ._dissectors._link import LINKTYPE_NAMES
from ._layers import IPv4Layer, IPv6FragmentLayer, IPv6Layer, UDPLayer
from ._reassembly import Reassembler

__all__ = [
    "LINKTYPES",
    "DissectStats",
    "DissectedFrame",
    "FrameDissector",
    "read_datagrams",
    "read_dissected",
]

_LOG = logging.getLogger(__name__)
_T = TypeVar("_T")

#: The link types with a built-in dissector, by pcap ``LINKTYPE_`` number.
LINKTYPES: Mapping[int, str] = MappingProxyType(dict(LINKTYPE_NAMES))

#: The most dissectors run on one frame: a tag stack or a chain of extension
#: headers is cut off here.
_MAX_LAYERS = 32
#: How many distinct selectors one frame dissector logs a failure for.
_MAX_LOGGED = 8
#: How many distinct link types one frame dissector counts frames by.
_MAX_COUNTED = 64


class DissectStats(NamedTuple):
    """What a :class:`FrameDissector` has met in the frames it was given.

    :ivar frames: frames given to ``dissect``.
    :ivar malformed: frames in which a dissector could not read its layer
        (a ``ValueError``), or that had more layers than the ceiling.
    :ivar failed: frames in which a dissector raised anything else, or
        returned something that is not a :class:`Dissected`: a defect in it.
    :ivar unsupported: frames whose link type has no dissector;
        :attr:`FrameDissector.unsupported_linktypes` says which.
    :ivar fragments: frames that were a piece of a fragmented IP datagram.
    :ivar dropped: reassemblies discarded: an overlap, a ceiling, old age.
    :ivar pending: reassemblies still waiting for a fragment.
    """

    frames: int
    malformed: int
    failed: int
    unsupported: int
    fragments: int
    dropped: int
    pending: int


class DissectedFrame(NamedTuple):
    """A captured frame and the layers that were read from it.

    :ivar frame: the frame as captured.
    :ivar layers: the layer records, outermost first.
    :ivar payloads: for each layer, the octets that follow it. The last one is
        what was not dissected.
    :ivar error: why dissection stopped early, naming the selector whose
        dissector could not read its layer; ``None`` when it simply ran out of
        dissectors or of octets.
    :ivar reassembled: the layers after an IP fragment were read from a
        datagram put together from several frames, of which this is the last.
    """

    frame: CapturedFrame
    layers: Tuple[object, ...]
    payloads: Tuple[bytes, ...]
    error: Optional[str] = None
    reassembled: bool = False

    @property
    def time(self) -> float:
        """The frame's time, in seconds since the epoch."""
        return self.frame.time

    @property
    def payload(self) -> bytes:
        """The octets no dissector read: after the last layer, or the whole
        frame when there is none."""
        return self.payloads[-1] if self.payloads else self.frame.data

    def layer(self, kind: Type[_T]) -> Optional[_T]:
        """The outermost layer that is a ``kind``, or ``None``."""
        for layer in self.layers:
            if isinstance(layer, kind):
                return layer
        return None

    def payload_of(self, kind: type) -> Optional[bytes]:
        """The octets that follow the outermost ``kind`` layer, or ``None``."""
        for layer, payload in zip(self.layers, self.payloads):
            if isinstance(layer, kind):
                return payload
        return None

    def datagram(self) -> Optional[CapturedDatagram]:
        """This frame as a UDP datagram: its time, both socket addresses and
        the octets after the UDP header, whatever dissected them further.
        ``None`` when the frame carries no UDP over IP."""
        source = destination = None
        partial = False
        for layer, payload in zip(self.layers, self.payloads):
            if isinstance(layer, (IPv4Layer, IPv6Layer)):
                source, destination = layer.source, layer.destination
                partial = isinstance(layer, IPv4Layer) and layer.is_fragment
            elif isinstance(layer, IPv6FragmentLayer):
                partial = layer.is_fragment
            elif isinstance(layer, UDPLayer):
                if source is None or destination is None:
                    return None
                fragmented = partial and not self.reassembled
                cut = layer.length > 8 + len(payload) and not fragmented
                return CapturedDatagram(
                    self.frame.time,
                    (source, layer.source_port),
                    (destination, layer.destination_port),
                    payload,
                    fragmented,
                    cut,
                )
        return None


class FrameDissector:
    """Dissects captured frames into :class:`DissectedFrame` objects.

    Feed it every frame of a capture, in order: with ``reassemble`` on it
    keeps IP fragment state between frames. It raises nothing for a frame:
    every frame comes back, with the layers that were read and the rest as
    payload, and :attr:`stats` counts what went wrong. Not safe to share
    between threads.

    :param registry: where dissectors are looked up; :func:`default_registry`
        when ``None``. It is read at each frame, so a dissector registered
        later is used from then on.
    :param reassemble: put IP fragments back together. Off, no state is kept:
        the layers of a first fragment are read from the octets it carries,
        and a later fragment's octets are left as payload.
    :param max_reassemblies: the most datagrams being reassembled at once; one
        more discards the oldest.
    :param reassembly_timeout: seconds of capture time after which an
        unfinished datagram is discarded.
    :raises ValueError: a limit that is not positive.
    """

    def __init__(
        self,
        registry: Optional[DissectorRegistry] = None,
        *,
        reassemble: bool = True,
        max_reassemblies: int = 256,
        reassembly_timeout: float = 30.0,
    ) -> None:
        if registry is not None and not isinstance(registry, DissectorRegistry):
            raise TypeError("registry must be a DissectorRegistry")
        if isinstance(max_reassemblies, bool) or not isinstance(max_reassemblies, int):
            raise TypeError("max_reassemblies must be an int")
        if max_reassemblies < 1:
            raise ValueError("max_reassemblies must be at least 1")
        if not reassembly_timeout > 0:
            raise ValueError("reassembly_timeout must be positive")
        self._registry = registry if registry is not None else default_registry()
        self._reassemble = bool(reassemble)
        self._table = Reassembler(max_reassemblies, float(reassembly_timeout))
        self._frames = self._malformed = self._failed = 0
        self._unsupported = self._fragments = 0
        self._logged: Set[Selector] = set()
        self._by_linktype: Dict[int, int] = {}

    @property
    def registry(self) -> DissectorRegistry:
        """The registry dissectors are looked up in."""
        return self._registry

    @property
    def stats(self) -> DissectStats:
        """The counters as they stand."""
        return DissectStats(
            self._frames,
            self._malformed,
            self._failed,
            self._unsupported,
            self._fragments,
            self._table.dropped,
            len(self._table),
        )

    @property
    def unsupported_linktypes(self) -> Mapping[int, int]:
        """How many frames each link type with no dissector had, by its
        ``LINKTYPE_`` number: a read-only snapshot. The first 64 distinct
        link types are told apart; ``stats.unsupported`` counts every frame."""
        return MappingProxyType(dict(self._by_linktype))

    def dissect(self, frame: CapturedFrame) -> DissectedFrame:
        """``frame`` with every layer a registered dissector could read."""
        self._frames += 1
        lookup = self._registry._lookup()
        selector: Selector = ("linktype", frame.linktype)
        dissector = lookup(selector)
        if dissector is None:
            self._unsupported += 1
            counted = self._by_linktype
            if frame.linktype in counted or len(counted) < _MAX_COUNTED:
                counted[frame.linktype] = counted.get(frame.linktype, 0) + 1
            return DissectedFrame(frame, (), ())
        layers: List[object] = []
        payloads: List[bytes] = []
        data = frame.data
        error: Optional[str] = None
        reassembled = False
        steps = 0
        while dissector is not None:
            if steps == _MAX_LAYERS:
                self._malformed += 1
                error = "more than %d dissectors deep" % _MAX_LAYERS
                break
            steps += 1
            try:
                result = dissector(data)
                if not isinstance(result, Dissected):
                    raise TypeError("a dissector returns a Dissected with bytes")
                layer, payload, following, fragment = result
                if not isinstance(payload, bytes):
                    raise TypeError("a dissector returns a Dissected with bytes")
            except ValueError as exc:
                self._malformed += 1
                error = "%s %d: %s" % (selector[0], selector[1], exc)
                break
            except Exception as exc:
                self._failed += 1
                error = "%s %d: the dissector raised %s" % (
                    selector[0],
                    selector[1],
                    type(exc).__name__,
                )
                self._log_failure(selector, exc)
                break
            data = payload
            if layer is not None:
                layers.append(layer)
                payloads.append(data)
            if fragment is not None:
                self._fragments += 1
                if not self._reassemble:
                    if fragment.offset:
                        break  # the middle of a datagram: no header to read
                else:
                    whole = self._table.add(
                        self._unit(layers, fragment.key),
                        frame.time,
                        fragment.offset,
                        data,
                        fragment.last,
                    )
                    if whole is None:
                        break
                    data, reassembled = whole, True
                    if layer is not None:
                        payloads[-1] = whole
            dissector = None
            for selector in following:
                dissector = lookup(selector)
                if dissector is not None:
                    break
        return DissectedFrame(frame, tuple(layers), tuple(payloads), error, reassembled)

    @staticmethod
    def _unit(layers: List[object], key: object) -> Tuple[object, ...]:
        """What identifies a fragmented unit: the dissector's own key and the
        addresses of the network layer it travels in."""
        for layer in reversed(layers):
            source = getattr(layer, "source", None)
            destination = getattr(layer, "destination", None)
            if source is not None and destination is not None:
                return (source, destination, key)
        return (key,)

    def _log_failure(self, selector: Selector, exc: Exception) -> None:
        if selector in self._logged or len(self._logged) >= _MAX_LOGGED:
            return
        self._logged.add(selector)
        _LOG.warning(
            "the dissector for %s %d raised %s; frames it fails on keep that "
            "layer undecoded and are counted",
            selector[0],
            selector[1],
            type(exc).__name__,
        )


def read_dissected(
    source: CaptureSource,
    *,
    dissector: Optional[FrameDissector] = None,
    max_frame_size: int = 262144,
) -> Iterator[DissectedFrame]:
    """Every frame of a pcap or pcapng capture, dissected, in capture order.

    :func:`read_frames` and :meth:`FrameDissector.dissect` in one call. Every
    frame is yielded, whatever its link type and whatever it carries.

    :param source: a path, or a binary stream, which need not be seekable.
    :param dissector: the frame dissector to use, for its registry, its
        options and its :attr:`~FrameDissector.stats`; a new
        ``FrameDissector()`` by default.
    :param max_frame_size: as for :func:`read_frames`.
    :raises CaptureFormatError: the container is not a capture or is damaged.
    """
    frames = read_frames(source, max_frame_size=max_frame_size)
    if dissector is None:
        dissector = FrameDissector()
    elif not isinstance(dissector, FrameDissector):
        raise TypeError("dissector must be a FrameDissector")
    return map(dissector.dissect, frames)


def read_datagrams(
    source: CaptureSource,
    *,
    dissector: Optional[FrameDissector] = None,
    max_frame_size: int = 262144,
) -> Iterator[CapturedDatagram]:
    """Every UDP datagram in a pcap or pcapng capture, in capture order.

    :func:`read_dissected` through :meth:`DissectedFrame.datagram`: the view
    a UDP protocol library works on. IP fragments are reassembled. Frames
    that carry no UDP are not yielded; pass a ``dissector`` to read its
    :attr:`~FrameDissector.stats` and tell an empty capture from one of
    another link type.

    :raises CaptureFormatError: the container is not a capture or is damaged.
    """
    dissected = read_dissected(
        source, dissector=dissector, max_frame_size=max_frame_size
    )
    return _datagrams(dissected)


def _datagrams(frames: Iterator[DissectedFrame]) -> Iterator[CapturedDatagram]:
    for frame in frames:
        datagram = frame.datagram()
        if datagram is not None:
            yield datagram
