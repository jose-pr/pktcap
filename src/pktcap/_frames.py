"""From captured frames to UDP datagrams (internal).

Strips the link layers tcpdump, Wireshark and dumpcap commonly write, reads
IPv4 and IPv6 (extension headers included) and hands back the UDP datagrams,
reassembling IP fragments on request: a datagram larger than the path MTU is
fragmented on the wire, and only the first fragment carries the UDP header.

A frame is untrusted. Every header is checked for length before it is read,
every loop over what a frame states has a ceiling, and a frame that cannot be
decoded is counted and never raised.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
from types import MappingProxyType
from typing import Iterator, List, Mapping, NamedTuple, Optional, Set

from ._captured import CapturedDatagram, CapturedFrame
from ._container import CaptureSource, read_frames
from ._reassembly import Reassembler

__all__ = ["LINKTYPES", "DecodeStats", "FrameDecoder", "read_datagrams"]

_LOG = logging.getLogger(__name__)

#: Link types understood, by pcap ``LINKTYPE_`` number.
LINKTYPES: Mapping[int, str] = MappingProxyType(
    {
        0: "NULL",  # BSD loopback, host-order family
        1: "ETHERNET",
        12: "RAW",  # some BSDs
        14: "RAW",
        101: "RAW",
        108: "LOOP",  # OpenBSD loopback, network-order family
        113: "LINUX_SLL",
        228: "IPV4",
        229: "IPV6",
        276: "LINUX_SLL2",
    }
)

_ETHERTYPES_IP = (0x0800, 0x86DD)
_ETHERTYPES_VLAN = (0x8100, 0x88A8, 0x9100)  # a tag, and the two QinQ outer tags
_FAMILY_IPV4 = 2
_FAMILIES_IPV6 = frozenset({10, 24, 28, 30})  # AF_INET6 on Linux, the BSDs, macOS
_PROTOCOL_UDP = 17
_HEADER_FRAGMENT = 44
_HEADERS_SKIPPED = (0, 43, 60)  # hop-by-hop, routing, destination options
_MAPPED_PREFIX = bytes(10) + b"\xff\xff"

#: Ceilings on what one frame may make the decoder loop over.
_MAX_VLAN_TAGS = 8
_MAX_EXTENSION_HEADERS = 64
#: How many distinct unknown link types one decoder logs before going quiet.
_MAX_LOGGED_LINKTYPES = 8


class _Malformed(Exception):
    """The frame is cut short or contradicts itself."""


class _NotUDP(Exception):
    """The frame is well formed and carries something else."""


class DecodeStats(NamedTuple):
    """What a :class:`FrameDecoder` has done with the frames it was given.

    :ivar frames: frames given to ``decode``.
    :ivar datagrams: UDP datagrams returned.
    :ivar ignored: well-formed frames that are not UDP over IP.
    :ivar malformed: frames cut short or inconsistent.
    :ivar unsupported: frames of a link type not in :data:`LINKTYPES`.
    :ivar fragments: frames that were IP fragments of a UDP datagram.
    :ivar dropped: reassemblies discarded: an overlap, a bound, old age.
    :ivar pending: reassemblies still waiting for a fragment.
    """

    frames: int
    datagrams: int
    ignored: int
    malformed: int
    unsupported: int
    fragments: int
    dropped: int
    pending: int


def _ipv6_text(packed: bytes) -> str:
    # str(IPv6Address) writes a v4-mapped address as ::ffff:102:304 before
    # Python 3.13 and as ::ffff:1.2.3.4 from it on; one form on every version.
    if packed[:12] == _MAPPED_PREFIX:
        return "::ffff:" + socket.inet_ntoa(packed[12:])
    return str(ipaddress.IPv6Address(packed))


def _network_start(kind: str, data: bytes) -> int:
    """Where the IP header starts in a frame of this link type."""
    if kind == "ETHERNET":
        offset = 12
        for _ in range(_MAX_VLAN_TAGS + 1):
            if len(data) < offset + 2:
                raise _Malformed
            ethertype = (data[offset] << 8) | data[offset + 1]
            if ethertype not in _ETHERTYPES_VLAN:
                break
            offset += 4
        else:
            raise _Malformed
        protocol, start = ethertype, offset + 2
    elif kind == "NULL" or kind == "LOOP":
        if len(data) < 4:
            raise _Malformed
        family = int.from_bytes(data[:4], "big")
        if kind == "NULL" and family > 0xFFFF:  # written by a little-endian host
            family = int.from_bytes(data[:4], "little")
        if family != _FAMILY_IPV4 and family not in _FAMILIES_IPV6:
            raise _NotUDP
        return 4
    elif kind == "LINUX_SLL":
        if len(data) < 16:
            raise _Malformed
        protocol, start = (data[14] << 8) | data[15], 16
    elif kind == "LINUX_SLL2":
        if len(data) < 20:
            raise _Malformed
        protocol, start = (data[0] << 8) | data[1], 20
    else:  # RAW, IPV4, IPV6
        return 0
    if protocol not in _ETHERTYPES_IP:
        raise _NotUDP
    return start


def _udp(
    time: float, pair: bytes, data: bytes, position: int, end: int, fragmented: bool
) -> CapturedDatagram:
    """The datagram whose UDP header is at ``position``; ``pair`` is the
    source and destination addresses, packed, one after the other."""
    available = end - position
    if available < 8:
        raise _Malformed
    sport, dport, length = struct.unpack_from("!HHH", data, position)
    if length == 0:  # a jumbogram, or a send the network card segmented
        length = available
    if length < 8:
        raise _Malformed
    payload = data[position + 8 : position + min(length, available)]
    if len(pair) == 8:
        source, destination = socket.inet_ntoa(pair[:4]), socket.inet_ntoa(pair[4:])
    else:
        source, destination = _ipv6_text(pair[:16]), _ipv6_text(pair[16:])
    truncated = length > available and not fragmented
    return CapturedDatagram(
        time, (source, sport), (destination, dport), payload, fragmented, truncated
    )


class FrameDecoder:
    """Decodes captured frames into :class:`CapturedDatagram` objects.

    Feed it every frame of a capture, in order: with ``reassemble`` on it
    keeps IP fragment state between frames. It raises nothing for a frame; what
    it could not use is counted in :attr:`stats`. Not safe to share between
    threads.

    :param reassemble: put IP fragments back together. Off, no state is kept:
        a first fragment is returned with ``fragmented=True`` and the octets
        it carries, and later fragments are counted and passed over.
    :param max_reassemblies: the most datagrams being reassembled at once; one
        more discards the oldest.
    :param reassembly_timeout: seconds of capture time after which an
        unfinished datagram is discarded.
    :raises ValueError: a limit that is not positive.
    """

    def __init__(
        self,
        *,
        reassemble: bool = True,
        max_reassemblies: int = 256,
        reassembly_timeout: float = 30.0,
    ) -> None:
        if isinstance(max_reassemblies, bool) or not isinstance(max_reassemblies, int):
            raise TypeError("max_reassemblies must be an int")
        if max_reassemblies < 1:
            raise ValueError("max_reassemblies must be at least 1")
        if not reassembly_timeout > 0:
            raise ValueError("reassembly_timeout must be positive")
        self._reassemble = bool(reassemble)
        self._table = Reassembler(max_reassemblies, float(reassembly_timeout))
        self._frames = self._datagrams = self._ignored = 0
        self._malformed = self._unsupported = self._fragments = 0
        self._logged: Set[int] = set()

    @property
    def stats(self) -> DecodeStats:
        """The counters as they stand."""
        return DecodeStats(
            self._frames,
            self._datagrams,
            self._ignored,
            self._malformed,
            self._unsupported,
            self._fragments,
            self._table.dropped,
            len(self._table),
        )

    def decode(self, frame: CapturedFrame) -> List[CapturedDatagram]:
        """The UDP datagram ``frame`` carries or completes, as a list of one;
        an empty list for anything else."""
        self._frames += 1
        kind = LINKTYPES.get(frame.linktype)
        if kind is None:
            self._unsupported += 1
            self._log_unsupported(frame.linktype)
            return []
        try:
            data = frame.data
            start = _network_start(kind, data)
            if len(data) <= start:
                raise _Malformed
            version = data[start] >> 4
            if version == 4:
                datagram = self._ipv4(frame.time, data, start)
            elif version == 6:
                datagram = self._ipv6(frame.time, data, start)
            else:
                raise _Malformed
        except _NotUDP:
            self._ignored += 1
            return []
        except _Malformed:
            self._malformed += 1
            return []
        if datagram is None:
            return []
        self._datagrams += 1
        return [datagram]

    def _log_unsupported(self, linktype: int) -> None:
        if linktype in self._logged or len(self._logged) >= _MAX_LOGGED_LINKTYPES:
            return
        self._logged.add(linktype)
        _LOG.warning(
            "link type %d is not understood; its frames are counted and skipped",
            linktype,
        )

    def _ipv4(self, time: float, data: bytes, start: int) -> Optional[CapturedDatagram]:
        available = len(data) - start
        header = (data[start] & 0x0F) * 4
        # A header of at least 20 octets, all of them present: the fixed
        # fields read below are inside it.
        if header < 20 or header > available:
            raise _Malformed
        total, ident, flags_offset = struct.unpack_from("!HHH", data, start + 2)
        if total == 0:  # left zero when the network card segments the send
            total = available
        if total < header:
            raise _Malformed
        if data[start + 9] != _PROTOCOL_UDP:
            raise _NotUDP
        pair = data[start + 12 : start + 20]
        position, end = start + header, start + min(total, available)
        more, offset = bool(flags_offset & 0x2000), (flags_offset & 0x1FFF) * 8
        if not more and not offset:
            return _udp(time, pair, data, position, end, False)
        self._fragments += 1
        if not self._reassemble:
            return None if offset else _udp(time, pair, data, position, end, True)
        if total > available:  # the snap length cut it: it cannot be placed
            raise _Malformed
        whole = self._table.add(
            (pair, ident), time, offset, data[position:end], not more
        )
        if whole is None:
            return None
        return _udp(time, pair, whole, 0, len(whole), False)

    def _ipv6(self, time: float, data: bytes, start: int) -> Optional[CapturedDatagram]:
        if len(data) - start < 40:
            raise _Malformed
        length = (data[start + 4] << 8) | data[start + 5]
        header = data[start + 6]
        pair = data[start + 8 : start + 40]
        position = start + 40
        stated = position + length if length else len(data)
        end, cut = min(stated, len(data)), stated > len(data)
        fragmented = seen_fragment = False
        for _ in range(_MAX_EXTENSION_HEADERS):
            if header == _PROTOCOL_UDP:
                return _udp(time, pair, data, position, end, fragmented)
            if header in _HEADERS_SKIPPED:
                if end - position < 2:
                    raise _Malformed
                header, size = data[position], (data[position + 1] + 1) * 8
                position += size
                if position > end:
                    raise _Malformed
                continue
            if header != _HEADER_FRAGMENT:
                raise _NotUDP
            if seen_fragment or end - position < 8:
                raise _Malformed
            seen_fragment = True
            header = data[position]
            field, ident = struct.unpack_from("!HI", data, position + 2)
            offset, more = (field >> 3) * 8, bool(field & 1)
            position += 8
            if not more and not offset:
                continue  # an atomic fragment: the whole datagram in one piece
            if header != _PROTOCOL_UDP and header not in _HEADERS_SKIPPED:
                raise _NotUDP
            self._fragments += 1
            if not self._reassemble:
                if offset:
                    return None
                fragmented = True
                continue
            if cut:
                raise _Malformed
            whole = self._table.add(
                (pair, ident), time, offset, data[position:end], not more
            )
            if whole is None:
                return None
            data, position, end, cut = whole, 0, len(whole), False
        raise _Malformed


def read_datagrams(
    source: CaptureSource,
    *,
    decoder: Optional[FrameDecoder] = None,
    max_frame_size: int = 262144,
) -> Iterator[CapturedDatagram]:
    """Every UDP datagram in a pcap or pcapng capture, in capture order.

    :func:`read_frames` and :meth:`FrameDecoder.decode` in one call: IP
    fragments are reassembled, and nothing is raised for a frame that does not
    decode. Pass a ``decoder`` to choose its options and to read its
    :attr:`~FrameDecoder.stats` afterwards.

    :param source: a path, or a binary stream, which need not be seekable.
    :param decoder: the decoder to use; a new ``FrameDecoder()`` by default.
    :param max_frame_size: as for :func:`read_frames`.
    :raises CaptureFormatError: the container is not a capture or is damaged.
    """
    frames = read_frames(source, max_frame_size=max_frame_size)
    if decoder is None:
        decoder = FrameDecoder()
    elif not isinstance(decoder, FrameDecoder):
        raise TypeError("decoder must be a FrameDecoder")
    return _decode_all(frames, decoder)


def _decode_all(
    frames: Iterator[CapturedFrame], decoder: FrameDecoder
) -> Iterator[CapturedDatagram]:
    for frame in frames:
        yield from decoder.decode(frame)
