"""Reading the two capture containers, pcap and pcapng (internal).

Both formats, either byte order, microsecond or nanosecond timestamps, several
interfaces per pcapng section, from a file or from a stream that cannot seek
(``tcpdump -w -``, ``dumpcap -w -``). The layouts are those of
draft-ietf-opsawg-pcap and draft-ietf-opsawg-pcapng.

A capture is untrusted input. Every length the file states is compared with a
ceiling before a single octet of it is read, so the memory a file can cost is
its ceilings and never its claims.
"""

from __future__ import annotations

import os
import struct
from typing import BinaryIO, Iterator, List, Optional, Tuple, Union

from ._captured import CapturedFrame
from ._exceptions import CaptureFormatError

__all__ = ["read_frames", "CaptureSource"]

#: What ``read_frames`` reads from: a path, or a binary stream.
CaptureSource = Union[str, "os.PathLike[str]", BinaryIO]

#: libpcap's MAXIMUM_SNAPLEN, the largest frame tcpdump or dumpcap records.
_DEFAULT_MAX_FRAME_SIZE = 262144
#: Room in a pcapng packet block beyond the frame: fixed fields and options.
_BLOCK_OVERHEAD = 65536
#: The most a pcapng section header or interface description may occupy.
_MAX_META_BLOCK = 1 << 20
#: The most interfaces one pcapng section may describe.
_MAX_INTERFACES = 4096
#: How much of a block that is not needed is read at a time before discarding.
_SKIP_CHUNK = 65536

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
_PCAPNG_SECTION = b"\x0a\x0d\x0d\x0a"
_BYTE_ORDER_MAGICS = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}

_BLOCK_INTERFACE = 1
_BLOCK_PACKET = 2  # the obsolete packet block: a 16-bit interface id
_BLOCK_SIMPLE_PACKET = 3
_BLOCK_ENHANCED_PACKET = 6
_OPTION_END = 0
_OPTION_TSRESOL = 9
_OPTION_TSOFFSET = 14


class _Reader:
    """A stream that counts what it has handed out and never reads past a
    length its caller has already checked."""

    __slots__ = ("_stream", "offset")

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self.offset = 0

    def _fill(self, count: int) -> bytes:
        """Up to ``count`` octets: fewer only where the input ends."""
        chunks: List[bytes] = []
        got = 0
        while got < count:
            chunk = self._stream.read(count - got)
            if not chunk:
                break
            if not isinstance(chunk, (bytes, bytearray)):
                raise TypeError(
                    "a capture is read from a binary stream, not a text one"
                )
            chunks.append(bytes(chunk))
            got += len(chunk)
        self.offset += got
        return b"".join(chunks)

    def need(self, count: int, what: str) -> bytes:
        """Exactly ``count`` octets; the input ending first is a truncation."""
        data = self._fill(count)
        if len(data) < count:
            raise self.fail("the capture ends inside %s" % what)
        return data

    def begin(self, count: int, what: str) -> Optional[bytes]:
        """As :meth:`need`, where the input may also end cleanly: ``None``."""
        data = self._fill(count)
        if not data:
            return None
        if len(data) < count:
            raise self.fail("the capture ends inside %s" % what)
        return data

    def skip(self, count: int, what: str) -> bytes:
        """Read and discard ``count`` octets, returning the last four."""
        tail = b""
        while count > 0:
            chunk = self.need(min(count, _SKIP_CHUNK), what)
            tail = (tail + chunk)[-4:]
            count -= len(chunk)
        return tail

    def fail(self, message: str) -> CaptureFormatError:
        return CaptureFormatError(message, offset=self.offset)


def _pcap(
    reader: _Reader, magic: bytes, max_frame_size: int
) -> Iterator[CapturedFrame]:
    endian, scale = _PCAP_MAGICS[magic]
    header = reader.need(20, "the file header")
    linktype = struct.unpack(endian + "I", header[16:20])[0] & 0x0FFFFFFF
    record = struct.Struct(endian + "IIII")
    while True:
        head = reader.begin(16, "a packet record header")
        if head is None:
            return
        seconds, fraction, captured, _original = record.unpack(head)
        if captured > max_frame_size:
            raise reader.fail(
                "a packet record claims %d octets, over the limit of %d"
                % (captured, max_frame_size)
            )
        data = reader.need(captured, "a packet record")
        yield CapturedFrame(seconds + fraction * scale, linktype, data)


def _interface(body: bytes, endian: str) -> Tuple[int, float, int]:
    """``(linktype, seconds per timestamp unit, seconds to add)`` from the body
    of an interface description block, its trailing length removed."""
    linktype = struct.unpack_from(endian + "H", body, 0)[0]
    scale, shift = 1e-6, 0
    position = 8
    while position + 4 <= len(body):
        code, size = struct.unpack_from(endian + "HH", body, position)
        value = body[position + 4 : position + 4 + size]
        if code == _OPTION_END:
            break
        if code == _OPTION_TSRESOL and len(value) == 1:
            exponent = value[0] & 0x7F
            scale = 2.0 ** -exponent if value[0] & 0x80 else 10.0**-exponent
        elif code == _OPTION_TSOFFSET and len(value) == 8:
            shift = struct.unpack(endian + "q", value)[0]
        position += 4 + ((size + 3) & ~3)
    return linktype, scale, shift


def _pcapng(reader: _Reader, max_frame_size: int) -> Iterator[CapturedFrame]:
    endian = ""
    interfaces: List[Tuple[int, float, int]] = []
    kind_bytes: Optional[bytes] = _PCAPNG_SECTION
    while kind_bytes is not None:
        length_bytes = reader.need(4, "a block header")
        if kind_bytes == _PCAPNG_SECTION:
            order = _BYTE_ORDER_MAGICS.get(reader.need(4, "a section header"))
            if order is None:
                raise reader.fail("a section header has no byte-order magic")
            # A section header holds 16 more octets before its second length.
            endian, interfaces, consumed, least, kind = order, [], 12, 28, 0
        else:
            consumed, least = 8, 12
            kind = struct.unpack(endian + "I", kind_bytes)[0]
        length = struct.unpack(endian + "I", length_bytes)[0]
        if length % 4 or length < least:
            raise reader.fail("a block states an impossible length, %d" % length)
        packet = kind in (_BLOCK_PACKET, _BLOCK_SIMPLE_PACKET, _BLOCK_ENHANCED_PACKET)
        if packet:
            ceiling: Optional[int] = max_frame_size + _BLOCK_OVERHEAD
        elif kind_bytes == _PCAPNG_SECTION or kind == _BLOCK_INTERFACE:
            ceiling = _MAX_META_BLOCK
        else:
            ceiling = None  # not needed: discarded as it is read, never held
        if ceiling is None:
            trailer = reader.skip(length - consumed, "a block")
            body = b""
        else:
            if length > ceiling:
                raise reader.fail(
                    "a block claims %d octets, over the limit of %d" % (length, ceiling)
                )
            rest = reader.need(length - consumed, "a block")
            body, trailer = rest[:-4], rest[-4:]
        if struct.unpack(endian + "I", trailer)[0] != length:
            raise reader.fail("a block's two lengths disagree")
        if kind == _BLOCK_INTERFACE:
            if len(body) < 8:
                raise reader.fail("an interface description is cut short")
            if len(interfaces) >= _MAX_INTERFACES:
                raise reader.fail(
                    "a section describes more than %d interfaces" % _MAX_INTERFACES
                )
            interfaces.append(_interface(body, endian))
        elif packet:
            yield _packet(reader, kind, body, endian, interfaces, max_frame_size)
        kind_bytes = reader.begin(4, "a block header")


def _packet(
    reader: _Reader,
    kind: int,
    body: bytes,
    endian: str,
    interfaces: List[Tuple[int, float, int]],
    max_frame_size: int,
) -> CapturedFrame:
    if kind == _BLOCK_SIMPLE_PACKET:
        if len(body) < 4:
            raise reader.fail("a packet block is cut short")
        index, stamp, start = 0, None, 4
        captured = min(struct.unpack_from(endian + "I", body, 0)[0], len(body) - 4)
    else:
        if len(body) < 20:
            raise reader.fail("a packet block is cut short")
        if kind == _BLOCK_ENHANCED_PACKET:
            index, high, low, captured = struct.unpack_from(endian + "IIII", body, 0)
        else:
            index, _drops, high, low, captured = struct.unpack_from(
                endian + "HHIII", body, 0
            )
        stamp, start = (high << 32) | low, 20
        if captured > len(body) - 20:
            raise reader.fail("a packet is longer than the block that holds it")
    if captured > max_frame_size:
        raise reader.fail(
            "a packet claims %d octets, over the limit of %d"
            % (captured, max_frame_size)
        )
    if index >= len(interfaces):
        raise reader.fail("a packet names an interface its section does not describe")
    linktype, scale, shift = interfaces[index]
    time = 0.0 if stamp is None else stamp * scale + shift
    return CapturedFrame(time, linktype, body[start : start + captured], index)


def read_frames(
    source: CaptureSource, *, max_frame_size: int = _DEFAULT_MAX_FRAME_SIZE
) -> Iterator[CapturedFrame]:
    """Every packet of a pcap or pcapng capture, in file order.

    Nothing is read until the first frame is asked for, and frames are yielded
    as they are read, so a live pipe (``sys.stdin.buffer``) works and a damaged
    capture gives every frame before the damage and then raises. An empty
    input is an empty capture.

    :param source: a path, or a binary stream, which need not be seekable. A
        stream stays the caller's to close.
    :param max_frame_size: the most octets one captured frame may have. A
        record or block that claims more is refused before it is read.
    :raises CaptureFormatError: the input is not a capture, is cut short, or
        states a length over its limit.
    :raises OSError: the path cannot be opened or the stream cannot be read.
    :raises ValueError: ``max_frame_size`` is not positive.
    """
    if isinstance(max_frame_size, bool) or not isinstance(max_frame_size, int):
        raise TypeError("max_frame_size must be an int")
    if max_frame_size <= 0:
        raise ValueError("max_frame_size must be positive")
    if not isinstance(source, (str, os.PathLike)) and not hasattr(source, "read"):
        raise TypeError("source must be a path or a binary stream")
    return _open_and_read(source, max_frame_size)


def _open_and_read(
    source: CaptureSource, max_frame_size: int
) -> Iterator[CapturedFrame]:
    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as stream:
            yield from _frames(_Reader(stream), max_frame_size)
    else:
        yield from _frames(_Reader(source), max_frame_size)


def _frames(reader: _Reader, max_frame_size: int) -> Iterator[CapturedFrame]:
    magic = reader.begin(4, "the file header")
    if magic is None:
        return
    if magic in _PCAP_MAGICS:
        yield from _pcap(reader, magic, max_frame_size)
    elif magic == _PCAPNG_SECTION:
        yield from _pcapng(reader, max_frame_size)
    else:
        raise CaptureFormatError("not a pcap or pcapng capture", offset=0)
