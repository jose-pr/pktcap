"""Writing what was captured, in a format chosen by name (internal).

One writer for every output: a capture format (pcap, pcapng) takes the frame
or the datagram itself, a record format takes the record made of it. The
container is this module's: one growing file, or one file per record under a
name pattern.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import logging
import math
import os
import re
import string
from types import TracebackType
from typing import (
    Any,
    BinaryIO,
    Dict,
    FrozenSet,
    Iterable,
    Mapping,
    Optional,
    Set,
    Type,
    Union,
)

from ._captured import CapturedDatagram
from ._dissect import DissectedFrame
from ._formats import CAPTURE_FORMATS, infer_format, record_format
from ._formats._contract import RecordFormat
from ._records import datagram_record, frame_record
from ._writer import PcapngWriter, PcapWriter

__all__ = ["CaptureWriter"]

_LOG = logging.getLogger(__name__)

#: The name-pattern fields the writer fills in itself.
_BUILT_IN_FIELDS = ("timestamp", "index", "format")
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")
#: The most characters one field value contributes to a file name.
_MAX_VALUE_LENGTH = 64
#: Hexadecimal digits of the SHA-256 of a cut value that follow its first
#: characters and a hyphen, so two long values with one start name two files.
_DIGEST_LENGTH = 8
#: Names Windows opens as devices, whatever follows the first dot.
_DEVICES = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + ["COM%d" % n for n in range(1, 10)]
    + ["LPT%d" % n for n in range(1, 10)]
)


def _safe(value: object) -> str:
    """A field value as part of a file name: no separator, no ``..``, at most
    ``_MAX_VALUE_LENGTH`` characters. A longer one is cut and ends in a hyphen
    and a digest of the whole value as given."""
    original = str(value)
    text = _UNSAFE.sub("_", original).strip("._") or "unknown"
    if len(text) <= _MAX_VALUE_LENGTH:
        return text
    digest = hashlib.sha256(original.encode("utf-8", "surrogatepass")).hexdigest()
    kept = text[: _MAX_VALUE_LENGTH - _DIGEST_LENGTH - 1].rstrip("._")
    return "%s-%s" % (kept, digest[:_DIGEST_LENGTH])


def _timestamp(time: float) -> str:
    """``time`` as UTC text for a file name. The capture controls ``time``, so
    one outside any calendar is written as a count of seconds."""
    try:
        moment = datetime.datetime.fromtimestamp(time, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        if math.isfinite(time) and abs(time) < 1 << 63:
            return "t%d" % int(time)
        return "unknown"
    return moment.strftime("%Y%m%dT%H%M%S.%fZ")


def _pattern_fields(pattern: str) -> FrozenSet[str]:
    """The fields a name pattern uses; ``ValueError`` for one that is
    malformed or that names anything but a bare field."""
    found: Set[str] = set()

    def scan(text: str) -> None:
        try:
            parts = list(string.Formatter().parse(text))
        except ValueError as exc:
            raise ValueError("the name pattern is malformed: %s" % exc) from None
        for _literal, field, spec, _conversion in parts:
            if field is None:
                continue
            if not _FIELD_NAME.match(field):
                raise ValueError(
                    "the name pattern may use bare field names only, not {%s}" % field
                )
            found.add(field)
            if spec:
                scan(spec)  # a spec may nest one level of fields

    scan(pattern)
    return frozenset(found)


class CaptureWriter:
    """Writes what was captured, or the records made of it, in one format.

    What is written is a :class:`CapturedDatagram` (the UDP view) or a
    :class:`DissectedFrame` (anything). ``pcap`` and ``pcapng`` write the
    datagram under synthesised headers, or the frame as captured, and ignore
    the record. A record format writes the record given, or
    :func:`datagram_record` or :func:`frame_record` when none is given:
    ``json`` one line per record, ``yaml`` one document per record. ``toml``
    and ``ini`` cannot hold two records in one file and need
    ``per_record=True``.

    Constructing a writer opens nothing: the file is opened by the first
    ``write``. Not safe to share between threads.

    :param target: a path or a binary stream; with ``per_record``, a file-name
        pattern such as ``"cap/{timestamp}_{xid}.json"``.
    :param format: one of :data:`OUTPUT_FORMATS`. ``None`` takes it from the
        ending of ``target``'s name.
    :param per_record: write one file per record, named by the pattern.
    :param append: add to an existing file. Not for ``pcap`` or ``pcapng``.
    :param fields: the pattern fields the caller will supply in ``names``, on
        top of ``timestamp``, ``index`` and ``format``.
    :param max_files: the most files a ``per_record`` writer creates. A field
        value may come from the network, so a peer would otherwise choose how
        many files land on the disk.
    :raises UnsupportedFormatError: no such format, or none can be told.
    :raises ImportError: the format's extra is not installed.
    :raises ValueError: a combination that cannot work, or a bad pattern.
    """

    def __init__(
        self,
        target: Union[str, "os.PathLike[str]", BinaryIO],
        format: Optional[str] = None,
        *,
        per_record: bool = False,
        append: bool = False,
        fields: Iterable[str] = (),
        max_files: int = 1000,
    ) -> None:
        if isinstance(target, io.TextIOBase):
            raise TypeError("target must be a binary stream, such as sys.stdout.buffer")
        if not isinstance(target, (str, os.PathLike)) and not hasattr(target, "write"):
            raise TypeError("target must be a path or a binary stream")
        if isinstance(max_files, bool) or not isinstance(max_files, int):
            raise TypeError("max_files must be an int")
        if max_files < 1:
            raise ValueError("max_files must be at least 1")
        self._format = infer_format(target, format)
        self._record_format: Optional[RecordFormat] = None
        if self._format not in CAPTURE_FORMATS:
            self._record_format = record_format(self._format)
            self._record_format.require()
            if not per_record and not self._record_format.streamable:
                raise ValueError(
                    "%s cannot hold more than one record in a file: pass "
                    "per_record=True and a file-name pattern, or use json or yaml"
                    % self._format
                )
        elif append:
            raise ValueError("a %s capture cannot be appended to" % self._format)
        self._fields = tuple(fields)
        self._pattern: Optional[str] = None
        if per_record:
            if not isinstance(target, (str, os.PathLike)):
                raise ValueError("per_record needs a file-name pattern, not a stream")
            self._pattern = self._checked_pattern(os.fspath(target))
        self._target = target
        self._append = bool(append)
        self._max_files = max_files
        self._file: Optional[BinaryIO] = None
        self._capture: Optional[Union[PcapWriter, PcapngWriter]] = None
        self._paths: Set[str] = set()
        self._closed = False
        self._warned = False
        self._count = 0
        #: Frames, datagrams or records written.
        self.written = 0
        #: Records not written because ``max_files`` had been reached.
        self.refused = 0

    def _checked_pattern(self, pattern: str) -> str:
        for name in self._fields:
            if not isinstance(name, str) or not _FIELD_NAME.match(name):
                raise ValueError("a pattern field is named by an identifier")
            if name in _BUILT_IN_FIELDS:
                raise ValueError("the field {%s} is filled in by the writer" % name)
        known = _BUILT_IN_FIELDS + self._fields
        for field in sorted(_pattern_fields(pattern)):
            if field not in known:
                raise ValueError(
                    "the name pattern uses {%s}, which is not a field; the fields "
                    "are %s" % (field, ", ".join("{%s}" % name for name in known))
                )
        return pattern

    @property
    def format(self) -> str:
        """The name of the format being written."""
        return self._format

    def _capture_writer(
        self, target: Union[str, "os.PathLike[str]", BinaryIO]
    ) -> Union[PcapWriter, PcapngWriter]:
        return PcapngWriter(target) if self._format == "pcapng" else PcapWriter(target)

    @staticmethod
    def _capture_write(
        writer: Union[PcapWriter, PcapngWriter],
        item: Union[CapturedDatagram, DissectedFrame],
    ) -> None:
        if isinstance(item, DissectedFrame):
            writer.write_frame(item.frame)
        else:
            writer.write_datagram(item)

    def write(
        self,
        item: Union[CapturedDatagram, DissectedFrame],
        record: Optional[Mapping[str, Any]] = None,
        *,
        text: Optional[str] = None,
        names: Optional[Mapping[str, object]] = None,
    ) -> None:
        """Write one datagram or frame, or the record made of it.

        :param item: what was captured: a :class:`CapturedDatagram` or a
            :class:`DissectedFrame`. A capture format writes it; a record
            format reads its time for ``{timestamp}``.
        :param record: plain data for a record format. ``None`` writes
            :func:`datagram_record` or :func:`frame_record` of ``item``.
        :param text: the record already rendered by the caller, for a record
            format; written as UTF-8 exactly as given, with nothing added. A
            growing file gets the format's separator before it (nothing for
            ``json``, ``---`` and a line feed for ``yaml``). Not with
            ``record``.
        :param names: with ``per_record``, a value for each of ``fields``.
        :raises ValueError: a closed writer, a field with no value, ``text``
            with a capture format or with ``record`` or that is not
            encodable, or an item or record the format must refuse.
        :raises TypeError: an item of another type, ``text`` that is not
            ``str``, or a record the format cannot represent.
        :raises OSError: the file cannot be opened or written.
        """
        if self._closed:
            raise ValueError("the writer is closed")
        if not isinstance(item, (CapturedDatagram, DissectedFrame)):
            raise TypeError("item must be a CapturedDatagram or a DissectedFrame")
        data = b""
        if text is not None:
            if not isinstance(text, str):
                raise TypeError("text must be a str")
            if self._record_format is None:
                raise ValueError(
                    "text is for a record format: a %s capture writes the frame "
                    "or datagram itself" % self._format
                )
            if record is not None:
                raise ValueError("give a record or the text of one, not both")
            data = text.encode("utf-8")
        elif self._record_format is not None:
            if record is None:
                if isinstance(item, DissectedFrame):
                    record = frame_record(item)
                else:
                    record = datagram_record(item)
            elif not isinstance(record, Mapping):
                raise TypeError("a record is a mapping")
            data = self._record_format.dumps(record).encode("utf-8")
        elif self._pattern is not None:
            buffer = io.BytesIO()
            self._capture_write(self._capture_writer(buffer), item)
            data = buffer.getvalue()
        if self._pattern is not None:
            index, self._count = self._count, self._count + 1
            self._write_file(self._pattern, item.time, data, index, names or {})
        elif self._record_format is None:
            if self._capture is None:
                self._make_parents(self._target)
                self._capture = self._capture_writer(self._target)
            self._capture_write(self._capture, item)
            self.written += 1
        else:
            self._write_stream(self._record_format.separator.encode("ascii") + data)

    @staticmethod
    def _make_parents(path: Union[str, "os.PathLike[str]", BinaryIO]) -> None:
        """The directories above a growing file, made at its first write."""
        if isinstance(path, (str, os.PathLike)):
            directory = os.path.dirname(os.fspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)

    def _write_stream(self, data: bytes) -> None:
        if self._file is None:
            if isinstance(self._target, (str, os.PathLike)):
                self._make_parents(self._target)
                self._file = open(self._target, "ab" if self._append else "wb")
            else:
                self._file = self._target
        self._file.write(data)
        self._file.flush()
        self.written += 1

    def _write_file(
        self,
        pattern: str,
        time: float,
        data: bytes,
        index: int,
        names: Mapping[str, object],
    ) -> None:
        values: Dict[str, object] = {
            "timestamp": _timestamp(time),
            "index": index,
            "format": self._format,
        }
        for name in self._fields:
            if name not in names:
                raise ValueError("names has no value for the field {%s}" % name)
            values[name] = _safe(names[name])
        try:
            path = pattern.format(**values)
        except (ValueError, TypeError) as exc:
            raise ValueError("the name pattern cannot be filled: %s" % exc) from None
        directory, name = os.path.split(path)
        if name.split(".", 1)[0].upper() in _DEVICES:
            path = os.path.join(directory, "_" + name)
        if path not in self._paths:
            if len(self._paths) >= self._max_files:
                self.refused += 1
                if not self._warned:
                    self._warned = True
                    _LOG.warning(
                        "%d files written; no more are created, and further "
                        "records are counted and not written",
                        self._max_files,
                    )
                return
            self._paths.add(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        self.written += 1

    def close(self) -> None:
        """Close the file if this writer opened it. Harmless when repeated."""
        self._closed = True
        opened, self._file = self._file, None
        if opened is not None and isinstance(self._target, (str, os.PathLike)):
            opened.close()
        capture, self._capture = self._capture, None
        if capture is not None:
            capture.close()

    def __enter__(self) -> "CaptureWriter":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()
