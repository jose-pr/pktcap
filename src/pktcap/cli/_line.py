"""The summary line a copying command prints, and the stream a tool call writes."""

from __future__ import annotations

import sys
from typing import List

from .._copy import CopyResult
from .._dissect import FrameDissector

__all__ = ["TextSink", "summary_parts"]

#: Link-type numbers named in the summary before it says "and more".
_LISTED_LINKTYPES = 8


class TextSink:
    """A binary stream over the text stdout, for records, which are ASCII."""

    def write(self, data: bytes) -> int:
        sys.stdout.write(data.decode("utf-8"))
        return len(data)

    def flush(self) -> None:
        sys.stdout.flush()


def summary_parts(
    result: CopyResult, dissector: FrameDissector, max_files: int
) -> List[str]:
    """What a copy did, as the parts of the line: the counts, and only the
    ones that are not zero after the first two."""
    stats = dissector.stats
    parts = ["%d frames read" % result.read, "%d written" % result.written]
    if result.skipped:
        parts.append("%d skipped" % result.skipped)
    if result.refused:
        parts.append(
            "%d refused, %d files already (--max-files)" % (result.refused, max_files)
        )
    if stats.malformed:
        parts.append("%d malformed" % stats.malformed)
    if stats.unsupported:
        numbers = sorted(dissector.unsupported_linktypes)
        parts.append(
            "%d of an unsupported link type (%s%s)"
            % (
                stats.unsupported,
                ", ".join(str(n) for n in numbers[:_LISTED_LINKTYPES]),
                ", ..." if len(numbers) > _LISTED_LINKTYPES else "",
            )
        )
    return parts
