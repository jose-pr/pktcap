"""How often a hook's failures are logged (internal)."""

from __future__ import annotations

import time
from typing import Optional

__all__ = ["FailureLimit"]

#: Seconds between two log lines about failures: a sender that makes a hook
#: fail must not choose how much is logged.
LOG_INTERVAL = 60.0


class FailureLimit:
    """Says when a failure may be logged: the first, then at most one every
    :data:`LOG_INTERVAL` seconds, with the running count beside it."""

    def __init__(self) -> None:
        self._last: Optional[float] = None

    def due(self) -> bool:
        """Whether a line may be logged at this moment; a yes starts the next interval."""
        moment = time.monotonic()
        last = self._last
        if last is not None and moment - last < LOG_INTERVAL:
            return False
        self._last = moment
        return True

    @staticmethod
    def note(failures: int) -> str:
        """The count to put at the end of a line, empty for the first."""
        if failures <= 1:
            return ""
        return " [%d failures so far; at most one line per %g s]" % (
            failures,
            LOG_INTERVAL,
        )
