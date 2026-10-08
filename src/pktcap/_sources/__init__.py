"""Where frames come from besides a file and a packet socket (internal)."""

from __future__ import annotations

from ._sniff import asniff_udp, sniff_udp
from ._udp import UDPCapture

__all__ = ["UDPCapture", "asniff_udp", "sniff_udp"]
