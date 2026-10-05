"""pktcap -- capture files for UDP protocol libraries.

Reads pcap and pcapng captures, decodes captured frames to UDP datagrams,
writes datagrams back as pcap or as structured records, and replays a capture.
What a datagram means stays with the protocol library that uses this one.

Every public name is imported from :mod:`pktcap`; the modules beside this one
are private.
"""

from __future__ import annotations

from importlib.metadata import version as _version

from ._exceptions import PktcapError

__all__ = [
    "PktcapError",
]

__version__ = _version("pktcap")
