"""``pktcap replay``: the UDP payloads of a capture, sent to one destination."""

from __future__ import annotations

import json
import sys
from typing import Annotated, BinaryIO, Iterator, Optional, Union

from duho import Meta
from netimps import Host, UDPEndpoint, bind, split_host

from .._captured import CapturedDatagram
from .._dissect import FrameDissector, read_dissected
from .._exceptions import CaptureFormatError
from .._replay import replay_to
from ._common import Base

__all__ = ["Replay"]


class Replay(Base):
    """Send the payload of each UDP datagram of a capture, in order and in time, to the one destination --to names, never to the addresses in the file."""

    _parsername_ = "replay"
    # Puts datagrams on a network: not a call a program makes by accident.
    _mcp_ = False

    input: str
    "The pcap or pcapng capture to read, or - for standard input"
    ("--input", "-i")

    to: str
    "The destination, HOST:PORT (an IPv6 address in brackets): the only place anything is sent"
    ("--to",)

    speed: Annotated[float, Meta(conflicts="pace")] = 1.0
    "Divide each recorded wait by this: 1 keeps the recorded pace, 2 is twice as fast"
    ("--speed",)

    no_delay: Annotated[bool, Meta(conflicts="pace")] = False
    "Send without waiting, as fast as the socket takes them. Omitted: keep the recorded pace"
    ("--no-delay",)

    max_delay: float = 5.0
    "The longest single wait in seconds, whatever the capture's times say"
    ("--max-delay",)

    limit: Optional[int] = None
    "Stop after this many datagrams, partial ones included. Omitted: all of them"
    ("--limit",)

    source_port: Optional[int] = None
    "Send from this UDP port. Omitted: any free port"
    ("--source-port",)

    broadcast: bool = False
    "Allow sending to a broadcast address. Omitted: refused"
    ("--broadcast",)

    json_out: bool = False
    'Print the result as one JSON object, {"sent": N, "partial": M}. Omitted: text'
    ("--json",)

    def _destination(self) -> "tuple[str, int]":
        host, port = split_host(self.to)
        if port is None:
            raise ValueError(
                "--to needs a port: HOST:PORT, with [ ] around an IPv6 address"
            )
        return str(host), port

    def _source(self) -> Union[str, BinaryIO]:
        return sys.stdin.buffer if self.input == "-" else self.input

    def _datagrams(self) -> Iterator[CapturedDatagram]:
        """The datagrams of the frames the filter keeps, in capture order."""
        wanted = self._select()
        for frame in read_dissected(self._source(), dissector=FrameDissector()):
            datagram = frame.datagram() if wanted(frame) else None
            if datagram is not None:
                yield datagram

    def _endpoint(self, host: str) -> Optional[UDPEndpoint]:
        """A socket for --source-port and --broadcast, of the destination's family."""
        if self.source_port is None and not self.broadcast:
            return None
        address = Host(host).ip(check=True)
        family_any = "::" if address is not None and address.version == 6 else ""
        sock = bind(family_any, self.source_port or 0, broadcast=self.broadcast)
        return UDPEndpoint(sock, pktinfo=False)

    def __call__(self) -> Optional[int]:
        host, port = self._destination()
        endpoint = self._endpoint(host)
        try:
            result = replay_to(
                self._datagrams(),
                host,
                port,
                endpoint=endpoint,
                speed=None if self.no_delay else self.speed,
                max_delay=self.max_delay,
                limit=self.limit,
            )
        except CaptureFormatError as exc:
            name = "standard input" if self.input == "-" else self.input
            raise ValueError("%s: %s" % (name, exc)) from exc
        finally:
            if endpoint is not None:
                endpoint.close()
        if self.json_out:
            print(json.dumps({"sent": result.sent, "partial": result.partial}))
        else:
            print("sent %d, partial %d" % (result.sent, result.partial))
        return None
