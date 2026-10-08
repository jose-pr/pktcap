"""``pktcap replay``: the UDP payloads of a capture, sent to one destination."""

from __future__ import annotations

import json
import sys
from typing import Annotated, Any, BinaryIO, ClassVar, Iterator, Optional, Tuple, Union

from duho import Meta
from netimps import Host, UDPEndpoint, bind, split_host

from .._captured import CapturedDatagram
from .._dissect import FrameDissector, read_dissected
from .._dissectors import DissectorRegistry
from .._exceptions import CaptureFormatError
from .._replay import replay_to
from ._common import Selecting

__all__ = ["Replay"]


class Replay(Selecting):
    """Send the payload of each UDP datagram of a capture, in order and in time, to the one destination --to names, never to the addresses in the file."""

    _parsername_ = "replay"
    # Puts datagrams on a network: not a call a program makes by accident.
    _mcp_ = False
    #: The port of a ``--to`` that names none; ``None`` refuses such a value.
    _default_port_: ClassVar[Optional[int]] = None

    input: str
    "The pcap or pcapng capture to read, or - for standard input"
    ("--input", "-i")

    to: str
    "The destination, HOST:PORT (an IPv6 address in brackets; the port may be left out where the command has a default): the only place anything is sent"
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

    def _destination(self) -> Tuple[str, int]:
        host, port = split_host(self.to)
        if port is None:
            port = self._default_port_
        if port is None:
            raise ValueError(
                "--to needs a port: HOST:PORT, with [ ] around an IPv6 address"
            )
        return str(host), port

    def _source(self) -> Union[str, BinaryIO]:
        return sys.stdin.buffer if self.input == "-" else self.input

    def _datagrams(self, registry: DissectorRegistry) -> Iterator[CapturedDatagram]:
        """The datagrams of the frames the filter keeps, in capture order:
        what ``_replay`` is given."""
        wanted = self._select(registry)
        for frame in read_dissected(self._source(), dissector=FrameDissector(registry)):
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

    def _replay(
        self, datagrams: Iterator[CapturedDatagram], host: str, port: int
    ) -> Any:
        """Send the datagrams to the destination, paced and limited by the
        options; returns what ``_report`` is given."""
        endpoint = self._endpoint(host)
        try:
            return replay_to(
                datagrams,
                host,
                port,
                endpoint=endpoint,
                speed=None if self.no_delay else self.speed,
                max_delay=self.max_delay,
                limit=self.limit,
            )
        finally:
            if endpoint is not None:
                endpoint.close()

    def _report(self, result: Any) -> Optional[int]:
        """Print the outcome on standard output: ``sent N, partial M``, or
        the same as a JSON object with ``--json``."""
        if self.json_out:
            print(json.dumps({"sent": result.sent, "partial": result.partial}))
        else:
            print("sent %d, partial %d" % (result.sent, result.partial))
        return None

    def __call__(self) -> Optional[int]:
        registry = self._registry()
        host, port = self._destination()
        try:
            result = self._replay(self._datagrams(registry), host, port)
        except CaptureFormatError as exc:
            name = "standard input" if self.input == "-" else self.input
            raise ValueError("%s: %s" % (name, exc)) from exc
        return self._report(result)
