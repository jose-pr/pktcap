"""One TCP connection written as segments, its sequence numbers kept (internal)."""

from __future__ import annotations

import secrets
from typing import Any, Dict, Optional, Tuple

from netimps import SocketAddress

__all__ = ["TCPFlowWriter"]

_UINT32 = 1 << 32
_SIDES = ("client", "server")
#: The largest payload one segment can carry over IPv6 (IPv4 allows less).
_MAX_MSS = 65495


class TCPFlowWriter:
    """Writes one TCP connection, from stream octets, as segments of a capture.

    ``writer`` is a :class:`PcapWriter` or :class:`PcapngWriter` (anything
    with their ``write_tcp``). ``client`` and ``server`` are the two
    ``(host, port)`` ends; the client opens. The sequence numbers start at
    ``client_isn`` and ``server_isn`` (random when omitted) and are kept from
    there, so a reader that reassembles TCP, Wireshark or
    :class:`TCPReassembler`, gets back exactly the octets given to
    :meth:`send`, in each direction.

    Every segment acknowledges everything the other side has sent; nothing is
    lost or reordered. Not safe to share between threads.

    :param mss: the largest payload of one segment, 1 to 65,495.
    :raises ValueError: an ``mss`` or initial sequence number out of range.
    :raises TypeError: an argument of the wrong type.
    """

    def __init__(
        self,
        writer: Any,
        client: SocketAddress,
        server: SocketAddress,
        *,
        mss: int = 1460,
        client_isn: Optional[int] = None,
        server_isn: Optional[int] = None,
    ) -> None:
        if not callable(getattr(writer, "write_tcp", None)):
            raise TypeError("writer must be a PcapWriter or PcapngWriter")
        if isinstance(mss, bool) or not isinstance(mss, int):
            raise TypeError("mss must be an int")
        if not 1 <= mss <= _MAX_MSS:
            raise ValueError("mss %d is outside 1 to %d" % (mss, _MAX_MSS))
        self.writer = writer
        self.client = client
        self.server = server
        self.mss = mss
        self._isn = {
            "client": self._start(client_isn, "client_isn"),
            "server": self._start(server_isn, "server_isn"),
        }
        self._next: Dict[str, int] = {}
        self._ended = {"client": False, "server": False}

    @staticmethod
    def _start(value: Optional[int], name: str) -> int:
        if value is None:
            return secrets.randbits(32)
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("%s must be an int" % name)
        if not 0 <= value < _UINT32:
            raise ValueError("%s %d is outside 0 to 2**32 - 1" % (name, value))
        return value

    def __repr__(self) -> str:
        return "TCPFlowWriter(client=%r, server=%r)" % (self.client, self.server)

    @property
    def opened(self) -> bool:
        return bool(self._next)

    def _ends(self, sender: str) -> Tuple[str, SocketAddress, SocketAddress]:
        if sender not in _SIDES:
            raise ValueError("sender must be 'client' or 'server', not %r" % (sender,))
        other = "server" if sender == "client" else "client"
        source = self.client if sender == "client" else self.server
        destination = self.server if sender == "client" else self.client
        return other, source, destination

    def _segment(self, time: float, sender: str, flags: str, data: bytes = b"") -> None:
        other, source, destination = self._ends(sender)
        self.writer.write_tcp(
            time,
            source,
            destination,
            data,
            seq=self._next[sender],
            ack=self._next[other],
            flags=flags,
        )

    def _require(self, sender: str) -> None:
        if not self._next:
            raise ValueError("open() the connection first")
        if self._ended[sender]:
            raise ValueError("the %s side has already ended" % sender)

    def open(self, time: float) -> None:
        """The three-way handshake: SYN, SYN-ACK, ACK, all at ``time``.

        :raises ValueError: the connection is already open.
        """
        if self._next:
            raise ValueError("the connection is already open")
        client, server = self._isn["client"], self._isn["server"]
        self.writer.write_tcp(time, self.client, self.server, seq=client, flags="S")
        self.writer.write_tcp(
            time,
            self.server,
            self.client,
            seq=server,
            ack=(client + 1) % _UINT32,
            flags="SA",
        )
        self._next = {
            "client": (client + 1) % _UINT32,
            "server": (server + 1) % _UINT32,
        }
        self._segment(time, "client", "A")

    def send(self, time: float, sender: str, data: bytes) -> None:
        """``data`` from ``sender`` (``"client"`` or ``"server"``), in
        segments of at most ``mss`` octets. Empty ``data`` writes nothing.

        :raises ValueError: before :meth:`open`, after that side ended, or an
            unknown ``sender``.
        """
        self._ends(sender)
        self._require(sender)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        view = bytes(data)
        for start in range(0, len(view), self.mss):
            piece = view[start : start + self.mss]
            self._segment(time, sender, "PA", piece)
            self._next[sender] = (self._next[sender] + len(piece)) % _UINT32

    def close(self, time: float, sender: str) -> None:
        """End ``sender``'s direction: its FIN, and the other side's ACK.

        The other direction stays open until its own :meth:`close`.

        :raises ValueError: as :meth:`send`.
        """
        other, _, _ = self._ends(sender)
        self._require(sender)
        self._segment(time, sender, "FA")
        self._next[sender] = (self._next[sender] + 1) % _UINT32
        self._ended[sender] = True
        if not self._ended[other]:
            self._segment(time, other, "A")

    def reset(self, time: float, sender: str) -> None:
        """Abort the connection: a RST from ``sender``; both sides end.

        :raises ValueError: before :meth:`open` or an unknown ``sender``.
        """
        self._ends(sender)
        if not self._next:
            raise ValueError("open() the connection first")
        self._segment(time, sender, "RA")
        self._ended = {"client": True, "server": True}
