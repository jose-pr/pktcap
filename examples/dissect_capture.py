"""Dissect a capture with a dissector of your own, and print one JSON line per
frame.

    python examples/dissect_capture.py [capture.pcap] ["proto=syslog and src=192.0.2.0/24"]

With no capture named, a small one is written to a temporary directory first:
two syslog messages over UDP, one TCP segment and an ARP frame. Nothing is
read from or sent to the network.

The protocol here is syslog (RFC 3164, UDP port 514), chosen because its
header is one field: ``<priority>`` and then the message. A real protocol
library ships its dissector the same way: a function, and a line that
registers it.
"""

import os
import struct
import sys
import tempfile
from typing import NamedTuple

import pktcap


class SyslogLayer(NamedTuple):
    """What the dissector below reads: the facility and the severity."""

    facility: int
    severity: int


def dissect_syslog(data: bytes) -> pktcap.Dissected:
    """``<priority>`` up to 191, then the message, which stays the payload."""
    end = data.find(b">", 1, 5)
    if not data.startswith(b"<") or end == -1 or not data[1:end].isdigit():
        raise pktcap.DissectError("a syslog message starts with <priority>")
    priority = int(data[1:end])
    if priority > 191:
        raise pktcap.DissectError("a syslog priority is 191 at most")
    return pktcap.Dissected(SyslogLayer(priority >> 3, priority & 7), data[end + 1 :])


def write_sample(path: str) -> None:
    """A capture of four Ethernet frames, built by hand."""

    def ethernet(ethertype: int, body: bytes) -> bytes:
        return (
            bytes.fromhex("020000000001")
            + bytes.fromhex("020000000002")
            + (struct.pack("!H", ethertype) + body)
        )

    def ipv4(protocol: int, body: bytes) -> bytes:
        header = struct.pack(
            "!BBHHHBBH", 0x45, 0, 20 + len(body), 1, 0, 64, protocol, 0
        )
        return header + bytes([192, 0, 2, 5, 192, 0, 2, 1]) + body

    def udp(port: int, body: bytes) -> bytes:
        return struct.pack("!HHHH", 50000, port, 8 + len(body), 0) + body

    tcp = struct.pack("!HHIIBBHHH", 50001, 80, 1, 0, 5 << 4, 0x02, 4096, 0, 0)
    frames = [
        ethernet(0x0800, ipv4(17, udp(514, b"<34>su: 'su root' failed on /dev/pts/8"))),
        ethernet(0x0800, ipv4(6, tcp)),
        ethernet(0x0806, bytes(28)),
        ethernet(0x0800, ipv4(17, udp(514, b"<165>the fan is back"))),
    ]
    with pktcap.PcapWriter(path) as writer:
        for index, data in enumerate(frames):
            writer.write_frame(pktcap.CapturedFrame(1_700_000_000 + index, 1, data))


def main(argv: list) -> int:
    with tempfile.TemporaryDirectory() as directory:
        path = argv[0] if argv else os.path.join(directory, "sample.pcap")
        if not argv:
            write_sample(path)
        # A registry of this program's own: the process-wide one is untouched.
        registry = pktcap.DissectorRegistry()
        registry.register("udp", 514, dissect_syslog)
        dissector = pktcap.FrameDissector(registry)
        wanted = pktcap.compile_capture_filter(
            argv[1] if len(argv) > 1 else None, pktcap.frame_filter
        )
        with pktcap.CaptureWriter(sys.stdout.buffer, "json") as output:
            for frame in pktcap.read_dissected(path, dissector=dissector):
                if wanted(frame):
                    output.write(frame)
        stats = dissector.stats
    print(
        "%d frames, %d malformed, %d of a link type with no dissector"
        % (stats.frames, stats.malformed, stats.unsupported),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
