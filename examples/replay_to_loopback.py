"""Replay the UDP datagrams of a capture to a listener on this host.

    python examples/replay_to_loopback.py [capture.pcap] [speed]

With no capture named, one is written to a temporary directory first: three
datagrams a quarter of a second apart. The listener is a UDP socket this
script binds on the loopback address, so nothing leaves the host: whatever
addresses the capture recorded, every payload goes to the one destination
named here. ``speed`` is how much faster than recorded to replay (``1`` by
default; ``0`` removes the waits).
"""

import os
import socket
import sys
import tempfile
import threading
import time

from netimps import bind

import pktcap


def write_sample(path: str) -> None:
    with pktcap.PcapWriter(path) as writer:
        for index, payload in enumerate((b"first", b"second", b"third")):
            writer.write(
                1_700_000_000 + index * 0.25,
                ("198.51.100.7", 40000),
                ("203.0.113.9", 514),
                payload,
            )


def main(argv: list) -> int:
    speed = float(argv[1]) if len(argv) > 1 else 1.0
    with tempfile.TemporaryDirectory() as directory:
        path = argv[0] if argv else os.path.join(directory, "sample.pcap")
        if not argv:
            write_sample(path)
        listener = bind("127.0.0.1", 0)  # a UDP socket on a free loopback port
        listener.settimeout(0.2)
        port = listener.getsockname()[1]
        received = []
        done = threading.Event()

        def listen() -> None:
            while not done.is_set():
                try:
                    data, sender = listener.recvfrom(65535)
                except socket.timeout:  # not the builtin TimeoutError before 3.10
                    continue
                received.append((time.monotonic(), sender, data))

        thread = threading.Thread(target=listen, daemon=True)
        thread.start()
        started = time.monotonic()
        result = pktcap.replay_to(path, "127.0.0.1", port, speed=speed or None)
        time.sleep(0.5)  # the last datagram is still on its way to the listener
        done.set()
        thread.join()
        listener.close()
    for when, sender, data in received:
        print("%6.3fs  %s:%d  %r" % (when - started, sender[0], sender[1], data))
    print("sent %d, passed over %d partial" % (result.sent, result.partial))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
