"""Record the conformance cases that a capture tool writes. Development only.

    sudo python3 tests/conformance/capture_cases.py [case ...]

Linux, as root, with tcpdump and Wireshark's editcap installed. Each case is a
capture of traffic this script sends to a loopback socket it owns, taken by
tcpdump: nothing but loopback traffic on one port is recorded. Most are UDP
datagrams; one is two TCP connections, opened, used and closed. The fragment
case lowers the loopback MTU to 1500 while it runs and restores it. Four more
cases are the same captures rewritten as pcapng by editcap, and one is taken
by this library's own ``LiveCapture`` and written by its ``PcapngWriter``, so
that the reference says what it makes of them. Naming cases records only
those, and leaves the others as they were recorded.

The captures are evidence: once recorded they are committed as they are, and
``record.py`` asks tshark what is in them.
"""

import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
PORT = 47001
FRAGMENTS = "(udp port %d) or (ip[6:2] & 0x1fff != 0) or (ip6[6] == 44)" % PORT

#: ``{case: (file name, the tool's command before the output file, the filter)}``
TOOLS = {
    "read-tcpdump-loopback": (
        "case.pcap",
        ["tcpdump", "-Z", "root", "-i", "lo", "-U", "-w"],
        "udp port %d" % PORT,
    ),
    "read-tcpdump-any-device": (
        "case.pcap",
        ["tcpdump", "-Z", "root", "-i", "any", "-U", "-w"],
        "udp port %d" % PORT,
    ),
    "read-tcpdump-nanosecond": (
        "case.pcap",
        [
            "tcpdump",
            "-Z",
            "root",
            "-i",
            "lo",
            "-U",
            "--time-stamp-precision=nano",
            "-w",
        ],
        "udp port %d" % PORT,
    ),
    "read-tcpdump-fragments": (
        "case.pcap",
        ["tcpdump", "-Z", "root", "-i", "lo", "-U", "-w"],
        FRAGMENTS,
    ),
    "read-tcpdump-tcp-loopback": (
        "case.pcap",
        ["tcpdump", "-Z", "root", "-i", "lo", "-U", "-w"],
        "tcp port %d" % PORT,
    ),
}
#: The cases whose traffic is TCP connections and not UDP datagrams.
CONNECTIONS = {"read-tcpdump-tcp-loopback"}

#: pcapng written by Wireshark's own writer: ``{case: the pcap it converts}``.
#: editcap is used and not a live tshark capture because dumpcap writes the
#: capturing host's kernel release into the file, which says nothing about the
#: format and does not belong in a repository.
CONVERTED = {
    "read-editcap-loopback": "read-tcpdump-loopback",
    "read-editcap-any-device": "read-tcpdump-any-device",
    "read-editcap-nanosecond": "read-tcpdump-nanosecond",
    "read-editcap-tcp-loopback": "read-tcpdump-tcp-loopback",
}

#: The case this library captures itself: every packet on the loopback
#: device to or from the port, UDP and then TCP.
LIVE = "read-livecapture-loopback"

#: What is sent for each case: ``(host, payload)``.
PAYLOADS = {
    "read-tcpdump-fragments": [
        ("127.0.0.1", bytes(range(256)) * 16),
        ("::1", bytes(range(255, -1, -1)) * 16),
        ("127.0.0.1", b"after the fragments"),
    ],
}
DEFAULT = [
    ("127.0.0.1", b"\x00\x01boot.efi\x00octet\x00"),
    ("::1", b"\x00\x01boot.efi\x00octet\x00"),
    ("127.0.0.1", b""),
    ("127.0.0.1", bytes(range(256)) * 5),
    ("::1", bytes(1200)),
]


def send(payloads):
    receivers = {}
    for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.bind((host, PORT))
        receivers[host] = sock
    try:
        for host, payload in payloads:
            family = receivers[host].family
            with socket.socket(family, socket.SOCK_DGRAM) as sender:
                sender.bind((host, PORT + 1))
                sender.sendto(payload, (host, PORT))
            receivers[host].settimeout(2)
            receivers[host].recvfrom(65535)
            time.sleep(0.05)
    finally:
        for sock in receivers.values():
            sock.close()


def converse():
    """One TCP connection over each IP version: a request, a longer answer in
    two writes, and an orderly close from both ends."""
    for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, PORT))
            listener.listen(1)
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect((host, PORT))
                server, _ = listener.accept()
                with server:
                    server.settimeout(2)
                    client.sendall(b"request " + bytes(range(64)))
                    server.recv(4096)
                    server.sendall(bytes(range(256)) * 4)
                    time.sleep(0.05)
                    server.sendall(b"the end")
                    time.sleep(0.05)
                    while client.recv(4096)[-7:] != b"the end":
                        pass
                    client.shutdown(socket.SHUT_WR)
                    server.recv(4096)
        time.sleep(0.05)


def record(name, workdir):
    filename, command, capture_filter = TOOLS[name]
    target = workdir / filename
    tool = subprocess.Popen(
        command + [str(target), capture_filter], stderr=subprocess.PIPE
    )
    try:
        time.sleep(2.0)  # the tool says it is listening before it is
        if name in CONNECTIONS:
            converse()
        else:
            send(PAYLOADS.get(name, DEFAULT))
        time.sleep(1.0)
    finally:
        tool.send_signal(signal.SIGINT)
        tool.wait(timeout=10)
    destination = HERE / "cases" / name
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(target, destination / filename)
    print("%-32s %6d octets" % (name, (destination / filename).stat().st_size))


def record_live():
    """The loopback traffic of this script, taken by ``pktcap.LiveCapture``."""
    import pktcap

    wanted = pktcap.compile_capture_filter("port=%d" % PORT, pktcap.frame_filter)
    dissector = pktcap.FrameDissector()
    kept = []

    def traffic():
        time.sleep(0.5)
        send(DEFAULT[:3])
        converse()

    sender = threading.Thread(target=traffic)
    with pktcap.LiveCapture("lo", timeout=0.5) as capture:
        sender.start()
        while True:
            frame = capture.read()
            if frame is None:
                if not sender.is_alive():
                    break
            elif wanted(dissector.dissect(frame)):
                kept.append(frame)
        sender.join()
    destination = HERE / "cases" / LIVE
    destination.mkdir(parents=True, exist_ok=True)
    with pktcap.PcapngWriter(destination / "case.pcapng") as writer:
        for frame in kept:
            writer.write_frame(frame)
    print("%-32s %6d frames" % (LIVE, len(kept)))


def main(wanted):
    unknown = set(wanted) - set(TOOLS) - set(CONVERTED) - {LIVE}
    if unknown:
        raise SystemExit("no such case: %s" % ", ".join(sorted(unknown)))
    with tempfile.TemporaryDirectory() as temporary:
        workdir = pathlib.Path(temporary)
        for name in sorted(TOOLS):
            if wanted and name not in wanted:
                continue
            if name == "read-tcpdump-fragments":
                subprocess.run(["ip", "link", "set", "lo", "mtu", "1500"], check=True)
            try:
                record(name, workdir)
            finally:
                if name == "read-tcpdump-fragments":
                    subprocess.run(
                        ["ip", "link", "set", "lo", "mtu", "65536"], check=True
                    )
    if not wanted or LIVE in wanted:
        record_live()
    for name, source in sorted(CONVERTED.items()):
        if wanted and name not in wanted:
            continue
        destination = HERE / "cases" / name
        destination.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "editcap",
                "-F",
                "pcapng",
                str(HERE / "cases" / source / "case.pcap"),
                str(destination / "case.pcapng"),
            ],
            check=True,
        )
        print("%-32s %6d octets" % (name, (destination / "case.pcapng").stat().st_size))


if __name__ == "__main__":
    main(sys.argv[1:])
