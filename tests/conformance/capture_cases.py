"""Record the conformance cases that a capture tool writes. Development only.

    sudo python3 tests/conformance/capture_cases.py

Linux, as root, with tcpdump and Wireshark's editcap installed. Each case is a
capture of UDP datagrams this script sends to a loopback socket it owns, taken
by tcpdump: nothing but loopback traffic on one port is recorded. The fragment
case lowers the loopback MTU to 1500 while it runs and restores it. Three more
cases are the same captures rewritten as pcapng by editcap.

The captures are evidence: once recorded they are committed as they are, and
``record.py`` asks tshark what is in them.
"""

import pathlib
import shutil
import signal
import socket
import subprocess
import tempfile
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
}

#: pcapng written by Wireshark's own writer: ``{case: the pcap it converts}``.
#: editcap is used and not a live tshark capture because dumpcap writes the
#: capturing host's kernel release into the file, which says nothing about the
#: format and does not belong in a repository.
CONVERTED = {
    "read-editcap-loopback": "read-tcpdump-loopback",
    "read-editcap-any-device": "read-tcpdump-any-device",
    "read-editcap-nanosecond": "read-tcpdump-nanosecond",
}

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


def record(name, workdir):
    filename, command, capture_filter = TOOLS[name]
    target = workdir / filename
    tool = subprocess.Popen(
        command + [str(target), capture_filter], stderr=subprocess.PIPE
    )
    try:
        time.sleep(2.0)  # the tool says it is listening before it is
        send(PAYLOADS.get(name, DEFAULT))
        time.sleep(1.0)
    finally:
        tool.send_signal(signal.SIGINT)
        tool.wait(timeout=10)
    destination = HERE / "cases" / name
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(target, destination / filename)
    print("%-32s %6d octets" % (name, (destination / filename).stat().st_size))


def main():
    with tempfile.TemporaryDirectory() as temporary:
        workdir = pathlib.Path(temporary)
        for name in sorted(TOOLS):
            if name == "read-tcpdump-fragments":
                subprocess.run(["ip", "link", "set", "lo", "mtu", "1500"], check=True)
            try:
                record(name, workdir)
            finally:
                if name == "read-tcpdump-fragments":
                    subprocess.run(
                        ["ip", "link", "set", "lo", "mtu", "65536"], check=True
                    )
    for name, source in sorted(CONVERTED.items()):
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
    main()
