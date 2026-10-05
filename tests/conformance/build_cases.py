"""Write the hand-built conformance cases. Development only.

    python tests/conformance/build_cases.py

Each case below is a capture spelled out octet by octet with the builders of
``tests/captures.py``, for a shape no capture tool can be made to write on
demand (a tag stack, a second byte order, a block that contradicts itself).
The cases written by a capture tool come from ``capture_cases.py`` instead.
Running this again rewrites the same octets; the goldens beside them are
recorded by ``record.py`` and never edited.
"""

import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import captures as build  # noqa: E402

A4, B4 = "192.0.2.5", "192.0.2.1"
A6, B6 = "2001:db8::5", "2001:db8::1"
T0 = 1_700_000_000


def _pcapng(*blocks):
    return build.section() + b"".join(blocks)


def _v4_fragments(datagram, size, ident, order=None):
    pieces = [datagram[i : i + size] for i in range(0, len(datagram), size)]
    packets = [
        build.ipv4(
            A4, B4, piece, ident=ident, offset=i * size, more=i < len(pieces) - 1
        )
        for i, piece in enumerate(pieces)
    ]
    return [packets[i] for i in order] if order else packets


def _v6_fragments(datagram, size, ident, order=None):
    pieces = [datagram[i : i + size] for i in range(0, len(datagram), size)]
    packets = [
        build.ipv6(
            A6,
            B6,
            build.ipv6_fragment(
                piece, offset=i * size, more=i < len(pieces) - 1, ident=ident
            ),
            next_header=44,
        )
        for i, piece in enumerate(pieces)
    ]
    return [packets[i] for i in order] if order else packets


def cases():
    """``{case name: (file name, octets)}``."""
    request = build.udp(50000, 69, b"\x00\x01boot.efi\x00octet\x00")
    reply = build.udp(69, 50000, bytes(range(256)) * 4)
    v4, v6 = build.ipv4(A4, B4, request), build.ipv6(A6, B6, request)
    big = build.udp(40000, 40001, bytes(range(256)) * 12)  # 3,080 octets
    out = {}

    out["read-built-ethernet-vlan"] = (
        "case.pcap",
        build.pcap(
            [
                build.ethernet(v4),
                build.ethernet(v4, vlans=1),
                build.ethernet(v6, v6=True, vlans=2),
                build.ethernet(build.ipv4(B4, A4, reply)),
            ],
            start=T0,
        ),
    )
    out["read-built-bigendian-nanosecond"] = (
        "case.pcap",
        build.pcap(
            [build.ethernet(v4), build.ethernet(v6, v6=True)],
            endian=">",
            nanoseconds=True,
            start=T0,
        ),
    )
    out["read-built-pcapng-interfaces"] = (
        "case.pcapng",
        _pcapng(
            build.interface(build.ETHERNET),
            build.interface(build.LINUX_SLL, tsresol=9),
            build.interface(build.RAW, tsresol=3, tsoffset=T0),
            build.packet(build.ethernet(v4), iface=0, stamp=T0 * 1_000_000 + 250_000),
            build.packet(
                build.linux_sll(v6, v6=True), iface=1, stamp=T0 * 10**9 + 5 * 10**8
            ),
            build.packet(v4, iface=2, stamp=750),
        ),
    )
    out["read-built-pcapng-bigendian"] = (
        "case.pcapng",
        build.pcapng(
            [build.ethernet(v4), build.ethernet(v6, v6=True)], endian=">", start=T0
        ),
    )
    out["read-built-loopback-linktypes"] = (
        "case.pcapng",
        _pcapng(
            build.interface(build.NULL),
            build.interface(build.LOOP),
            build.interface(build.LINUX_SLL2),
            build.packet(struct.pack("<I", 2) + v4, iface=0, stamp=T0 * 1_000_000),
            build.packet(struct.pack("<I", 30) + v6, iface=0, stamp=T0 * 1_000_000 + 1),
            build.packet(struct.pack(">I", 2) + v4, iface=1, stamp=T0 * 1_000_000 + 2),
            build.packet(
                build.linux_sll2(v6, v6=True), iface=2, stamp=T0 * 1_000_000 + 3
            ),
        ),
    )
    out["read-built-ipv6-extension-headers"] = (
        "case.pcap",
        build.pcap(
            [
                build.ipv6(
                    A6,
                    B6,
                    build.ipv6_extension(
                        build.ipv6_extension(request, next_header=17), next_header=60
                    ),
                    next_header=0,
                )
            ],
            linktype=build.RAW,
            start=T0,
        ),
    )
    out["read-built-ipv4-fragments-out-of-order"] = (
        "case.pcap",
        build.pcap(
            [build.ethernet(p) for p in _v4_fragments(big, 1480, 9, order=[2, 0, 1])],
            start=T0,
        ),
    )
    out["read-built-ipv6-fragments-out-of-order"] = (
        "case.pcap",
        build.pcap(
            [
                build.ethernet(p, v6=True)
                for p in _v6_fragments(big, 1232, 77, order=[1, 2, 0])
            ],
            start=T0,
        ),
    )
    first, second, third = _v4_fragments(big, 1480, 11)
    overlap = build.ipv4(A4, B4, bytes(64), ident=11, offset=1472, more=True)
    out["read-built-ipv4-fragments-overlap"] = (
        "case.pcap",
        build.pcap(
            [build.ethernet(p) for p in (first, overlap, second, third)], start=T0
        ),
    )
    out["read-built-snap-length"] = (
        "case.pcap",
        build.pcap([])
        + struct.pack(
            "<IIII", T0, 0, 96, len(build.ethernet(build.ipv4(B4, A4, reply)))
        )
        + build.ethernet(build.ipv4(B4, A4, reply))[:96],
    )
    out["read-built-not-udp"] = (
        "case.pcap",
        build.pcap(
            [
                b"\x02" * 6 + b"\x04" * 6 + b"\x08\x06" + bytes(28),  # ARP
                build.ethernet(
                    build.ipv4(A4, B4, build.tcp(50000, 47001, flags=0x02), protocol=6)
                ),
                build.ethernet(build.ipv6(A6, B6, bytes(8), next_header=58), v6=True),
                build.ethernet(v4),
            ],
            start=T0,
        ),
    )

    # Shapes on which this library gives up and tshark does not: each is one
    # of the ceilings on untrusted input, or the overlap rule.
    late = _v4_fragments(big, 1480, 13)
    out["read-built-fragments-a-minute-apart"] = (
        "case.pcap",
        build.pcap([])
        + b"".join(
            build.pcap_record(build.ethernet(p), seconds=T0 + 60 * i)
            for i, p in enumerate(late)
        ),
    )
    held = [
        build.ipv4(A4, B4, build.udp(1, 2, bytes(8))[:8], ident=1000 + i, more=True)
        for i in range(257)
    ]
    completing = build.ipv4(A4, B4, bytes(8), ident=1000, offset=8)
    # Both within one second of capture time, so age plays no part in them.
    out["read-built-reassemblies-in-flight"] = (
        "case.pcap",
        build.pcap([])
        + b"".join(
            build.pcap_record(build.ethernet(p), seconds=T0, fraction=i)
            for i, p in enumerate(held + [completing])
        ),
    )
    tiny = build.udp(7, 9, bytes(1025 * 8 - 8))
    out["read-built-fragments-without-end"] = (
        "case.pcap",
        build.pcap([])
        + b"".join(
            build.pcap_record(build.ethernet(p), seconds=T0, fraction=i)
            for i, p in enumerate(_v4_fragments(tiny, 8, 14))
        ),
    )
    out["read-built-pcapng-interfaces-without-end"] = (
        "case.pcapng",
        _pcapng(
            build.interface(build.ETHERNET) * 4097, build.packet(build.ethernet(v4))
        ),
    )
    out["read-built-empty"] = ("case.pcap", b"")

    good = build.pcap([build.ethernet(v4), build.ethernet(v6, v6=True)], start=T0)
    out["refuse-built-not-a-capture"] = ("case.pcap", b"this is not a capture\n")
    out["refuse-built-pcap-cut-in-a-packet"] = ("case.pcap", good[:-10])
    out["refuse-built-pcap-cut-in-a-record-header"] = (
        "case.pcap",
        good + b"\x01\x02\x03\x04\x05",
    )
    out["refuse-built-pcap-record-over-the-limit"] = (
        "case.pcap",
        build.pcap([build.ethernet(v4)], start=T0)
        + build.pcap_record(bytes(64), seconds=T0 + 1, captured=1 << 30),
    )
    ng = build.pcapng([build.ethernet(v4)], start=T0)
    out["refuse-built-pcapng-cut-in-a-block"] = ("case.pcapng", ng[:-6])
    out["refuse-built-pcapng-short-packet-block"] = (
        "case.pcapng",
        ng + build.block(6, bytes(8)),
    )
    out["refuse-built-pcapng-lengths-disagree"] = (
        "case.pcapng",
        ng + build.packet(build.ethernet(v6, v6=True), trailer=40),
    )
    out["refuse-built-pcapng-undescribed-interface"] = (
        "case.pcapng",
        ng + build.packet(build.ethernet(v6, v6=True), iface=3),
    )
    out["refuse-built-pcapng-block-over-the-limit"] = (
        "case.pcapng",
        ng + struct.pack("<II", 6, 1 << 30) + bytes(64),
    )
    return out


def main():
    root = HERE / "cases"
    for name, (filename, data) in sorted(cases().items()):
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / filename).write_bytes(data)
        print("%-48s %6d octets" % (name + "/" + filename, len(data)))


if __name__ == "__main__":
    main()
