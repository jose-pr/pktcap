"""Write the hand-built conformance cases. Development only.

    python tests/conformance/build_cases.py

Each case below is a capture spelled out octet by octet with the builders of
``tests/captures.py``, for a shape no capture tool can be made to write on
demand (a tag stack, a second byte order, a block that contradicts itself).
The cases written by a capture tool come from ``capture_cases.py`` instead.
Three ``write-`` cases are built here too: the frames a writer is asked to
write, as ``case.json``. Running this again rewrites the same octets; the
goldens beside them are recorded by ``record.py`` and never edited.
"""

import json
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


# TCP streams: a client at ``A4`` and a server at ``B4``. Every case is
# spelled out segment by segment, so the sequence numbers are the question.
PSH_ACK, SYN, SYN_ACK, FIN_ACK, RST_ACK, ACK = 0x18, 0x02, 0x12, 0x11, 0x14, 0x10
CLIENT, SERVER = (A4, 50000), (B4, 80)


def _segment(sender, seq, ack, data=b"", flags=PSH_ACK, *, v6=False):
    """One Ethernet frame holding a TCP segment from the client or the server."""
    source, target = (CLIENT, SERVER) if sender == "c" else (SERVER, CLIENT)
    if v6:
        hosts = (A6, B6) if sender == "c" else (B6, A6)
        source, target = (hosts[0], source[1]), (hosts[1], target[1])
    return build.tcp_frame(
        source[0],
        target[0],
        source[1],
        target[1],
        seq,
        data,
        flags=flags,
        acknowledgment=ack,
    )


def _opening(client_isn=1000, server_isn=5000, **kw):
    """The three-way handshake."""
    return [
        _segment("c", client_isn, 0, flags=SYN, **kw),
        _segment("s", server_isn, client_isn + 1, flags=SYN_ACK, **kw),
        _segment("c", client_isn + 1, server_isn + 1, flags=ACK, **kw),
    ]


def tcp_cases():
    """``{case name: (file name, octets)}`` for the TCP stream cases."""
    out = {}
    request = b"GET /index HTTP/1.1\r\nHost: x\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    c1, s1 = 1001, 5001

    def exchange(**kw):
        return _opening(**kw) + [
            _segment("c", c1, s1, request, **kw),
            _segment("s", s1, c1 + len(request), flags=ACK, **kw),
            _segment("s", s1, c1 + len(request), response, **kw),
            _segment("c", c1 + len(request), s1 + len(response), flags=FIN_ACK, **kw),
            _segment(
                "s", s1 + len(response), c1 + len(request) + 1, flags=FIN_ACK, **kw
            ),
            _segment(
                "c", c1 + len(request) + 1, s1 + len(response) + 1, flags=ACK, **kw
            ),
        ]

    def pcap(frames):
        return ("case.pcap", build.pcap(frames, start=T0))

    out["read-built-tcp-stream-exchange"] = pcap(exchange())
    out["read-built-tcp-stream-ipv6"] = pcap(exchange(v6=True))

    message = bytes(range(65, 65 + 40))  # 40 octets in four pieces of ten
    pieces = [(c1 + 10 * i, message[10 * i : 10 * i + 10]) for i in range(4)]
    out["read-built-tcp-stream-out-of-order"] = pcap(
        _opening()
        + [
            _segment("c", seq, s1, data)
            for seq, data in [pieces[i] for i in (3, 1, 0, 2)]
        ]
        + [_segment("s", s1, c1 + 40, flags=ACK)]
    )
    out["read-built-tcp-stream-retransmission"] = pcap(
        _opening()
        + [
            _segment("c", c1, s1, b"aaaaaaaa"),
            _segment("c", c1, s1, b"aaaaaaaa"),
            _segment("c", c1 + 8, s1, b"bbbbbbbb"),
            _segment("c", c1, s1, b"aaaaaaaa"),
            _segment("c", c1 + 4, s1, b"aaaabbbb"),
            _segment("c", c1 + 16, s1, b"cccccccc"),
        ]
    )
    # A hole, two copies of the octets beyond it, then the octets that fill it.
    out["read-built-tcp-stream-overlap-agrees"] = pcap(
        _opening()
        + [
            _segment("c", c1 + 10, s1, b"ABCDEFGHIJ"),
            _segment("c", c1 + 15, s1, b"FGHIJklmno"),
            _segment("c", c1, s1, b"0123456789"),
        ]
    )
    out["read-built-tcp-stream-overlap-disagrees"] = pcap(
        _opening()
        + [
            _segment("c", c1 + 10, s1, b"ABCDEFGHIJ"),
            _segment("c", c1 + 15, s1, b"fghijklmno"),
            _segment("c", c1, s1, b"0123456789"),
        ]
    )
    lost = b"lost in capture"
    out["read-built-tcp-stream-missing-acknowledged"] = pcap(
        _opening()
        + [
            _segment("c", c1, s1, b"head"),
            _segment("c", c1 + 4 + len(lost), s1, b"tail"),
            _segment("s", s1, c1 + 8 + len(lost), flags=ACK),
            _segment("s", s1, c1 + 8 + len(lost), b"reply"),
        ]
    )
    out["read-built-tcp-stream-missing-unacknowledged"] = pcap(
        _opening()
        + [
            _segment("c", c1, s1, b"head"),
            _segment("c", c1 + 4 + len(lost), s1, b"tail"),
            _segment("c", c1 + 8 + len(lost), s1, b"more"),
        ]
    )
    out["read-built-tcp-stream-mid-capture"] = pcap(
        [
            _segment("c", 700000, 90000, b"already running, "),
            _segment("s", 90000, 700017, b"reply one"),
            _segment("c", 700017, 90009, b"and on"),
            _segment("s", 90009, 700023, b" and two"),
        ]
    )
    wrap = 0xFFFFFFF0
    wrapped = [(wrap + 1 + 10 * i, message[10 * i : 10 * i + 10]) for i in range(4)]
    out["read-built-tcp-stream-sequence-wraps"] = pcap(
        _opening(client_isn=wrap)
        + [
            _segment("c", seq & 0xFFFFFFFF, s1, data)
            for seq, data in [wrapped[i] for i in (0, 2, 1, 3)]
        ]
    )
    out["read-built-tcp-stream-reset"] = pcap(
        _opening()
        + [
            _segment("c", c1, s1, b"before the reset"),
            _segment("s", s1, c1 + 16, b"reply"),
            _segment("s", s1 + 5, c1 + 16, flags=RST_ACK),
            _segment("c", c1 + 16, s1 + 5, b"after the reset"),
        ]
    )
    again = exchange()
    out["read-built-tcp-stream-same-addresses-twice"] = pcap(
        again
        + _opening(client_isn=900000, server_isn=300000)
        + [
            _segment("c", 900001, 300001, b"second connection"),
            _segment("s", 300001, 900018, b"second reply"),
            _segment("c", 900018, 300013, flags=FIN_ACK),
        ]
    )
    return out


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

    # TCP, under each shape of VLAN tag: 802.1Q, with a priority, the 802.1ad
    # stack, the drop-eligible bit, the older 0x9100 outer tag, and none.
    mss = bytes([2, 4, 5, 180])
    opening = build.tcp(
        50000, 47001, flags=0x02, sequence=100, acknowledgment=0, options=mss
    )
    answer = build.tcp(
        47001, 50000, flags=0x12, sequence=900, acknowledgment=101, options=mss
    )
    segment = build.tcp(
        50000, 47001, b"sixteen octets..", sequence=101, acknowledgment=901
    )
    closing = build.tcp(47001, 50000, flags=0x11, sequence=901, acknowledgment=117)
    reset = build.tcp(50000, 47001, flags=0x04, sequence=117, acknowledgment=0)
    out["read-built-tcp-vlan"] = (
        "case.pcap",
        build.pcap(
            [
                build.ethernet(
                    build.ipv4(A4, B4, opening, protocol=6), tags=[(0x8100, 100)]
                ),
                build.ethernet(
                    build.ipv4(B4, A4, answer, protocol=6),
                    tags=[(0x8100, 5 << 13 | 100)],
                ),
                build.ethernet(
                    build.ipv6(A6, B6, segment, next_header=6),
                    v6=True,
                    tags=[(0x88A8, 100), (0x8100, 200)],
                ),
                build.ethernet(
                    build.ipv6(B6, A6, closing, next_header=6),
                    v6=True,
                    tags=[(0x8100, 0x1000 | 7)],
                ),
                build.ethernet(
                    build.ipv4(A4, B4, reset, protocol=6),
                    tags=[(0x9100, 300), (0x8100, 400)],
                ),
                build.ethernet(build.ipv4(A4, B4, segment, protocol=6)),
                build.ethernet(v4, tags=[(0x8100, 100)]),
            ],
            start=T0,
        ),
    )
    # A link type with no dissector beside one with: every frame is read, and
    # the frame nothing dissects is counted and kept whole.
    out["read-built-linktype-without-dissector"] = (
        "case.pcapng",
        _pcapng(
            build.interface(build.ETHERNET),
            build.interface(147),  # LINKTYPE_USER0: private use, by definition
            build.packet(build.ethernet(v4), iface=0, stamp=T0 * 1_000_000),
            build.packet(b"private framing", iface=1, stamp=T0 * 1_000_000 + 1),
            build.packet(
                build.ethernet(v6, v6=True), iface=0, stamp=T0 * 1_000_000 + 2
            ),
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
    out.update(tcp_cases())
    return out


def questions():
    """``{case name: the case.json of a write- case}``: what a writer is asked
    to write, for the reference to read back."""
    request = build.udp(50000, 69, b"\x00\x01boot.efi\x00octet\x00")
    v4, v6 = build.ipv4(A4, B4, request), build.ipv6(A6, B6, request)
    segment = build.tcp(50000, 47001, b"sixteen octets..", sequence=101)
    tagged = build.ethernet(
        build.ipv6(A6, B6, segment, next_header=6),
        v6=True,
        tags=[(0x88A8, 100), (0x8100, 200)],
    )
    arp = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x06" + bytes(28)

    def frames(*rows):
        return [[time, linktype, data.hex()] for time, linktype, data in rows]

    out = {}
    out["write-pcapwriter-frames"] = {
        "question": "Does tshark read the frames PcapWriter writes back as "
        "the frames they were?",
        "writer": "pcap",
        "frames": frames(
            (T0, 1, build.ethernet(v4, tags=[(0x8100, 100)])),
            (T0 + 0.25, 1, arp),
            (T0 + 0.5, 1, tagged),
            (T0 + 1.999999, 1, build.ethernet(v6, v6=True)),
        ),
    }
    out["write-pcapngwriter-frames"] = {
        "question": "Does tshark read frames of several link types, written "
        "into one file by PcapngWriter, as the frames they were?",
        "writer": "pcapng",
        "frames": frames(
            (T0, 1, build.ethernet(v4)),
            (T0 + 0.25, 101, v6),
            (T0 + 0.5, 113, build.linux_sll(v4)),
            (T0 + 0.75, 276, build.linux_sll2(v6, v6=True)),
            (T0 + 1.0, 0, struct.pack("<I", 2) + v4),
            (T0 + 1.5, 1, tagged),
            (T0 + 1.75, 147, b"private framing"),
            (T0 + 1.999999, 101, build.ipv4(A4, B4, segment, protocol=6)),
        ),
    }
    out["write-pcapngwriter-datagrams"] = {
        "question": "Does tshark read what PcapngWriter writes as these "
        "datagrams, with every checksum good?",
        "writer": "pcapng",
        "datagrams": [
            [T0, [A4, 50000], [B4, 69], "0001626f6f742e656669006f6374657400"],
            [T0 + 0.25, [B4, 40000], [A4, 50000], ""],
            [T0 + 0.75, [A6, 546], ["ff02::1:2", 547], "010203"],
            [T0 + 1.999999, ["::ffff:" + A4, 68], ["::ffff:" + B4, 67], "00ff00ff00"],
            [T0 + 2.0, [A4, 68], [B6, 67], "abcdef"],
        ],
    }
    return out


def main():
    root = HERE / "cases"
    for name, (filename, data) in sorted(cases().items()):
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / filename).write_bytes(data)
        print("%-48s %6d octets" % (name + "/" + filename, len(data)))
    for name, question in sorted(questions().items()):
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        text = json.dumps(question, indent=1) + "\n"
        (directory / "case.json").write_bytes(text.encode("utf-8"))
        print("%-48s %6d octets" % (name + "/case.json", len(text)))


if __name__ == "__main__":
    main()
