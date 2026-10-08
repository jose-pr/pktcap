"""Record what the reference says about each conformance case. Development only.

    python tests/conformance/record.py            # write every golden.json
    python tests/conformance/record.py --check    # re-record in memory, report drift

The reference is tshark, which must be on ``PATH``; ``pktcap`` must be
importable for the ``write-`` cases, whose input is what a writer makes of
``case.json``. A golden is what tshark answered, with its version, and is
never edited by hand. ``test_conformance.py`` replays the goldens and needs
neither this script nor tshark.

A golden holds up to three readings of the capture: ``layers``, one row per
frame of the fields tshark printed for the layers this library has dissectors
for; ``datagrams``, one row per UDP datagram with its payload; and, for a
capture with TCP in it, ``streams``, the octets of each direction of each TCP
stream as tshark's ``follow`` gives them.
"""

import hashlib
import json
import pathlib
import platform
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CASES = HERE / "cases"

#: One line per UDP datagram. ICMP errors quote the datagram that caused
#: them, and are not datagrams.
FILTER = "udp && !icmp && !icmpv6"
FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "udp.srcport",
    "ip.dst",
    "ipv6.dst",
    "udp.dstport",
    "udp.length",
    "udp.payload",
    "ip.checksum.status",
    "udp.checksum.status",
]
#: One line per frame. A field that occurs more than once in a frame (two
#: VLAN tags, a packet quoted by an ICMP error) is printed once per
#: occurrence, comma separated, outermost first.
LAYER_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.cap_len",
    "frame.interface_id",
    "frame.protocols",
    "eth.dst",
    "eth.src",
    "eth.type",
    "vlan.id",
    "vlan.priority",
    "vlan.dei",
    "vlan.etype",
    "ieee8021ad.id",
    "ieee8021ad.priority",
    "ieee8021ad.dei",
    "sll.pkttype",
    "sll.hatype",
    "sll.ifindex",
    "sll.etype",
    "null.family",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "ip.ttl",
    "ip.id",
    "ip.len",
    "ip.flags.df",
    "ip.flags.mf",
    "ip.frag_offset",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.nxt",
    "ipv6.hlim",
    "ipv6.plen",
    "ipv6.fraghdr.offset",
    "ipv6.fraghdr.more",
    "ipv6.fraghdr.ident",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.hdr_len",
    "tcp.options",
    "tcp.payload",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
]
#: Per-frame rows are kept for captures of at most this many frames: the
#: cases about a ceiling have thousands, each the same as the last.
MOST_LAYER_ROWS = 64
#: Checksums are verified for what a writer wrote, where they are the
#: question. A capture is read with tshark's own defaults, which is what its
#: users have: with verification on, tshark does not reassemble a fragment
#: whose IP checksum is wrong.
VERIFY = ["-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE"]


def _tshark(arguments):
    return subprocess.run(
        ["tshark"] + arguments, capture_output=True, text=True, timeout=120
    )


def _reference():
    version = _tshark(["--version"]).stdout.splitlines()[0].strip()
    return {
        "tshark": version,
        "environment": "%s %s" % (platform.system(), platform.machine()),
    }


def _fields(path, fields, extra):
    arguments = ["-r", str(path)] + extra + ["-T", "fields", "-E", "separator=|"]
    for field in fields:
        arguments += ["-e", field]
    return [
        dict(zip(fields, line.split("|")))
        for line in _tshark(arguments).stdout.splitlines()
    ]


#: What ``follow`` prints in place of octets the capture does not hold, in
#: hex: "[15 bytes missing in capture file]" and a NUL.
_MISSING = re.compile(rb"\[(\d+) bytes? missing in capture file\]\x00")


def _follow(text):
    """One stream of ``follow,tcp,raw`` output as plain data.

    ``nodes`` are the two socket addresses as tshark names them, in its order;
    ``runs[i]`` is what node ``i`` sent: ``[octets missing before, hex]`` for
    each run of octets with no gap inside. The chunks tshark prints, one per
    segment, are joined; a line indented by a tab is node 1's.
    """
    nodes = [None, None]
    runs = [[], []]
    gap = [0, 0]
    inside = False
    for line in text.splitlines():
        if line.startswith("Node "):
            nodes[int(line[5])] = line.split(": ", 1)[1].strip()
            inside = line.startswith("Node 1")
        elif inside and line.strip() and not line.startswith("="):
            side = 1 if line.startswith("\t") else 0
            raw = bytes.fromhex(line.strip())
            marker = _MISSING.fullmatch(raw)
            if marker:
                gap[side] += int(marker.group(1))
            elif runs[side] and not gap[side]:
                runs[side][-1][1] += raw.hex()
            else:
                runs[side].append([gap[side], raw.hex()])
                gap[side] = 0
    return {"nodes": nodes, "runs": runs}


def _streams(path):
    """tshark's follow of every TCP stream in the capture, or ``None``."""
    listed = _tshark(["-r", str(path), "-T", "fields", "-e", "tcp.stream"])
    numbers = sorted({int(n) for n in re.findall(r"\d+", listed.stdout)})
    if not numbers:
        return None
    out = []
    for number in numbers:
        shown = _tshark(["-r", str(path), "-q", "-z", "follow,tcp,raw,%d" % number])
        out.append(dict(_follow(shown.stdout), stream=number))
    return out


def _ask(path, verify=False):
    """tshark's reading of one capture file, as plain data."""
    frames = _tshark(["-r", str(path), "-T", "fields", "-e", "frame.number"])
    options = VERIFY if verify else []
    datagrams = []
    for row in _fields(path, FIELDS, options + ["-Y", FILTER, "-E", "occurrence=l"]):
        datagrams.append(
            {
                "frame": int(row["frame.number"]),
                "time": row["frame.time_epoch"],
                "source": [row["ip.src"] or row["ipv6.src"], int(row["udp.srcport"])],
                "destination": [
                    row["ip.dst"] or row["ipv6.dst"],
                    int(row["udp.dstport"]),
                ],
                "udp_length": int(row["udp.length"]),
                "payload": row["udp.payload"],
                "ip_checksum": row["ip.checksum.status"],
                "udp_checksum": row["udp.checksum.status"],
            }
        )
    count = len(frames.stdout.split())
    layers = None
    if count <= MOST_LAYER_ROWS:
        rows = _fields(path, LAYER_FIELDS, ["-E", "occurrence=a", "-E", "aggregator=,"])
        # Only what tshark printed: a field a frame does not have is left out.
        layers = [{name: value for name, value in row.items() if value} for row in rows]
    error = None
    if frames.returncode:
        # The message names the file by the path it was given: drop it.
        error = frames.stderr.strip().splitlines()[0].replace(str(path), "case")
    asked = {
        "exit_status": frames.returncode,
        "error": error,
        "frames": count,
        "layers": layers,
        "datagrams": datagrams,
    }
    streams = _streams(path) if not frames.returncode else None
    if streams is not None:
        asked["streams"] = streams
    return asked


def written(question):
    """The capture file a ``write-`` case asks a writer for, as octets.

    ``question`` is the case's ``case.json``: the writer by its format name,
    and either datagrams to put in frames or frames to write as they are.
    """
    import io

    from pktcap import CapturedFrame, PcapngWriter, PcapWriter

    stream = io.BytesIO()
    writer_type = PcapngWriter if question.get("writer") == "pcapng" else PcapWriter
    with writer_type(stream) as writer:
        for time, source, destination, payload in question.get("datagrams", ()):
            writer.write(
                time, tuple(source), tuple(destination), bytes.fromhex(payload)
            )
        for time, linktype, data in question.get("frames", ()):
            writer.write_frame(CapturedFrame(time, linktype, bytes.fromhex(data)))
    return stream.getvalue()


def record(case, reference):
    golden = {"reference": reference}
    if case.name.startswith("write-"):
        question = json.loads((case / "case.json").read_text(encoding="utf-8"))
        data = written(question)
        golden["sha256"] = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "case"
            path.write_bytes(data)
            golden.update(_ask(path, verify=True))
    else:
        (path,) = [p for p in case.iterdir() if p.name.startswith("case.")]
        golden.update(_ask(path))
    return golden


def main(argv):
    check = "--check" in argv
    reference = _reference()
    drift = 0
    for case in sorted(p for p in CASES.iterdir() if p.is_dir()):
        golden = record(case, reference)
        text = json.dumps(golden, indent=1, sort_keys=True) + "\n"
        target = case / "golden.json"
        if check:
            current = target.read_text(encoding="utf-8") if target.exists() else ""
            if current != text:
                drift += 1
                print("DRIFT  %s" % case.name)
        else:
            target.write_bytes(text.encode("utf-8"))
            print(
                "%-46s exit %-2d %4d frames %3d datagrams"
                % (
                    case.name,
                    golden["exit_status"],
                    golden["frames"],
                    len(golden["datagrams"]),
                )
            )
    if check:
        print("%d of the goldens differ from %s" % (drift, reference["tshark"]))
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
