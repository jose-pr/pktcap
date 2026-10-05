"""Record what the reference says about each conformance case. Development only.

    python tests/conformance/record.py            # write every golden.json
    python tests/conformance/record.py --check    # re-record in memory, report drift

The reference is tshark, which must be on ``PATH``; ``pktcap`` must be
importable for the ``write-`` cases, whose input is what ``PcapWriter`` makes
of ``case.json``. A golden is what tshark answered, with its version, and is
never edited by hand. ``test_conformance.py`` replays the goldens and needs
neither this script nor tshark.
"""

import hashlib
import json
import pathlib
import platform
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
#: Checksums are verified for what PcapWriter wrote, where they are the
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


def _ask(path, verify=False):
    """tshark's reading of one capture file, as plain data."""
    frames = _tshark(["-r", str(path), "-T", "fields", "-e", "frame.number"])
    options = VERIFY if verify else []
    arguments = ["-r", str(path)] + options + ["-Y", FILTER, "-T", "fields"]
    arguments += ["-E", "separator=|", "-E", "occurrence=l"]
    for field in FIELDS:
        arguments += ["-e", field]
    decoded = _tshark(arguments)
    datagrams = []
    for line in decoded.stdout.splitlines():
        row = dict(zip(FIELDS, line.split("|")))
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
    error = None
    if frames.returncode:
        # The message names the file by the path it was given: drop it.
        error = frames.stderr.strip().splitlines()[0].replace(str(path), "case")
    return {
        "exit_status": frames.returncode,
        "error": error,
        "frames": len(frames.stdout.split()),
        "datagrams": datagrams,
    }


def _written(case):
    """The pcap that ``PcapWriter`` makes of a ``write-`` case."""
    import io

    from pktcap import PcapWriter

    question = json.loads((case / "case.json").read_text(encoding="utf-8"))
    stream = io.BytesIO()
    with PcapWriter(stream) as writer:
        for time, source, destination, payload in question["datagrams"]:
            writer.write(
                time, tuple(source), tuple(destination), bytes.fromhex(payload)
            )
    return stream.getvalue()


def record(case, reference):
    golden = {"reference": reference}
    if case.name.startswith("write-"):
        data = _written(case)
        golden["pcap_sha256"] = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "case.pcap"
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
                "%-46s exit %-2d %3d frames %3d datagrams"
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
