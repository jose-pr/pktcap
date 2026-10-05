"""The performance suite. Run on demand, never in CI.

    python benchmarks/run.py            # print a table
    python benchmarks/run.py --save     # also write benchmarks/results/<name>.json

Each metric is one call of a whole operation over a fixed, synthetic input,
timed ``--samples`` times; the table and the JSON give the minimum, the median
and the maximum in milliseconds. Compare medians: a single average hides the
run-to-run noise of a shared machine.
"""

import argparse
import io
import json
import pathlib
import platform
import statistics
import struct
import sys
import sysconfig
import time

import pktcap

RESULTS = pathlib.Path(__file__).resolve().parent / "results"
FRAMES = 2000


def _udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _ipv4(body, ident=1, offset=0, more=False):
    flags = (0x2000 if more else 0) | (offset // 8)
    return (
        struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(body), ident, flags, 64, 17, 0)
        + bytes([192, 0, 2, 5, 192, 0, 2, 1])
        + body
    )


def _ethernet(ip):
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip


def _pcap(frames):
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)]
    for index, frame in enumerate(frames):
        out.append(struct.pack("<IIII", 1_700_000_000, index, len(frame), len(frame)))
        out.append(frame)
    return b"".join(out)


def _pcapng(frames):
    def block(kind, body):
        body += b"\0" * (-len(body) % 4)
        size = struct.pack("<I", 12 + len(body))
        return struct.pack("<I", kind) + size + body + size

    out = [
        block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)),
        block(1, struct.pack("<HHI", 1, 0, 262144)),
    ]
    for index, frame in enumerate(frames):
        head = struct.pack("<IIIII", 0, 395812, index, len(frame), len(frame))
        out.append(block(6, head + frame))
    return b"".join(out)


def _inputs():
    payload = bytes(512)
    whole = [_ethernet(_ipv4(_udp(50000, 69, payload), ident=i)) for i in range(FRAMES)]
    big = _udp(50000, 69, bytes(4096))
    pieces = [big[i : i + 1480] for i in range(0, len(big), 1480)]
    fragmented = [
        _ethernet(_ipv4(piece, ident=i, offset=n * 1480, more=n < len(pieces) - 1))
        for i in range(FRAMES // len(pieces))
        for n, piece in enumerate(pieces)
    ]
    tiny = [
        pktcap.CapturedFrame(
            0.0, 101, _ipv4(bytes(8), ident=7, offset=8 * n, more=True)
        )
        for n in range(1000)
    ]
    return {
        "pcap": _pcap(whole),
        "pcapng": _pcapng(whole),
        "fragments": _pcap(fragmented),
        "tiny": tiny,
        "datagrams": list(pktcap.read_datagrams(io.BytesIO(_pcap(whole)))),
    }


def metrics(inputs):
    """``{name: callable}``; each call is one whole operation."""
    datagrams = inputs["datagrams"]

    def write():
        with pktcap.PcapWriter(io.BytesIO()) as writer:
            for datagram in datagrams:
                writer.write_datagram(datagram)

    def tiny_fragments():
        decoder = pktcap.FrameDecoder()
        for frame in inputs["tiny"]:
            decoder.decode(frame)

    def records():
        for datagram in datagrams:
            pktcap.dumps_record(pktcap.datagram_record(datagram))

    def filtered():
        wanted = pktcap.compile_capture_filter(
            "port=69 and port!=7", lambda c: lambda d: d.destination[1] == int(c.value)
        )
        return sum(1 for datagram in datagrams if wanted(datagram))

    return {
        "read_frames/pcap-2000": lambda: sum(
            1 for _ in pktcap.read_frames(io.BytesIO(inputs["pcap"]))
        ),
        "read_frames/pcapng-2000": lambda: sum(
            1 for _ in pktcap.read_frames(io.BytesIO(inputs["pcapng"]))
        ),
        "read_datagrams/ethernet-ipv4-2000": lambda: sum(
            1 for _ in pktcap.read_datagrams(io.BytesIO(inputs["pcap"]))
        ),
        "read_datagrams/fragments-3x666": lambda: sum(
            1 for _ in pktcap.read_datagrams(io.BytesIO(inputs["fragments"]))
        ),
        "decode/1000-fragments-of-one-datagram": tiny_fragments,
        "PcapWriter.write/2000": write,
        "dumps_record/json-2000": records,
        "compile_capture_filter/apply-2000": filtered,
    }


def measure(function, samples):
    function()  # warm up
    timings = []
    for _ in range(samples):
        started = time.perf_counter()
        function()
        timings.append((time.perf_counter() - started) * 1000.0)
    return {
        "min_ms": round(min(timings), 4),
        "median_ms": round(statistics.median(timings), 4),
        "max_ms": round(max(timings), 4),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--samples", type=int, default=15)
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--name", help="result file name, without .json")
    arguments = parser.parse_args(argv)
    results = {
        name: measure(function, arguments.samples)
        for name, function in metrics(_inputs()).items()
    }
    print("%-42s %10s %10s %10s" % ("metric (ms per call)", "min", "median", "max"))
    for name, timing in results.items():
        print(
            "%-42s %10.3f %10.3f %10.3f"
            % (name, timing["min_ms"], timing["median_ms"], timing["max_ms"])
        )
    if arguments.save:
        tag = sysconfig.get_platform().replace("-", "_")
        name = arguments.name or "%s-%s-py%d.%d" % (
            pktcap.__version__,
            tag,
            sys.version_info[0],
            sys.version_info[1],
        )
        document = {
            "version": pktcap.__version__,
            "python": platform.python_version(),
            "platform": sysconfig.get_platform(),
            "samples": arguments.samples,
            "unit": "milliseconds per call",
            "metrics": results,
        }
        RESULTS.mkdir(exist_ok=True)
        target = RESULTS / (name + ".json")
        target.write_bytes((json.dumps(document, indent=2) + "\n").encode("utf-8"))
        print("saved", target.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
