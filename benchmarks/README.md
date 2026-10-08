# Benchmarks

A performance suite run **on demand**, never on a push: a shared runner is
too noisy for a per-push number to mean anything. The `Benchmarks` workflow
runs it by hand on the three hosted systems and uploads one result file per
system as an artifact; two runs of the same system are what a before-and-after
comparison is made of.

```bash
.venv/3.14-nt-arm64/Scripts/python benchmarks/run.py            # print a table
.venv/3.14-nt-arm64/Scripts/python benchmarks/run.py --save     # and keep it
```

`--save` writes `results/<version>-<platform>-py<major.minor>.json`
(`--name` overrides the name). Results are tracked, so a before-and-after
comparison stays recoverable: save one before a change that is meant to be
faster, and one after.

## What is measured

Each metric is one call of a whole operation over a fixed, synthetic input,
repeated `--samples` times (15 by default) after one warm-up call.

| Metric | One call is |
| --- | --- |
| `read_frames/pcap-2000` | reading 2,000 frames of a pcap from memory |
| `read_frames/pcapng-2000` | the same frames in pcapng |
| `read_dissected/ethernet-ipv4-udp-2000` | reading and dissecting 2,000 Ethernet, IPv4, UDP frames: three layers each |
| `read_dissected/ethernet-ipv6-udp-2000` | 2,000 Ethernet, IPv6, UDP frames: three layers each, two IPv6 addresses written as text in each |
| `read_dissected/qinq-ipv4-tcp-2000` | 2,000 frames with two VLAN tags, IPv4 and TCP with options: five layers each |
| `read_dissected/registered-dissector-2000` | the first input again, with a dissector registered for its UDP port: four layers each |
| `read_datagrams/ethernet-ipv4-2000` | the same frames through the UDP datagram view |
| `read_datagrams/fragments-3x666` | 666 datagrams of 4,096 octets, each in three fragments |
| `dissect/1000-fragments-of-one-datagram` | 1,000 eight-octet fragments of one datagram that never completes: the shape that is quadratic when each fragment is compared with all the others |
| `TCPReassembler.add/in-order-2000` | 2,000 segments of 100 octets of one TCP stream, already dissected, in order, and the flush |
| `TCPReassembler.add/pairs-swapped-2000` | the same segments with each pair swapped, so every other segment waits for the one before it |
| `PcapWriter.write/2000` | writing 2,000 datagrams under synthesised headers, checksums included |
| `PcapngWriter.write_frame/2000` | writing 2,000 captured frames back as pcapng |
| `dumps_record/datagram-json-2000` | the default record of 2,000 datagrams as JSON lines |
| `dumps_record/frame-json-2000` | the default record of 2,000 dissected frames as JSON lines |
| `compile_capture_filter/apply-2000` | compiling a two-clause filter with a caller's builder and applying it 2,000 times |
| `frame_filter/apply-2000` | compiling a three-clause filter over the built-in keys and applying it to 2,000 dissected frames |

## The result file

```json
{
  "version": "0.1.0",
  "python": "3.14.7",
  "platform": "win-arm64",
  "samples": 15,
  "unit": "milliseconds per call",
  "metrics": {
    "read_frames/pcap-2000": {"min_ms": 0.0, "median_ms": 0.0, "max_ms": 0.0}
  }
}
```

**Compare on the median.** The minimum is the best case and the maximum
shows the noise; a single average hides both.

## Reading the numbers

A result measured on a developer's machine is a sanity check of the order of
magnitude, not evidence: the same commit varies severalfold from one day to
the next on a laptop. A performance claim in the changelog or the release
notes says where its numbers were measured. `results/0.1.0-*.json` is the
baseline every later result is compared with.
