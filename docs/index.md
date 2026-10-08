# pktcap

**Read any packet capture, dissect it layer by layer, write it back, replay
it.** Every frame of a pcap or pcapng file comes back, whatever its link type;
the built-in dissectors read the link layer, IP, UDP and TCP, and any other
protocol is a dissector you register. Built on the standard library and
[netimps](https://github.com/jose-pr/netimps).

## Installation

```bash
pip install pktcap
```

Requires Python 3.9 or newer.

| Extra | Adds | Needed for |
| --- | --- | --- |
| `yaml` | `PyYAML` | writing and reading records as YAML |
| `toml` | `tomli-w`, and `tomli` before Python 3.11 | writing records as TOML, and reading them before 3.11 |
| `cli` | `duho` | the `pktcap` command |

## 30-second tour

```python
import pktcap

for frame in pktcap.read_dissected("trace.pcapng"):
    tcp = frame.layer(pktcap.TCPLayer)
    if tcp is not None and tcp.syn:
        ip = frame.layer(pktcap.IPv4Layer) or frame.layer(pktcap.IPv6Layer)
        print(frame.time, ip.source, "->", ip.destination, tcp.destination_port)

for datagram in pktcap.read_datagrams("trace.pcapng"):  # the UDP view
    print(datagram.source, datagram.destination, len(datagram.payload))
```

A protocol of your own is a function and one line that registers it:

```python
def dissect_echo(data: bytes) -> pktcap.Dissected:
    if len(data) < 2:
        raise pktcap.DissectError("an echo header is 2 octets")
    return pktcap.Dissected({"kind": data[0], "code": data[1]}, data[2:])


pktcap.register_dissector("udp", 7, dissect_echo)
```

## Learn more

- [Dissectors](dissectors.md): the contract, the registry, and what each
  built-in dissector reads and leaves alone.
- [TCP streams](streams.md): `TCPReassembler` and `read_tcp_streams`: each
  direction's octets in order, the rules for what a passive reader cannot
  know, and the bounds.
- [Output formats](formats.md): `CaptureWriter`, and what each record format
  writes.
- [Command line](cli.md): the `pktcap` command, `capture`, `replay` and
  `convert`, with every option and exit status.
- [API Reference](api/reference.md): every export, generated from the source.
- [Changelog](changelog.md)
