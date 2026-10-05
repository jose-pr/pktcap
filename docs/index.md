# pktcap

**The capture layer a UDP protocol library needs, and nothing above it**: read
pcap and pcapng, decode frames to UDP datagrams, write them back, replay them.
What a datagram means stays with the library that speaks the protocol. Built on
the standard library and [netimps](https://github.com/jose-pr/netimps).

## Installation

```bash
pip install pktcap
```

Requires Python 3.9 or newer.

| Extra | Adds | Needed for |
| --- | --- | --- |
| `yaml` | `PyYAML` | writing records as YAML |
| `toml` | `tomli-w` | writing records as TOML |

## 30-second tour

```python
import pktcap

print(pktcap.__version__)
```

## Learn more

- [API Reference](api/reference.md): every export, generated from the source.
- [Changelog](changelog.md)
