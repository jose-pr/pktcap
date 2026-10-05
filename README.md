# pktcap

[![Version](https://img.shields.io/pypi/v/pktcap.svg)](https://pypi.org/project/pktcap/)
[![Python versions](https://img.shields.io/pypi/pyversions/pktcap.svg)](https://pypi.org/project/pktcap/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/pktcap/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/pktcap/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/pktcap/test.yml)](https://github.com/jose-pr/pktcap/actions/workflows/test.yml)

**The capture layer a UDP protocol library needs, and nothing above it**: read
pcap and pcapng, decode frames to UDP datagrams, write them back, replay them.
What a datagram means stays with the library that speaks the protocol. Built on
the standard library and [netimps](https://github.com/jose-pr/netimps).
Documentation: <https://jose-pr.github.io/pktcap/>.

## Features

- **One exception base** — `PktcapError`, for anything the library reports on
  its own account.

## Installation

```bash
pip install pktcap
```

Requires Python 3.9 or newer.

| Extra | Adds | Needed for |
| --- | --- | --- |
| `yaml` | `PyYAML` | writing records as YAML |
| `toml` | `tomli-w` | writing records as TOML |

## Quick start

```python
import pktcap

print(pktcap.__version__)
```

## API overview

Everything is imported from `pktcap`; the modules below it are private.

| Module | Purpose |
| --- | --- |
| `pktcap` | every public name |

## Development

```bash
py -3.14-arm64 -m venv .venv/3.14-nt-arm64
.venv/3.14-nt-arm64/Scripts/python -m pip install -e ".[dev,docs]"
.venv/3.14-nt-arm64/Scripts/python -m pytest -q -rs
```

The floor, Python 3.9, has its own venv and is run before a push. The
environments, the checks and the conventions are in
[`AGENTS.md`](https://github.com/jose-pr/pktcap/blob/main/AGENTS.md).

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/jose-pr/pktcap/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow: test gate → build
(checking the tag names the version built) → a strict docs build as a gate →
GitHub release → publish. The release workflow never deploys the docs site
itself: for a final release its last job dispatches the docs workflow at the
tag, which owns every Pages deploy.

## License

MIT — see [LICENSE](https://github.com/jose-pr/pktcap/blob/main/LICENSE).
