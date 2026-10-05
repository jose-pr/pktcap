# pktcap

Contributor orientation for a checkout of `pktcap`, the capture layer shared by
UDP protocol libraries. This file is development documentation and does not
ship; the library's reference is the header below, which does.

| Header | Covers |
| --- | --- |
| `src/pktcap/AGENTS.md` | the shipped API header: every public name with its signature and contract, the bounds on untrusted input, the exceptions |
| `tests/AGENTS.md` | running and writing the tests: the network guard, the capture builders, the conformance cases |

A public API change updates the shipped header in the same commit.

## Layout

```
src/pktcap/   the package: every module is private, the root re-exports the API
tests/        the suite (tests/AGENTS.md)
docs/         the published site, with mkdocs.yml; built strictly as a release gate
benchmarks/   run on demand, never in CI; results/ is tracked
examples/     runnable scripts, local and loopback only
.github/      the three workflows: test, docs, release
```

## Environment

One venv per interpreter under `.venv/<version>-<os>-<arch>/`: the newest
Python and the floor, 3.9. `<arch>` is what the interpreter was built for
(`sysconfig.get_platform()`), not the host's.

```bash
py -3.14-arm64 -m venv .venv/3.14-nt-arm64
py -3.9-arm64  -m venv .venv/3.9-nt-arm64
.venv/3.14-nt-arm64/Scripts/python -m pip install -e ".[dev,docs]"
.venv/3.9-nt-arm64/Scripts/python -m pip install -e ".[dev]"
```

On POSIX the scripts are in `bin/` and the name is e.g.
`.venv/3.14-posix-x86_64`. The `dev` extra installs every format extra, so
their tests run and do not skip.

## Checks

Run all of them on both venvs before a push; CI runs the same on a `ci-*` tag
or a manual dispatch.

```bash
.venv/3.14-nt-arm64/Scripts/python -m pytest -q -rs
.venv/3.14-nt-arm64/Scripts/python -m black --check src/ tests/
.venv/3.14-nt-arm64/Scripts/python -m mypy --platform linux src/pktcap
.venv/3.14-nt-arm64/Scripts/python -m mypy --platform darwin src/pktcap
.venv/3.14-nt-arm64/Scripts/python -m mypy --platform win32 src/pktcap
.venv/3.14-nt-arm64/Scripts/python -m mkdocs build --strict
```

`mypy` resolves platform-only names against the platform it targets, so one
clean run says nothing about the other two.

## Conventions

- **Root-only surface.** Every module is private; `pktcap.__all__` is the API,
  and `tests/test_surface.py` pins it name by name.
- **A capture is untrusted input.** Every length, count and offset a file or a
  frame controls is checked against a ceiling before anything is allocated or
  looped over, and each ceiling has a test that fails without it.
- **Nothing is dropped silently.** A frame that does not decode is counted.
- **A private module imports a name from the module that owns it**, never from
  the root.
- **netimps supplies addresses, interfaces and sockets.** No local copy of
  what it provides, and nothing imported from a private netimps module.
- **Comments describe the code as it is**: the constraint, the reason, the
  unit. `tests/test_comments.py` enforces it over the source and the header.
- **Line endings are LF** (`.gitattributes`); a capture file is `-text`.

## Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Before 1.0 a minor bump means the documented
API broke; additions and fixes are patches. Pushing a tag matching `v*`
triggers the release workflow: test gate → build → strict docs build (a gate,
not a deploy) → GitHub release → PyPI. The last job dispatches `docs.yml` at
the tag, which owns every Pages deploy.
