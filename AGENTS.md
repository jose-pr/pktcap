# pktcap

Contributor orientation for a checkout of `pktcap`, a library that reads,
dissects, writes and replays packet captures, with pluggable dissectors. This
file is development documentation and does not ship; the library's reference
is the headers below, which do.

| Header | Covers |
| --- | --- |
| `src/pktcap/AGENTS.md` | the shipped API header: every public name with its signature and contract, the bounds on untrusted input, the exceptions |
| `src/pktcap/_dissectors/AGENTS.md` | shipped: the dissector contract, the registry, each built-in dissector and layer |
| `src/pktcap/_formats/AGENTS.md` | shipped: the capture writers, `CaptureWriter` and `copy_frames`, what each record format writes |
| `src/pktcap/_plugins/AGENTS.md` | shipped: layers and filter keys in a registry, how a filter reads a layer's fields, loading plugins by name, the file and the trust rule |
| `src/pktcap/cli/AGENTS.md` | shipped: the `pktcap` command, every option, what it prints, its statuses |
| `tests/AGENTS.md` | running and writing the tests: the network guard, the capture builders, the conformance cases |

A public API change updates the shipped header in the same commit.

## Layout

```
src/pktcap/   the package: every module is private but `cli/`, the root re-exports the API;
              `_plugins/` holds layers and filter keys, and loading plugins by name
tests/        the suite (tests/AGENTS.md)
docs/         the published site, with mkdocs.yml; built strictly as a release gate
benchmarks/   run on demand, never on a push; results/ is tracked
examples/     runnable scripts, local and loopback only
.github/      the workflows: test, docs, release, and benchmarks (run by hand)
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
`.venv/3.14-posix-x86_64`. The `dev` extra installs every format extra and `cli`, so
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
  and `tests/test_surface.py` pins it name by name. `pktcap.cli` is the one
  public subpackage and is not library API.
- **Only `cli/` imports `duho`**, and `cli.main()` imports it inside the
  function, so a no-extra install gets one line naming the extra. A command
  is a class whose methods call the library's public API; what a command does
  beyond parsing and printing is a library function. A command module stays
  under 200 lines.
- **A capture is untrusted input.** Every length, count and offset a file or a
  frame controls is checked against a ceiling before anything is allocated or
  looped over, and each ceiling has a test that fails without it.
- **Any valid capture is read, and nothing is dropped silently.** A frame
  nothing dissects comes back whole; one a dissector could not read is
  counted, and keeps the layers before it.
- **A protocol is a dissector in a registry.** The built-in ones stop at UDP
  and TCP headers; anything above is registered by whoever needs it, and
  nothing is registered on import or through an entry point, and a plugin is
  loaded only when its user names it.
- **One path.** The UDP datagram view, the readers, the filter keys, replay
  and live capture are all built on `FrameDissector`; there is no second
  decoder.
- **A private module imports a name from the module that owns it**, never from
  the root.
- **netimps supplies addresses, interfaces and sockets.** No local copy of
  what it provides, and nothing imported from a private netimps module.
- **Comments describe the code as it is**: the constraint, the reason, the
  unit. `tests/test_comments.py` enforces it over the source and the header.
- **Line endings are LF** (`.gitattributes`); a capture file is `-text`.

## Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md), with the benchmark figures and the validation
evidence of each release in [`RELEASENOTES.md`](RELEASENOTES.md). Before 1.0 a minor bump means the documented
API broke; additions and fixes are patches. Pushing a tag matching `v*`
triggers the release workflow: test gate → build → strict docs build (a gate,
not a deploy) → GitHub release → PyPI. The last job dispatches `docs.yml` at
the tag, which owns every Pages deploy.
