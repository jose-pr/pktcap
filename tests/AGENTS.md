# Tests

Running and writing the tests of `pktcap`. The root `AGENTS.md` points here.

## Running them

From the root of a checkout, on the newest interpreter and on the floor:

```bash
.venv/3.14-nt-arm64/Scripts/python -m pytest -q -rs
.venv/3.9-nt-arm64/Scripts/python -m pytest -q -rs
```

`pyproject.toml` puts `src/` on the path and turns warnings into errors. `-rs`
prints the reason for every skip: a skip is not a pass.

## What is here

| File | Covers |
| --- | --- |
| `conftest.py` | the network guard: a test that sends anywhere but loopback fails at the call |
| `test_network_guard.py` | the guard itself refuses an off-host destination and a name lookup |
| `test_surface.py` | exactly what `pktcap.__all__` exports, and that options are keyword-only |
| `test_shipped_header.py` | the shipped `AGENTS.md`: every export is in it, every printed signature is the live one |
| `test_import_structure.py` | no module takes a name from the root, none is over 400 lines, nothing imports a private netimps module |
| `test_comments.py` | the source and the shipped header describe the code as it is |

## Rules

- **A test asserts through `pktcap`'s public names.** No test imports a private
  module to call it.
- **A bound is seen to fail.** A test for a ceiling is run once against the
  code with the ceiling removed, and must fail there.
- **Nothing leaves the host.** Sockets are loopback, bound to port 0. The guard
  in `conftest.py` enforces it.
