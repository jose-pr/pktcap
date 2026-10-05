# `pktcap` — public API header

Header-file-style reference for the `pktcap` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/pktcap>.

Everything is imported from `pktcap` directly. Every module under `pktcap`
(each name starts with `_`) is implementation detail: do not import them.

Install with `pip install pktcap`, which brings `netimps`. The `yaml` extra
(`pip install "pktcap[yaml]"`) adds `PyYAML` and the `toml` extra adds
`tomli-w`, each for the output format of that name. Importing `pktcap` needs
neither. Python 3.9 or newer.

`pktcap.__version__` — the package version string, the same value the
installed distribution's metadata carries.

## Exceptions

Every exception pktcap raises on its own account descends from
**`PktcapError(Exception)`**. A caller's own mistake (a bad option, a wrong
argument type) is a plain `ValueError` or `TypeError`, never a `PktcapError`.

| Class | Bases | Raised for |
| --- | --- | --- |
| `PktcapError` | `Exception` | the base; catch it for "anything pktcap reported" |
