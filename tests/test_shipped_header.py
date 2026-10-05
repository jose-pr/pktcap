"""The shipped ``AGENTS.md`` header stays complete and true.

Every export is named in it, every signature it prints is the live one, and it
and the two contributor files stay short enough to be read in one go.
"""

import ast
import inspect
import re
from pathlib import Path

import pytest

import pktcap

_ROOT = Path(__file__).resolve().parent.parent
_HEADER = _ROOT / "src" / "pktcap" / "AGENTS.md"

#: The most lines each file may have. Past these, detail moves to a header
#: beside the code it describes and the parent points to it.
HEADER_MAX_LINES = 500
ROOT_MAX_LINES = 120
TESTS_MAX_LINES = 120


def _lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def test_the_files_are_not_over_their_limits():
    assert len(_lines(_HEADER)) <= HEADER_MAX_LINES
    assert len(_lines(_ROOT / "AGENTS.md")) <= ROOT_MAX_LINES
    assert len(_lines(_ROOT / "tests" / "AGENTS.md")) <= TESTS_MAX_LINES


def test_the_header_has_the_standard_opening():
    text = _HEADER.read_text(encoding="utf-8")
    assert text.startswith("# `pktcap` — public API header\n")
    assert "https://github.com/jose-pr/pktcap" in text
    assert "`pktcap.__version__`" in text


def test_the_header_links_nothing_inside_the_repository():
    # An installed package has no repository beside it.
    links = re.findall(r"\]\(([^)]+)\)", _HEADER.read_text(encoding="utf-8"))
    assert [link for link in links if not link.startswith("http")] == []


@pytest.mark.parametrize("name", pktcap.__all__)
def test_every_export_is_in_the_header(name):
    text = _HEADER.read_text(encoding="utf-8")
    pattern = r"`[^`\n]*(?<![\w.])%s(?!\w)[^`\n]*`" % re.escape(name)
    assert re.search(pattern, text), "%s is exported but not in the header" % name


def test_the_root_file_names_the_two_headers():
    text = (_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "src/pktcap/AGENTS.md" in text and "tests/AGENTS.md" in text


def test_the_tests_header_names_every_test_file():
    tests = _ROOT / "tests"
    text = (tests / "AGENTS.md").read_text(encoding="utf-8")
    names = [
        path.relative_to(tests).as_posix()
        for path in tests.rglob("*.py")
        if "__pycache__" not in path.parts and path.name != "__init__.py"
    ]
    missing = [name for name in names if name not in text]
    assert missing == [], "tests/AGENTS.md does not name: %s" % ", ".join(missing)


#: ``**`name(args) -> result`**``: how the header prints a signature.
_SIGNATURE = re.compile(r"\*\*`([A-Za-z_][\w.]*)\(([^`]*?)\)(?: ->[^`]*)?`\*\*")

_KINDS = {
    inspect.Parameter.POSITIONAL_ONLY: "positional",
    inspect.Parameter.POSITIONAL_OR_KEYWORD: "positional",
    inspect.Parameter.VAR_POSITIONAL: "var_positional",
    inspect.Parameter.KEYWORD_ONLY: "keyword",
    inspect.Parameter.VAR_KEYWORD: "var_keyword",
}


def _resolve(dotted):
    obj = pktcap
    for part in dotted.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj


def _printed(args):
    spec = ast.parse("def f(%s): pass" % " ".join(args.split())).body[0].args
    out = []
    defaults = [None] * (len(spec.args) - len(spec.defaults)) + list(spec.defaults)
    for arg, default in zip(spec.args, defaults):
        out.append((arg.arg, "positional", default))
    if spec.vararg:
        out.append((spec.vararg.arg, "var_positional", None))
    for arg, default in zip(spec.kwonlyargs, spec.kw_defaults):
        out.append((arg.arg, "keyword", default))
    if spec.kwarg:
        out.append((spec.kwarg.arg, "var_keyword", None))
    return [(n, k, None if d is None else ast.unparse(d)) for n, k, d in out]


def _live(obj):
    out = []
    for p in inspect.signature(obj).parameters.values():
        if p.name in ("self", "cls"):
            continue
        default = None if p.default is inspect.Parameter.empty else ("=", p.default)
        out.append((p.name, _KINDS[p.kind], default))
    return out


def _same_default(printed, live):
    if printed is None or live is None:
        return printed is None and live is None
    try:
        return eval(printed, dict(vars(pktcap))) == live[1]
    except Exception:
        return printed == repr(live[1])


def _probe(path):
    """``(checked, mismatches)`` for every signature the file prints."""
    checked, bad = 0, []
    for match in _SIGNATURE.finditer(path.read_text(encoding="utf-8")):
        name, args = match.group(1), match.group(2)
        obj = _resolve(name)
        if obj is None or not callable(obj):
            continue
        if isinstance(obj, type) and issubclass(obj, BaseException):
            continue
        printed, live = _printed(args), _live(obj)
        checked += 1
        same = len(printed) == len(live) and all(
            p[0] == l[0] and p[1] == l[1] and _same_default(p[2], l[2])
            for p, l in zip(printed, live)
        )
        if not same:
            bad.append("%s(%s)" % (name, " ".join(args.split())))
    return checked, bad


def test_every_printed_signature_is_the_live_one():
    checked, bad = _probe(_HEADER)
    assert bad == [], "signature drift:\n" + "\n".join(bad)
    exports = [getattr(pktcap, name) for name in pktcap.__all__]
    plain = [
        obj
        for obj in exports
        if inspect.isfunction(obj)
        or (inspect.isclass(obj) and not issubclass(obj, BaseException))
    ]
    # Every function and class has its signature printed, so a probe that
    # matched nothing cannot pass.
    assert checked >= len(plain), (checked, len(plain))


def test_the_probe_sees_a_changed_signature(tmp_path, monkeypatch):
    def sample(source: str, limit: int = 3, *, strict: bool = False) -> None:
        """A stand-in export."""

    monkeypatch.setattr(pktcap, "sample", sample, raising=False)
    header = tmp_path / "AGENTS.md"
    header.write_text(
        "**`sample(source, limit=4, *, strict=False)`** wrong default.\n"
        "**`sample(source, limit=3, strict=False)`** not keyword-only.\n"
        "**`sample(source, limit=3, *, strict=False) -> None`** right.\n",
        encoding="utf-8",
    )
    checked, bad = _probe(header)
    assert checked == 3
    assert len(bad) == 2
