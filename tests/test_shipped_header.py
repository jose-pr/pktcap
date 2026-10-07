"""The shipped ``AGENTS.md`` headers stay complete, listed and true.

``src/pktcap/AGENTS.md`` is the top header; a topic with much detail keeps it
in an ``AGENTS.md`` beside its code. Every export is named in the top header,
every header below it is listed there, every function and class has its
signature printed in one of them, every signature printed is the live one,
and each file stays short enough to be read in one go.
"""

import ast
import inspect
import re
from pathlib import Path

import pytest

import pktcap

_ROOT = Path(__file__).resolve().parent.parent
_PACKAGE = _ROOT / "src" / "pktcap"
_HEADER = _PACKAGE / "AGENTS.md"
_COMMAND_HEADER = _PACKAGE / "cli" / "AGENTS.md"
_SUBHEADERS = sorted(p for p in _PACKAGE.rglob("AGENTS.md") if p != _HEADER)
#: The headers of private directories, which print signatures of the library.
_LIBRARY_SUBHEADERS = [p for p in _SUBHEADERS if p != _COMMAND_HEADER]

#: The most lines each file may have. Past these, detail moves to a header
#: beside the code it describes and the parent points to it.
HEADER_MAX_LINES = 500
SUB_MAX_LINES = 300
ROOT_MAX_LINES = 120
TESTS_MAX_LINES = 120


def _lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def _inside_package(path):
    """The path a reader of the installed package uses."""
    return "pktcap/" + path.relative_to(_PACKAGE).as_posix()


def test_the_files_are_not_over_their_limits():
    assert len(_lines(_HEADER)) <= HEADER_MAX_LINES
    assert len(_lines(_ROOT / "AGENTS.md")) <= ROOT_MAX_LINES
    assert len(_lines(_ROOT / "tests" / "AGENTS.md")) <= TESTS_MAX_LINES
    for path in _SUBHEADERS:
        assert len(_lines(path)) <= SUB_MAX_LINES, _inside_package(path)


@pytest.mark.parametrize("path", _SUBHEADERS, ids=_inside_package)
def test_a_header_below_the_top_is_listed_there_and_says_what_it_is(path):
    rows = [line for line in _lines(_HEADER) if line.startswith("|")]
    assert any("`%s`" % _inside_package(path) in row for row in rows)
    head = "\n".join(_lines(path)[:12])
    assert head.startswith("# `pktcap`")
    if path == _COMMAND_HEADER:
        assert "not library API" in " ".join(head.split())
    else:
        assert "public API header" in head
        assert "private and not an import path" in " ".join(head.split())
    links = re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8"))
    assert [link for link in links if not link.startswith("http")] == []


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


def test_the_example_of_the_dissectors_header_runs(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pktcap.PcapWriter("trace.pcap") as writer:
        request = b"\x00\x01boot.efi\x00octet\x00"
        writer.write(1.0, ("192.0.2.5", 50000), ("192.0.2.1", 69), request)
        writer.write(2.0, ("192.0.2.1", 40000), ("192.0.2.5", 50000), b"\x00\x03")
    text = (_PACKAGE / "_dissectors" / "AGENTS.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```python\n(.*?)```", text, re.DOTALL)
    assert len(blocks) == 3
    # The first block shows the shape alone, before the one that imports.
    namespace = {"__name__": "header_example", "pktcap": pktcap}
    for block in blocks:
        exec(compile(block, "AGENTS.md", "exec"), namespace)
    namespace["test_the_tftp_dissector_keeps_the_contract"]()
    assert capsys.readouterr().out == "('192.0.2.5', 50000) 1 boot.efi\n"


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
    """``(names checked, mismatches)`` for every signature the file prints."""
    checked, bad = [], []
    for match in _SIGNATURE.finditer(path.read_text(encoding="utf-8")):
        name, args = match.group(1), match.group(2)
        obj = _resolve(name)
        if obj is None or not callable(obj):
            continue
        if isinstance(obj, type) and issubclass(obj, BaseException):
            continue
        printed, live = _printed(args), _live(obj)
        checked.append(name)
        same = len(printed) == len(live) and all(
            p[0] == l[0] and p[1] == l[1] and _same_default(p[2], l[2])
            for p, l in zip(printed, live)
        )
        if not same:
            bad.append("%s(%s)" % (name, " ".join(args.split())))
    return checked, bad


def test_every_printed_signature_is_the_live_one():
    checked, bad = _probe(_HEADER)
    for path in _LIBRARY_SUBHEADERS:
        names, mismatches = _probe(path)
        assert names, "%s prints no signature to check" % _inside_package(path)
        checked += names
        bad += ["%s: %s" % (_inside_package(path), m) for m in mismatches]
    assert bad == [], "signature drift:\n" + "\n".join(bad)
    plain = {
        name
        for name in pktcap.__all__
        if inspect.isfunction(getattr(pktcap, name))
        or (
            inspect.isclass(getattr(pktcap, name))
            and not issubclass(getattr(pktcap, name), BaseException)
        )
    }
    # Every function and class has its signature printed in one header or
    # another, so a probe that matched nothing cannot pass.
    assert plain - set(checked) == set()


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
    assert checked == ["sample"] * 3
    assert len(bad) == 2


# -- the header of the command line -----------------------------------------


def _declared_options():
    pytest.importorskip("duho")
    from pktcap.cli.capture import Capture
    from pktcap.cli.convert import Convert
    from pktcap.cli.replay import Replay
    from pktcap.cli._root import Pktcap

    found = {}
    for command in (Convert, Replay, Capture, Pktcap):
        parser = command._parser_()
        found[command.__name__] = sorted(
            option
            for action in parser._actions
            for option in action.option_strings
            if option not in ("-h", "--help")
        )
    return found


def test_the_command_header_is_listed_and_inside_the_package():
    assert _COMMAND_HEADER.is_file()
    rows = [line for line in _lines(_HEADER) if line.startswith("|")]
    assert any("`pktcap/cli/AGENTS.md`" in row for row in rows)
    assert "pip install" in _HEADER.read_text(encoding="utf-8")
    assert "`cli` extra" in _HEADER.read_text(encoding="utf-8")


def test_every_option_a_command_declares_is_named_in_its_header():
    text = _COMMAND_HEADER.read_text(encoding="utf-8")
    missing = [
        "%s %s" % (command, option)
        for command, options in _declared_options().items()
        for option in options
        if not re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(option), text)
    ]
    assert missing == [], "cli/AGENTS.md does not name: %s" % ", ".join(missing)


def test_the_command_header_names_each_command_the_environment_and_the_tool():
    pytest.importorskip("duho")
    text = _COMMAND_HEADER.read_text(encoding="utf-8")
    for needle in (
        "pktcap convert",
        "pktcap replay",
        "pktcap capture",
        "PKTCAP_MCP=stdio",
        "pktcap.convert",
    ):
        assert needle in text, needle
    assert "PKTCAP_MCP" in _HEADER.read_text(encoding="utf-8")


def test_a_built_wheel_holds_the_command_header_and_the_console_script(tmp_path):
    pytest.importorskip("build")
    pytest.importorskip("hatchling")
    import subprocess
    import sys
    import zipfile

    done = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation"]
        + ["--outdir", str(tmp_path), str(_ROOT)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    (wheel,) = tmp_path.glob("pktcap-*.whl")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        entries = [n for n in names if n.endswith("entry_points.txt")]
        points = archive.read(entries[0]).decode("utf-8")
    assert "pktcap/cli/AGENTS.md" in names and "pktcap/cli/convert.py" in names
    assert "pktcap = pktcap.cli:main" in points
    assert not [n for n in names if ".agents" in n or n.endswith("tests/AGENTS.md")]
