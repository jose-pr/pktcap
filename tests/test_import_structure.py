"""How the package modules import each other, and what they import.

Internal code imports a name from the module that owns it, a module stays
small enough to review in one sitting, and netimps is used through its public
names only.
"""

import ast
import re
import subprocess
import sys
from pathlib import Path

import pktcap

_SRC = Path(pktcap.__file__).parent

#: The most lines a module may have.
MAX_MODULE_LINES = 400
#: The most lines a command module may have: past it, logic belongs in the
#: library, where it is public and tested without a parser.
MAX_COMMAND_LINES = 200

#: ``pktcap.cli`` is the one public subpackage, and each subcommand is a module
#: named for it. Everything else is private.
COMMAND_MODULES = {"cli/capture.py", "cli/convert.py", "cli/replay.py"}


def _modules():
    return sorted(_SRC.rglob("*.py"))


def _name(path):
    return path.relative_to(_SRC).as_posix()


def test_every_module_but_the_root_is_private():
    public = [
        _name(path)
        for path in _modules()
        if path.name != "__init__.py"
        and not any(part.startswith("_") for part in path.relative_to(_SRC).parts)
    ]
    assert sorted(public) == sorted(COMMAND_MODULES)


def test_duho_is_imported_by_the_command_line_alone():
    offenders = []
    for path in _modules():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            if any(name.split(".")[0] == "duho" for name in names):
                if not _name(path).startswith("cli/"):
                    offenders.append(_name(path))
    assert offenders == []


def test_the_package_init_of_the_command_line_imports_duho_inside_main_only():
    tree = ast.parse((_SRC / "cli" / "__init__.py").read_text(encoding="utf-8"))
    top = [
        node
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and any(
            (
                alias.name if isinstance(node, ast.Import) else node.module or ""
            ).startswith("duho")
            for alias in node.names
        )
    ]
    assert top == []


def test_a_command_module_stays_short():
    long = {
        _name(path): len(path.read_text(encoding="utf-8").splitlines())
        for path in (_SRC / "cli").glob("*.py")
        if len(path.read_text(encoding="utf-8").splitlines()) > MAX_COMMAND_LINES
    }
    assert long == {}, "move what is not parsing, calling and printing into the library"


def test_no_module_imports_a_name_from_the_root():
    """`from . import name` in a submodule resolves through the root's partly
    built namespace and fails when that submodule is imported first."""
    offenders = []
    for path in _modules():
        if path.parent == _SRC and path.name == "__init__.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                depth = len(path.relative_to(_SRC).parts)
                if node.level == depth and node.module is None:
                    offenders.append(_name(path))
                if node.level == 0 and node.module == "pktcap":
                    offenders.append(_name(path))
    assert offenders == []


def test_no_module_is_over_the_size_limit():
    long = {
        _name(path): len(path.read_text(encoding="utf-8").splitlines())
        for path in _modules()
        if len(path.read_text(encoding="utf-8").splitlines()) > MAX_MODULE_LINES
    }
    assert long == {}, "split it along a seam"


def test_netimps_is_imported_by_its_public_names_only():
    pattern = re.compile(r"^\s*(?:from|import)\s+netimps\.", re.MULTILINE)
    offenders = [
        _name(path)
        for path in _modules()
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], "import from `netimps`, never from a module below it"


def test_every_module_has_future_annotations():
    missing = [
        _name(path)
        for path in _modules()
        if "from __future__ import annotations" not in path.read_text(encoding="utf-8")
    ]
    assert missing == []


def test_importing_the_package_loads_no_optional_dependency():
    """`import pktcap` works with no extra installed and imports none of them,
    nor the command line, nor asyncio, which only a caller driving a loop
    needs."""
    code = (
        "import sys, pktcap; "
        "print(sorted(m for m in ('yaml', 'tomli_w', 'asyncio', 'duho', "
        "'pktcap.cli') if m in sys.modules))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        env=None,
    ).stdout.strip()
    assert out == "[]"
