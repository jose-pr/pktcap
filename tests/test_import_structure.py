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
COMMAND_MODULES = {
    "cli/capture.py",
    "cli/convert.py",
    "cli/plugins.py",
    "cli/replay.py",
}


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


# -- the trust boundary of plugin loading ------------------------------------
#
# Importing a module because a string names it runs its code. A plugin list is
# read from three places only (an argument, PKTCAP_LOAD, one configuration
# file), so the three capabilities are kept in three modules, and these tests
# say which. Each takes the tree to scan so a test can plant a violation.

_LOAD = "_plugins/_load.py"
_CONFIG = "_plugins/_config.py"


def _tree_modules(root):
    return sorted(root.rglob("*.py"))


def _relative(root, path):
    return path.relative_to(root).as_posix()


def _names_used(path):
    """Every identifier and attribute name a module mentions, and every name
    it imports, as ``(kind, name)`` pairs."""
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Name):
            found.add(("name", node.id))
        elif isinstance(node, ast.Attribute):
            found.add(("name", node.attr))
        elif isinstance(node, ast.alias):
            found.add(("name", node.name.split(".")[-1]))
            found.add(("module", node.name))
        elif isinstance(node, ast.ImportFrom):
            found.add(("module", node.module or ""))
    return found


def _naming(root, names, allowed):
    return [
        _relative(root, path)
        for path in _tree_modules(root)
        if _relative(root, path) not in allowed
        and any(("name", name) in _names_used(path) for name in names)
    ]


def _loader_importers(root):
    """The modules that import ``_plugins/_load.py``, by any spelling."""
    offenders = []
    for path in _tree_modules(root):
        package = _relative(root, path).split("/")[:-1]
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            targets = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = (
                    ["pktcap"] + package[: len(package) - node.level + 1]
                    if node.level
                    else []
                )
                module = ".".join(base + ([node.module] if node.module else []))
                targets = [module] + ["%s.%s" % (module, a.name) for a in node.names]
            if any(t.endswith("_plugins._load") for t in targets):
                offenders.append(_relative(root, path))
    return sorted(set(offenders))


def test_import_module_is_named_in_the_loader_alone():
    assert _naming(_SRC, ("import_module", "__import__"), {_LOAD}) == []
    assert _naming(_SRC, ("import_module",), set()) == [_LOAD]


def test_no_other_way_of_running_a_named_module_is_used():
    assert (
        _naming(_SRC, ("runpy", "exec", "eval", "spec_from_file_location"), set()) == []
    )


def test_the_environment_is_read_by_the_configuration_module_alone():
    assert _naming(_SRC, ("environ", "getenv", "environb", "getenvb"), {_CONFIG}) == []
    assert _naming(_SRC, ("environ",), set()) == [_CONFIG]


def test_the_loader_is_imported_by_the_package_root_and_the_command_line_alone():
    importers = _loader_importers(_SRC)
    assert importers and all(
        name == "__init__.py" or name.startswith("cli/") for name in importers
    ), importers


def test_the_plugin_package_init_imports_nothing_but_the_annotations_future():
    tree = ast.parse((_SRC / "_plugins" / "__init__.py").read_text(encoding="utf-8"))
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert [n.module for n in imports] == ["__future__"]


def _planted(tmp_path, files):
    root = tmp_path / "pktcap"
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def test_the_scanners_see_a_planted_violation(tmp_path):
    root = _planted(
        tmp_path,
        {
            "__init__.py": "from ._plugins._load import load_plugins\n",
            "_plugins/_load.py": "from importlib import import_module\n",
            "_plugins/_config.py": "import os\nos.environ.get('X')\n",
            "_filter.py": "from importlib import import_module\nimport_module('x')\n",
            "_dissect.py": "import os\nos.getenv('X')\n",
            "_copy.py": "from os import environ\n",
            "_keys.py": "from ._plugins import _load\n",
            "_other.py": "import importlib\nimportlib.__import__('x')\n",
            "cli/_x.py": "from .._plugins._load import LoadedPlugin\n",
            "_exec.py": "eval('1')\n",
        },
    )
    assert _naming(root, ("import_module", "__import__"), {_LOAD}) == [
        "_filter.py",
        "_other.py",
    ]
    assert _naming(root, ("environ", "getenv"), {_CONFIG}) == [
        "_copy.py",
        "_dissect.py",
    ]
    assert _loader_importers(root) == ["__init__.py", "_keys.py", "cli/_x.py"]
    assert _naming(root, ("exec", "eval"), set()) == ["_exec.py"]
