"""``load_plugins``: both forms of an item, every way a plugin fails, and that
nothing is imported, read or registered that was not asked for."""

import json
import logging
import os
import subprocess
import sys
import textwrap

import pytest

import captures as build
from pktcap import (
    CapturedFrame,
    CapturePluginError,
    Dissected,
    DissectorRegistry,
    FrameDissector,
    LoadedPlugin,
    PktcapError,
    compile_capture_filter,
    default_registry,
    frame_filter_for,
    frame_filter_keys,
    load_plugins,
)


def state(registry):
    """Everything a hook can add to a registry, as comparable values."""
    return (
        registry.selectors(),
        sorted(registry.layers()),
        frame_filter_keys(registry),
    )


# -- the done-when of the plan -------------------------------------------------


def test_the_variable_names_a_module_and_its_hook_registers_into_the_registry(
    plugin_module, monkeypatch
):
    mod = plugin_module()
    before = default_registry().selectors()
    monkeypatch.setenv("PKTCAP_PLUGINS", mod.name)
    registry = DissectorRegistry()
    result = load_plugins(registry, None)
    assert result == (
        LoadedPlugin(mod.name, "PKTCAP_PLUGINS", (("udp", 9999),), ("demo",)),
    )
    assert registry.get("udp", 9999) is not None
    assert default_registry().selectors() == before
    assert default_registry().layers() == {}


def test_the_file_gives_its_path_as_the_source(plugin_module, tmp_path, monkeypatch):
    mod = plugin_module()
    ini = tmp_path / "named.ini"
    ini.write_text("[pktcap]\nplugins = %s\n" % mod.name, encoding="utf-8")
    (only,) = load_plugins(DissectorRegistry(), config=ini)
    assert only.source == str(ini) and only.selectors == (("udp", 9999),)


def test_a_loaded_plugins_keys_and_dissector_work_in_a_filter(plugin_module):
    mod = plugin_module()
    registry = DissectorRegistry()
    load_plugins(registry, mod.name)
    frame = FrameDissector(registry).dissect(
        CapturedFrame(
            0.0,
            1,
            build.ethernet(
                build.ipv4(
                    "10.0.0.5", "10.0.0.1", build.udp(50000, 9999, b"\x01boot.efi")
                )
            ),
        )
    )
    keep = compile_capture_filter(
        "demo.opcode=1 and proto=demo", frame_filter_for(registry)
    )
    assert keep(frame) is True
    assert "demo.opcode" in frame_filter_keys(registry)


# -- both forms of an item ---------------------------------------------------


def test_an_item_is_a_module_with_a_hook_or_a_callable_in_a_module(plugin_module):
    source = """
        import pktcap

        def register(registry, *, ports=(7000,)):
            for port in ports:
                registry.register("udp", port, lambda data: pktcap.Dissected(None, data))

        def pktcap_plugin(registry):
            registry.register("udp", 7001, lambda data: pktcap.Dissected(None, data))
        """
    body = textwrap.dedent(source)
    mod = plugin_module(body)
    registry = DissectorRegistry()
    (module_form,) = load_plugins(registry, mod.name)
    assert module_form.selectors == (("udp", 7001),)
    (callable_form,) = load_plugins(registry, mod.name + ".register")
    assert callable_form.selectors == (("udp", 7000),)
    assert callable_form.name == mod.name + ".register"


def test_a_dotted_module_inside_a_package_is_found(plugin_module, tmp_path):
    package = plugin_module("", name="pktcap_pkg_%s" % os.urandom(3).hex())
    inner = package.directory / package.name
    inner.mkdir()
    (inner / "__init__.py").write_text("", encoding="utf-8")
    (inner / "inner.py").write_text(
        "def pktcap_plugin(registry):\n    registry.register('udp', 7002, print)\n",
        encoding="utf-8",
    )
    os.remove(package.path)
    registry = DissectorRegistry()
    (only,) = load_plugins(registry, package.name + ".inner")
    assert only.selectors == (("udp", 7002),)
    (again,) = load_plugins(DissectorRegistry(), package.name + ".inner.pktcap_plugin")
    assert again.selectors == (("udp", 7002),)


@pytest.mark.parametrize(
    "failure, kind",
    [
        ("import nosuch_dependency_xyz", "ModuleNotFoundError"),
        (
            "import importlib.metadata as m\nraise m.PackageNotFoundError(__name__)",
            "PackageNotFoundError",
        ),
        ("raise RuntimeError('boom')", "RuntimeError"),
    ],
)
@pytest.mark.parametrize("tail", [".inner", ".inner.pktcap_plugin", ""])
def test_a_package_whose_own_import_fails_gives_none_of_its_modules(
    plugin_module, failure, kind, tail
):
    """The package imports its submodule and then fails. The submodule stays
    in ``sys.modules``, and it must not be taken from there: the package did
    not import, so nothing inside it is a plugin."""
    package = plugin_module("", name="pktcap_half_%s" % os.urandom(3).hex())
    inner = package.directory / package.name
    inner.mkdir()
    (inner / "__init__.py").write_text(
        "from . import inner\n%s\n" % failure, encoding="utf-8"
    )
    (inner / "inner.py").write_text(
        "CALLED = []\n"
        "def pktcap_plugin(registry):\n"
        "    CALLED.append(1)\n"
        "    registry.register('udp', 7003, print)\n",
        encoding="utf-8",
    )
    os.remove(package.path)
    registry = DissectorRegistry()
    before = state(registry)

    with pytest.raises(CapturePluginError) as caught:
        load_plugins(registry, package.name + tail)

    assert "importing it failed (%s" % kind in str(caught.value)
    assert caught.value.plugin == package.name + tail
    assert state(registry) == before
    left = sys.modules.get(package.name + ".inner")
    assert left is None or left.CALLED == []


def test_the_plugins_come_back_in_the_order_given(plugin_module):
    mods = [
        plugin_module(
            "def pktcap_plugin(registry):\n    registry.register('udp', %d, print)\n"
            % p
        )
        for p in (7101, 7102, 7103)
    ]
    result = load_plugins(DissectorRegistry(), [m.name for m in reversed(mods)])
    assert [p.name for p in result] == [m.name for m in reversed(mods)]


def test_each_plugin_loaded_is_logged_at_info_with_its_source(plugin_module, caplog):
    mod = plugin_module()
    with caplog.at_level(logging.INFO, logger="pktcap"):
        load_plugins(DissectorRegistry(), mod.name)
    (line,) = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert mod.name in line and "plugins argument" in line


# -- every way a plugin fails ------------------------------------------------


def failing(plugin_module, body, item=None, **options):
    mod = plugin_module(body)
    registry = DissectorRegistry()
    before = state(registry)
    with pytest.raises(CapturePluginError) as caught:
        load_plugins(registry, item(mod) if item else mod.name, **options)
    assert state(registry) == before
    assert isinstance(caught.value, PktcapError) and isinstance(
        caught.value, ValueError
    )
    return mod, caught.value


def test_no_module_of_that_name(plugin_module):
    registry = DissectorRegistry()
    with pytest.raises(CapturePluginError) as caught:
        load_plugins(registry, "nosuch_plugin_xyz")
    error = caught.value
    assert error.plugin == "nosuch_plugin_xyz" and error.source == "argument"
    assert (
        str(error)
        == "the plugins argument names 'nosuch_plugin_xyz': no module of that name"
    )
    assert registry.selectors() == DissectorRegistry().selectors()
    for item in ("json.nosuch", "email.mime.nosuch.deeper", "nosuch_pkg.sub.fn"):
        with pytest.raises(CapturePluginError, match="no module of that name"):
            load_plugins(registry, item)


def test_the_text_names_the_variable_as_the_source(monkeypatch):
    monkeypatch.setenv("PKTCAP_PLUGINS", "pydemo.captur")
    with pytest.raises(CapturePluginError) as caught:
        load_plugins(DissectorRegistry())
    assert (
        str(caught.value)
        == "PKTCAP_PLUGINS names 'pydemo.captur': no module of that name"
    )
    assert caught.value.source == "PKTCAP_PLUGINS"


def test_a_module_whose_import_raises(plugin_module):
    for body, kind in (
        ("raise RuntimeError('boom')\n", "RuntimeError"),
        ("import nosuch_dependency_xyz\n", "ModuleNotFoundError"),
        ("def broken(:\n", "SyntaxError"),
        ("raise ImportError('half')\n", "ImportError"),
    ):
        _, error = failing(plugin_module, body)
        assert "importing it failed (%s" % kind in str(error)
        assert error.__cause__ is not None


def test_a_module_with_no_hook_says_how_to_name_a_callable(plugin_module):
    _, error = failing(plugin_module, "x = 1\n")
    assert "no pktcap_plugin: name a callable as MODULE.NAME" in str(error)
    _, error = failing(plugin_module, "pktcap_plugin = 5\n")
    assert "no pktcap_plugin" in str(error)


def test_a_missing_or_uncallable_attribute(plugin_module):
    _, error = failing(plugin_module, "x = 5\n", lambda m: m.name + ".nosuch")
    assert "no module of that name, and" in str(error) and "'nosuch'" in str(error)
    _, error = failing(plugin_module, "x = 5\n", lambda m: m.name + ".x")
    assert "is not callable" in str(error)


def test_a_hook_that_takes_no_single_argument(plugin_module):
    for body in (
        "def pktcap_plugin(): pass\n",
        "def pktcap_plugin(a, b): pass\n",
        "def pktcap_plugin(*, registry): pass\n",
    ):
        _, error = failing(plugin_module, body)
        assert "takes no single argument" in str(error)


def test_a_hook_that_registers_one_thing_and_raises_leaves_the_registry_as_it_was(
    plugin_module,
):
    source = """
        from typing import NamedTuple
        import pktcap

        class HalfLayer(NamedTuple):
            x: int

        def pktcap_plugin(registry):
            registry.register_layer(HalfLayer, keys={"k": lambda c: lambda l: True})
            registry.register("udp", 7200, lambda data: pktcap.Dissected(None, data))
            registry.register("tcp", 7201, lambda data: pktcap.Dissected(None, data))
            raise ValueError("after two registrations")
        """
    body = textwrap.dedent(source)
    _, error = failing(plugin_module, body)
    assert "the hook raised (ValueError: after two registrations)" in str(error)
    assert isinstance(error.__cause__, ValueError)


def test_a_failure_part_way_through_a_list_undoes_the_plugins_before_it(plugin_module):
    first = plugin_module()
    second = plugin_module("raise RuntimeError('no')\n")
    registry = DissectorRegistry()
    registry.register("udp", 7300, print)
    before = state(registry)
    with pytest.raises(CapturePluginError) as caught:
        load_plugins(registry, [first.name, second.name])
    assert caught.value.plugin == second.name and first.imported
    assert state(registry) == before and registry.get("udp", 9999) is None
    assert "demo" not in registry.layers()
    # What was imported stays imported: the first module ran once.
    assert first.marker.read_text().count("imported") == 1
    load_plugins(registry, first.name)
    assert first.marker.read_text().count("imported") == 1


def test_a_hook_that_replaces_a_dissector_is_undone_too(plugin_module):
    mod = plugin_module(
        "def pktcap_plugin(registry):\n"
        "    registry.register('ip', 17, print, replace=True)\n"
        "    raise ValueError('late')\n"
    )
    registry = DissectorRegistry()
    original = registry.get("ip", 17)
    with pytest.raises(CapturePluginError):
        load_plugins(registry, mod.name)
    assert registry.get("ip", 17) is original


def test_a_selector_the_registry_has_is_the_hooks_own_error(plugin_module):
    mod = plugin_module()
    registry = DissectorRegistry()
    registry.register("udp", 9999, print)
    with pytest.raises(CapturePluginError, match="already registered for udp 9999"):
        load_plugins(registry, mod.name)
    assert registry.get("udp", 9999) is print and "demo" not in registry.layers()


def test_two_plugins_may_not_claim_one_layer_name(plugin_module):
    one, two = plugin_module(), plugin_module()
    registry = DissectorRegistry()
    with pytest.raises(CapturePluginError, match="already registered"):
        load_plugins(registry, [one.name, two.name])
    assert registry.layers() == {}


# -- nothing is read, imported or registered that was not asked for ----------

_CHILD = """
import json, os, sys

WATCHED = {"PKTCAP_PLUGINS", "PKTCAP_CONFIG", "XDG_CONFIG_HOME", "APPDATA"}
reads = []  # (name, the file that asked)

PASS_THROUGH = {"os.py", "ntpath.py", "posixpath.py", "genericpath.py", "_collections_abc.py"}

def note(key):
    # Record who asked: the first frame that is not the os module's own.
    if key in WATCHED:
        frame = sys._getframe(2)
        while frame is not None and os.path.basename(frame.f_code.co_filename) in PASS_THROUGH:
            frame = frame.f_back
        reads.append((key, frame.f_code.co_filename if frame else ""))

class Recording(dict):
    def __getitem__(self, key):
        note(key)
        return dict.__getitem__(self, key)
    def get(self, key, default=None):
        note(key)
        return dict.get(self, key, default)
    def __contains__(self, key):
        note(key)
        return dict.__contains__(self, key)

os.environ = Recording(os.environ)
import pktcap

steps = {}
with pktcap.PcapWriter("trace.pcap") as writer:
    writer.write(1.0, ("192.0.2.5", 50000), ("192.0.2.1", 9999), b"\\x01boot")
frames = list(pktcap.read_dissected("trace.pcap"))
steps["read_dissected"] = len(frames)
dissector = pktcap.FrameDissector()
steps["dissect"] = len([dissector.dissect(f) for f in pktcap.read_frames("trace.pcap")])
steps["filter"] = pktcap.compile_capture_filter("port=9999", pktcap.frame_filter)(frames[0])
with pktcap.CaptureWriter("out.jsonl") as output:
    result = pktcap.copy_frames(frames, output)
steps["copy"] = result.written
with pktcap.CaptureWriter("direct.json") as output:
    output.write(frames[0])
package = os.path.dirname(pktcap.__file__)
# The standard library reads some of these itself (sysconfig reads APPDATA when
# it is imported): what counts is a read made from a pktcap module.
seen = sorted({key for key, asker in reads if asker.startswith(package)})
print(json.dumps({"seen": seen, "steps": steps}))
"""


def test_importing_and_using_the_library_reads_no_variable_and_imports_no_plugin(
    plugin_module, tmp_path
):
    mod = plugin_module()
    ini = tmp_path / "elsewhere.ini"
    ini.write_text("[pktcap]\nplugins = %s\n" % mod.name, encoding="utf-8")
    work = tmp_path / "child"
    work.mkdir()
    env = dict(os.environ)
    env.update(
        PKTCAP_PLUGINS=mod.name,
        PKTCAP_CONFIG=str(ini),
        PYTHONPATH=str(mod.directory),
        APPDATA=str(tmp_path / "a"),
        XDG_CONFIG_HOME=str(tmp_path / "x"),
    )
    done = subprocess.run(
        [sys.executable, "-c", _CHILD],
        cwd=str(work),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    report = json.loads(done.stdout)
    assert report["seen"] == []
    assert report["steps"] == {
        "read_dissected": 1,
        "dissect": 1,
        "filter": True,
        "copy": 1,
    }
    assert not mod.imported


def test_the_same_child_does_import_the_plugin_once_asked_to(plugin_module, tmp_path):
    """The control of the test above: with the call made, the marker is
    written, so its absence there means nothing was imported."""
    mod = plugin_module()
    code = (
        "import pktcap; r = pktcap.DissectorRegistry();"
        "print(len(pktcap.load_plugins(r)))"
    )
    env = dict(os.environ, PKTCAP_PLUGINS=mod.name, PYTHONPATH=str(mod.directory))
    done = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.stdout.strip() == "1", done.stderr[-2000:]
    assert mod.imported


def test_a_dissector_the_plugin_registered_runs_only_in_the_registry_given(
    plugin_module,
):
    mod = plugin_module()
    registry = DissectorRegistry()
    load_plugins(registry, mod.name)
    other = DissectorRegistry()
    frame = CapturedFrame(
        0.0,
        1,
        build.ethernet(
            build.ipv4("10.0.0.5", "10.0.0.1", build.udp(50000, 9999, b"\x01boot"))
        ),
    )
    assert FrameDissector(registry).dissect(frame).layers[-1].opcode == 1
    assert (
        FrameDissector(other).dissect(frame).layers[-1].__class__.__name__ == "UDPLayer"
    )
    assert Dissected  # the contract type is the public one


def test_the_recording_of_the_test_above_sees_a_read_when_there_is_one(
    plugin_module, tmp_path
):
    mod = plugin_module()
    work = tmp_path / "control"
    work.mkdir()
    code = _CHILD.replace(
        "package = os.path.dirname",
        "pktcap.load_plugins(pktcap.DissectorRegistry())\npackage = os.path.dirname",
    )
    env = dict(os.environ, PKTCAP_PLUGINS=mod.name, PYTHONPATH=str(mod.directory))
    done = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(work),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert json.loads(done.stdout)["seen"] == ["PKTCAP_PLUGINS"] and mod.imported
