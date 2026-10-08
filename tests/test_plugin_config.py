"""Where a plugin list comes from: the argument, the variable, the file.

The order of the three, the file's location on each platform and its dialect,
and what is refused. A plugin module is written by the test into a temporary
directory (``plugin_module``); nothing here names a protocol library.
"""

import os
import pickle
import sys

import pytest

from pktcap import (
    CaptureConfigError,
    CapturePluginError,
    DissectorRegistry,
    PktcapError,
    capture_config_path,
    default_registry,
    load_plugins,
)

IS_WINDOWS = os.name == "nt"


def hook_on(port):
    """A plugin that registers a dissector on one UDP port."""
    return (
        "import pktcap\n\n"
        "def pktcap_plugin(registry):\n"
        "    registry.register('udp', %d, lambda data: pktcap.Dissected(None, data))\n"
        % port
    )


@pytest.fixture
def home(tmp_path, monkeypatch):
    """The user's configuration directory, set through this platform's own
    variable: ``APPDATA`` on Windows, ``XDG_CONFIG_HOME`` elsewhere."""
    base = tmp_path / "config-home"
    base.mkdir()
    monkeypatch.delenv("PKTCAP_CONFIG", raising=False)
    monkeypatch.setenv("APPDATA" if IS_WINDOWS else "XDG_CONFIG_HOME", str(base))
    return base


def write_default(home, text, *, raw=None):
    target = home / "pktcap"
    target.mkdir(exist_ok=True)
    (target / "pktcap.ini").write_bytes(
        raw if raw is not None else text.encode("utf-8")
    )
    return target / "pktcap.ini"


def ports(loaded):
    return [selector[1] for plugin in loaded for selector in plugin.selectors]


# -- where the file is -------------------------------------------------------


def test_the_file_is_under_the_platforms_configuration_directory(home):
    assert capture_config_path() == home / "pktcap" / "pktcap.ini"


def test_the_configuration_directory_falls_back_to_the_users_home(
    tmp_path, monkeypatch
):
    user = tmp_path / "user"
    user.mkdir()
    monkeypatch.delenv("PKTCAP_CONFIG", raising=False)
    for name in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.setenv("USERPROFILE", str(user))
    tail = ("AppData", "Roaming") if IS_WINDOWS else (".config",)
    assert capture_config_path() == user.joinpath(*tail, "pktcap", "pktcap.ini")


def test_a_relative_configuration_directory_is_ignored(tmp_path, monkeypatch):
    user = tmp_path / "user"
    user.mkdir()
    monkeypatch.delenv("PKTCAP_CONFIG", raising=False)
    monkeypatch.setenv("APPDATA" if IS_WINDOWS else "XDG_CONFIG_HOME", "zzrel/dir")
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.setenv("USERPROFILE", str(user))
    path = capture_config_path()
    assert path is not None and path.is_absolute()
    assert str(user) in str(path) and "zzrel" not in str(path)


def test_the_argument_names_the_file_before_the_variable_does(tmp_path, monkeypatch):
    other = tmp_path / "other.ini"
    monkeypatch.setenv("PKTCAP_CONFIG", str(other))
    assert capture_config_path() == other
    chosen = tmp_path / "chosen.ini"
    assert capture_config_path(chosen) == chosen
    assert capture_config_path(str(chosen)) == chosen
    assert capture_config_path("NONE") is None
    assert capture_config_path("none") is None


@pytest.mark.parametrize("value", ["none", "None", " NONE "])
def test_none_in_the_variable_names_no_file(value, monkeypatch):
    monkeypatch.setenv("PKTCAP_CONFIG", value)
    assert capture_config_path() is None


def test_a_relative_variable_is_refused_as_one_that_outlives_its_directory(
    monkeypatch,
):
    monkeypatch.setenv("PKTCAP_CONFIG", "pktcap.ini")
    with pytest.raises(CaptureConfigError, match="PKTCAP_CONFIG must be an absolute"):
        capture_config_path()
    with pytest.raises(CaptureConfigError):
        load_plugins(DissectorRegistry())
    # An argument may be relative: the user typed it where they are.
    assert str(capture_config_path("pktcap.ini")) == "pktcap.ini"


def test_a_config_that_is_not_a_path_is_a_type_error():
    with pytest.raises(TypeError):
        capture_config_path(5)  # type: ignore[arg-type]


# -- the order: argument, variable, file ---------------------------------------


def test_the_nearest_source_that_names_a_list_is_the_list(
    plugin_module, home, monkeypatch
):
    arg, var, ini = (plugin_module(hook_on(p)) for p in (9001, 9002, 9003))
    write_default(home, "[pktcap]\nload = %s\n" % ini.name)
    registry = DissectorRegistry()
    (only,) = load_plugins(registry)
    assert (only.name, only.source) == (ini.name, str(capture_config_path()))
    assert ports([only]) == [9003]

    monkeypatch.setenv("PKTCAP_LOAD", var.name)
    (only,) = load_plugins(DissectorRegistry())
    assert (only.name, only.source) == (var.name, "PKTCAP_LOAD")

    (only,) = load_plugins(DissectorRegistry(), arg.name)
    assert (only.name, only.source) == (arg.name, "argument")
    (only,) = load_plugins(DissectorRegistry(), [arg.name])
    assert only.source == "argument"
    # A higher source replaces the list: lists never add up.
    registry = DissectorRegistry()
    load_plugins(registry, arg.name)
    assert (("udp", 9001) in registry.selectors()) and not (
        ("udp", 9002) in registry.selectors() or ("udp", 9003) in registry.selectors()
    )


def test_a_source_below_the_list_is_not_opened(plugin_module, home, monkeypatch):
    var = plugin_module(hook_on(9002))
    write_default(home, "", raw=b"\xff\xfe not even text")  # unreadable if opened
    monkeypatch.setenv("PKTCAP_LOAD", var.name)
    (only,) = load_plugins(DissectorRegistry())
    assert only.source == "PKTCAP_LOAD"
    (only,) = load_plugins(DissectorRegistry(), var.name)
    assert only.source == "argument"


def test_a_file_named_by_the_config_argument_is_read_and_checked_whatever_the_list(
    plugin_module, tmp_path
):
    arg = plugin_module(hook_on(9001))
    broken = tmp_path / "broken.ini"
    broken.write_text("[pktcap]\nplugin = x\n", encoding="utf-8")
    with pytest.raises(CaptureConfigError, match="plugin"):
        load_plugins(DissectorRegistry(), arg.name, config=broken)
    assert not arg.imported
    with pytest.raises(FileNotFoundError):
        load_plugins(DissectorRegistry(), arg.name, config=tmp_path / "missing.ini")
    assert not arg.imported


def test_a_file_named_by_the_variable_is_not_opened_when_a_list_is_given(
    plugin_module, tmp_path, monkeypatch
):
    arg = plugin_module(hook_on(9001))
    monkeypatch.setenv("PKTCAP_CONFIG", str(tmp_path / "missing.ini"))
    (only,) = load_plugins(DissectorRegistry(), arg.name)
    assert only.source == "argument"


def test_the_variable_may_name_the_file(plugin_module, tmp_path, monkeypatch):
    mod = plugin_module(hook_on(9001))
    ini = tmp_path / "named.ini"
    ini.write_text("[pktcap]\nload = %s\n" % mod.name, encoding="utf-8")
    monkeypatch.setenv("PKTCAP_CONFIG", str(ini))
    (only,) = load_plugins(DissectorRegistry())
    assert (only.name, only.source) == (mod.name, str(ini))


def test_a_named_file_must_exist_and_the_default_need_not(home, tmp_path, monkeypatch):
    assert load_plugins(DissectorRegistry()) == ()
    with pytest.raises(FileNotFoundError):
        load_plugins(DissectorRegistry(), config=tmp_path / "missing.ini")
    monkeypatch.setenv("PKTCAP_CONFIG", str(tmp_path / "missing.ini"))
    with pytest.raises(FileNotFoundError):
        load_plugins(DissectorRegistry())


def test_none_is_the_explicit_empty_list_and_a_file_is_then_not_opened(
    plugin_module, home, monkeypatch
):
    mod = plugin_module(hook_on(9001))
    write_default(home, "[pktcap]\nload = %s\n" % mod.name)
    monkeypatch.setenv("PKTCAP_LOAD", "None")
    assert load_plugins(DissectorRegistry()) == ()
    monkeypatch.delenv("PKTCAP_LOAD")
    assert load_plugins(DissectorRegistry(), "none") == ()
    assert load_plugins(DissectorRegistry(), ["NONE"]) == ()
    assert load_plugins(DissectorRegistry(), config="none") == ()
    assert not mod.imported


def test_none_in_the_file_is_the_empty_list(home):
    write_default(home, "[pktcap]\nload = none\n")
    assert load_plugins(DissectorRegistry()) == ()


def test_an_empty_variable_is_unset(plugin_module, home, monkeypatch):
    mod = plugin_module(hook_on(9001))
    write_default(home, "[pktcap]\nload = %s\n" % mod.name)
    monkeypatch.setenv("PKTCAP_LOAD", "  ")
    (only,) = load_plugins(DissectorRegistry())
    assert only.source != "PKTCAP_LOAD"


@pytest.mark.parametrize("separator", [",", ";", ":", " ", "\n", ", ", " ; ", "\t"])
def test_items_are_separated_by_comma_semicolon_colon_or_white_space(
    separator, plugin_module, monkeypatch
):
    first, second = plugin_module(hook_on(9001)), plugin_module(hook_on(9002))
    monkeypatch.setenv("PKTCAP_LOAD", first.name + separator + second.name)
    assert ports(load_plugins(DissectorRegistry())) == [9001, 9002]


def test_the_working_directory_names_nothing(plugin_module, tmp_path, monkeypatch):
    """A file of the working directory is not a source: the list is the file
    of the user's configuration directory or nothing."""
    mod = plugin_module(hook_on(9001))
    work = tmp_path / "work"
    work.mkdir()
    for name in ("pktcap.ini", ".pktcap.ini", ".pkcap.ini", "setup.cfg"):
        (work / name).write_text("[pktcap]\nload = %s\n" % mod.name, encoding="utf-8")
    monkeypatch.chdir(work)
    monkeypatch.delenv("PKTCAP_CONFIG")
    monkeypatch.setenv(
        "APPDATA" if IS_WINDOWS else "XDG_CONFIG_HOME", str(tmp_path / "e")
    )
    assert load_plugins(DissectorRegistry()) == () and not mod.imported


# -- the file's dialect ---------------------------------------------------------


def test_the_dialect_comments_continuation_lines_and_a_byte_order_mark(
    plugin_module, home
):
    one, two = plugin_module(hook_on(9001)), plugin_module(hook_on(9002))
    text = (
        "# the first line is a comment\n"
        "; and so is this one\n"
        "\n"
        "[pktcap]\n"
        "load = %s,\n"
        "   %s\n" % (one.name, two.name)
    )
    write_default(home, "", raw=b"\xef\xbb\xbf" + text.encode("utf-8"))
    assert ports(load_plugins(DissectorRegistry())) == [9001, 9002]


def test_a_percent_sign_is_not_interpolated(home):
    write_default(home, "[pktcap]\nload = %(x)s\n")
    with pytest.raises(CapturePluginError, match="not a dotted Python name") as caught:
        load_plugins(DissectorRegistry())
    assert caught.value.source == str(capture_config_path())


def test_an_empty_file_or_an_empty_section_or_value_names_nothing(home):
    for text in ("", "[pktcap]\n", "[pktcap]\nload =\n", "# only a comment\n"):
        write_default(home, text)
        assert load_plugins(DissectorRegistry()) == ()


SECRET = "s3cr3t-line-content"


@pytest.mark.parametrize(
    "text, lineno, problem",
    [
        ("[pktcap]\n%s\n" % SECRET, 2, "not a section header"),
        ("load = %s\n" % SECRET, 1, "text before the first section"),
        ("[pktcap]\nload = a\n[pktcap]\n", 3, "a section written twice"),
        ("[pktcap]\nload = a\nload = b\n", 3, "a key written twice"),
        ("[pktcap]\nload: %s\n" % SECRET, 2, "not a section header"),
        ("\n\n[pktcap\nload = x\n", 3, "text before the first section"),
        (
            "[pktcap]\nplugin = %s\n" % SECRET,
            None,
            "unknown key 'plugin' in \\[pktcap\\]",
        ),
        ("[pktcap]\nLoad = x\n", None, "unknown key 'Load'"),
        ("[other]\nload = x\n", None, "unknown section 'other'"),
        ("[DEFAULT]\nload = x\n", None, "unknown section 'DEFAULT'"),
        ("[pktcap]\nload = a\n[extra]\n", None, "unknown section 'extra'"),
    ],
)
def test_a_malformed_file_is_one_error_with_the_path_and_the_line_and_no_text_of_it(
    home, text, lineno, problem
):
    path = write_default(home, text)
    with pytest.raises(CaptureConfigError, match=problem) as caught:
        load_plugins(DissectorRegistry())
    error = caught.value
    assert error.lineno == lineno and error.path == str(path)
    assert str(error).startswith(
        "%s:%d: " % (path, lineno) if lineno else "%s: " % path
    )
    assert SECRET not in str(error) and error.__cause__ is None
    assert error.__context__ is None or error.__suppress_context__
    assert isinstance(error, PktcapError) and isinstance(error, ValueError)


def test_a_file_that_is_not_utf_8_is_refused_with_its_path_and_the_octet(home):
    path = write_default(home, "", raw=b"[pktcap]\nload = \xff\n")
    with pytest.raises(
        CaptureConfigError, match="not UTF-8 \\(at octet 16\\)"
    ) as caught:
        load_plugins(DissectorRegistry())
    assert caught.value.path == str(path) and caught.value.lineno is None


def test_a_file_over_65536_octets_is_refused_and_one_of_exactly_that_is_read(home):
    padding = "# " + "x" * 60 + "\n"
    head = b"[pktcap]\nload = none\n"
    body = (padding * 2000).encode("ascii")
    exact = head + body[: 65536 - len(head)]
    assert len(exact) == 65536
    write_default(home, "", raw=exact)
    assert load_plugins(DissectorRegistry()) == ()
    write_default(home, "", raw=exact + b"#")
    with pytest.raises(CaptureConfigError, match="over 65536 octets"):
        load_plugins(DissectorRegistry())


def test_a_long_key_is_named_cut_and_escaped(home):
    write_default(home, "[pktcap]\n%s = x\n" % ("k" * 500))
    with pytest.raises(CaptureConfigError) as caught:
        load_plugins(DissectorRegistry())
    assert "k" * 41 not in str(caught.value) and "..." in str(caught.value)


def test_a_directory_in_place_of_the_default_file_is_refused(home):
    (home / "pktcap").mkdir()
    (home / "pktcap" / "pktcap.ini").mkdir()
    if hasattr(os, "geteuid"):  # the default file is checked where owners are
        with pytest.raises(CaptureConfigError, match="not a regular file"):
            load_plugins(DissectorRegistry())
    else:
        with pytest.raises(OSError):
            load_plugins(DissectorRegistry())


# -- what an item may be ------------------------------------------------------


@pytest.mark.parametrize(
    "item",
    [
        "a/b",
        "a\\b",
        "../x",
        "./x",
        ".x",
        "x.",
        "a..b",
        "a-b",
        "1a",
        "é",
        "mod" * 100,
        "c:\\temp\\plugin",
        "/etc/plugin",
    ],
)
def test_an_item_that_is_no_dotted_name_is_refused_before_anything_is_imported(
    item, plugin_module, monkeypatch
):
    good = plugin_module(hook_on(9001))
    text = good.name + "," + item
    if len(item) <= 255 and not any(c in item for c in ",;: \t"):
        pass
    with pytest.raises(ValueError, match="not a dotted Python name") as caught:
        load_plugins(DissectorRegistry(), text)
    assert not isinstance(caught.value, PktcapError) and not good.imported
    monkeypatch.setenv("PKTCAP_LOAD", text)
    with pytest.raises(CapturePluginError, match="not a dotted Python name") as named:
        load_plugins(DissectorRegistry())
    assert named.value.source == "PKTCAP_LOAD" and not good.imported


def test_more_than_64_items_and_a_repeated_item_are_refused(plugin_module):
    names = ["m%d" % i for i in range(64)]
    registry = DissectorRegistry()
    with pytest.raises(ValueError, match="more than 64 plugins"):
        load_plugins(registry, names + ["extra"])
    mod = plugin_module(hook_on(9001))
    with pytest.raises(ValueError, match="named twice"):
        load_plugins(registry, [mod.name, mod.name])
    assert not mod.imported


def test_an_argument_that_is_not_text_is_a_type_error():
    for bad in (5, [1], [b"a"], object()):
        with pytest.raises(TypeError):
            load_plugins(DissectorRegistry(), bad)  # type: ignore[arg-type]


def test_the_registry_is_required_and_must_be_one():
    with pytest.raises(TypeError):
        load_plugins()  # type: ignore[call-arg]
    for bad in (None, default_registry().copy().layers(), "x"):
        with pytest.raises(TypeError):
            load_plugins(bad)  # type: ignore[arg-type]


# -- the file the platform's owner rules decide ------------------------------


def _can_set_everyone_write(tmp_path):
    probe = tmp_path / "probe"
    probe.write_text("x")
    os.chmod(probe, 0o600)
    closed = not probe.stat().st_mode & 0o002
    os.chmod(probe, 0o666)
    return closed and bool(probe.stat().st_mode & 0o002)


def test_a_default_file_everyone_may_write_is_not_read_and_a_named_one_is(
    plugin_module, home, tmp_path, monkeypatch
):
    if not _can_set_everyone_write(tmp_path):
        pytest.skip("this platform records no write permission for everyone")
    mod = plugin_module(hook_on(9001))
    path = write_default(home, "[pktcap]\nload = %s\n" % mod.name)
    os.chmod(path, 0o666)
    with pytest.raises(CaptureConfigError, match="everyone may write it") as caught:
        load_plugins(DissectorRegistry())
    assert caught.value.path == str(path) and not mod.imported
    # A file the user names is theirs: read as it is, whatever its mode.
    (only,) = load_plugins(DissectorRegistry(), config=path)
    assert only.source == str(path)
    monkeypatch.setenv("PKTCAP_CONFIG", str(path))
    (only,) = load_plugins(DissectorRegistry())
    assert only.source == str(path)
    assert (
        load_plugins(DissectorRegistry(), mod.name) != ()
    )  # the default is not opened


def _another_user():
    if not hasattr(os, "geteuid") or os.geteuid() != 0 or not hasattr(os, "chown"):
        return None
    return 65534  # nobody: the owner of a file root did not write


def test_a_default_file_another_user_owns_is_not_read_and_a_named_one_is(
    plugin_module, home, monkeypatch
):
    other = _another_user()
    if other is None:
        pytest.skip("only root can make a file another user owns")
    mod = plugin_module(hook_on(9001))
    path = write_default(home, "[pktcap]\nload = %s\n" % mod.name)
    os.chown(path, other, other)
    with pytest.raises(CaptureConfigError, match="another user owns it") as caught:
        load_plugins(DissectorRegistry())
    assert caught.value.path == str(path) and not mod.imported
    (only,) = load_plugins(DissectorRegistry(), config=path)
    assert only.source == str(path)
    monkeypatch.setenv("PKTCAP_CONFIG", str(path))
    (only,) = load_plugins(DissectorRegistry())
    assert only.source == str(path)


def test_a_default_file_the_user_owns_is_read(plugin_module, home):
    mod = plugin_module(hook_on(9001))
    write_default(home, "[pktcap]\nload = %s\n" % mod.name)
    (only,) = load_plugins(DissectorRegistry())
    assert only.name == mod.name


# -- the exceptions are values --------------------------------------------------


def test_the_two_errors_keep_their_attributes_through_a_pickle():
    plugin = CapturePluginError("x names 'a'", plugin="a", source="PKTCAP_LOAD")
    clone = pickle.loads(pickle.dumps(plugin))
    assert type(clone) is CapturePluginError and str(clone) == str(plugin)
    assert (clone.plugin, clone.source) == ("a", "PKTCAP_LOAD")
    config = CaptureConfigError("p:2: bad", path="p", lineno=2)
    clone = pickle.loads(pickle.dumps(config))
    assert type(clone) is CaptureConfigError and str(clone) == "p:2: bad"
    assert (clone.path, clone.lineno) == ("p", 2)
    assert (
        CaptureConfigError("m").path is None and CaptureConfigError("m").lineno is None
    )
    with pytest.raises(TypeError):
        CapturePluginError("no data")  # type: ignore[call-arg]


def test_the_variable_is_read_when_asked_not_before(plugin_module, monkeypatch):
    mod = plugin_module(hook_on(9001))
    registry = DissectorRegistry()
    assert load_plugins(registry) == ()
    monkeypatch.setenv("PKTCAP_LOAD", mod.name)  # set after the import
    assert ports(load_plugins(registry)) == [9001]
    assert sys.modules.get(mod.name) is not None
