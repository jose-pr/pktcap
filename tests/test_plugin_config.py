"""The list `load_plugins` is given: what an item may be, how items are
separated, and what is refused before anything is imported.

Where a command line takes the list from (the argument, a variable, a settings
file) is `test_cli_settings.py`. A plugin module is written by the test into a
temporary directory (`plugin_module`); nothing here names a protocol library.
"""

import pickle

import pytest

from pktcap import (
    CapturePluginError,
    DissectorRegistry,
    PktcapError,
    default_registry,
    load_plugins,
)
from pktcap._plugins._load import load_named


def hook_on(port):
    """A plugin that registers a dissector on one UDP port."""
    return (
        "import pktcap\n\n"
        "def pktcap_plugin(registry):\n"
        "    registry.register('udp', %d, lambda data: pktcap.Dissected(None, data))\n"
        % port
    )


def ports(loaded):
    return [selector[1] for plugin in loaded for selector in plugin.selectors]


@pytest.mark.parametrize("separator", [",", ";", ":", " ", "\n", ", ", " ; ", "\t"])
def test_items_are_separated_by_comma_semicolon_colon_or_white_space(
    separator, plugin_module
):
    first, second = plugin_module(hook_on(9001)), plugin_module(hook_on(9002))
    text = first.name + separator + second.name
    assert ports(load_plugins(DissectorRegistry(), text)) == [9001, 9002]
    registry = DissectorRegistry()
    assert ports(load_named(registry, text, "PKTCAP_LOAD")) == [9001, 9002]


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
    item, plugin_module
):
    good = plugin_module(hook_on(9001))
    text = good.name + "," + item
    with pytest.raises(ValueError, match="not a dotted Python name") as caught:
        load_plugins(DissectorRegistry(), text)
    assert not isinstance(caught.value, PktcapError) and not good.imported
    with pytest.raises(CapturePluginError, match="not a dotted Python name") as named:
        load_named(DissectorRegistry(), text, "PKTCAP_LOAD")
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


def test_the_plugin_error_keeps_its_attributes_through_a_pickle():
    plugin = CapturePluginError("x names 'a'", plugin="a", source="PKTCAP_LOAD")
    clone = pickle.loads(pickle.dumps(plugin))
    assert type(clone) is CapturePluginError and str(clone) == str(plugin)
    assert (clone.plugin, clone.source) == ("a", "PKTCAP_LOAD")
    with pytest.raises(TypeError):
        CapturePluginError("no data")  # type: ignore[call-arg]
