"""The record formats: one contract for all of them, then each one's dialect.

The contract suite runs over every name in ``RECORD_FORMATS``; a format added
later passes it unmodified or is not done.
"""

import configparser
import json
import sys

import pytest

import pktcap
from pktcap import (
    OUTPUT_FORMATS,
    RECORD_FORMATS,
    MissingExtraError,
    PktcapError,
    UnsupportedFormatError,
    dumps_record,
    has_output_format,
)

#: What installs each format's writer, and the module that would be missing.
EXTRAS = {"yaml": "yaml", "toml": "tomli_w"}

RECORD = {
    "op": "BOOTREQUEST",
    "xid": 305441741,
    "secs": 0,
    "broadcast": True,
    "ratio": 0.5,
    "hops": [1, 2, 3],
    "note": "caf\u00e9 \x1b[2J \u2028 end",
    "options": {"53": "DHCPDISCOVER", "hostname": "host-1", "sizes": [576, 1500]},
}


def _loads(text, name):
    """Parse ``text`` with a parser this library did not write."""
    if name == "json":
        return json.loads(text)
    if name == "yaml":
        return pytest.importorskip("yaml").safe_load(text)
    if name == "toml":
        try:
            import tomllib
        except ImportError:  # before Python 3.11
            import tomli as tomllib
        return tomllib.loads(text)
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(text)
    out = {}
    for section in parser.sections():
        values = {key: json.loads(value) for key, value in parser.items(section)}
        if section == "record":
            out.update(values)
        else:
            out[section] = values
    return out


# -- the contract every record format passes ------------------------------


def test_the_names_are_a_closed_documented_set():
    assert RECORD_FORMATS == ("json", "yaml", "toml", "ini")
    assert OUTPUT_FORMATS == ("pcap", "pcapng") + RECORD_FORMATS


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_a_record_reads_back_as_itself(name):
    text = dumps_record(RECORD, name)
    assert isinstance(text, str) and text.endswith("\n")
    assert _loads(text, name) == RECORD


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_keys_stay_in_the_records_own_order(name):
    record = {"zeta": 1, "alpha": 2, "mid": 3}
    assert list(_loads(dumps_record(record, name), name)) == ["zeta", "alpha", "mid"]


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_the_output_is_printable_ascii_whatever_the_wire_sent(name):
    """A value may be text a peer chose: no escape sequence of it reaches a
    terminal, and no character needs a console encoding."""
    text = dumps_record({"name": "\x1b[2J\x07\x00 caf\u00e9 \udcff"}, name)
    assert all(32 <= ord(char) < 127 or char == "\n" for char in text), text


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_an_empty_record_is_written(name):
    assert _loads(dumps_record({}, name), name) == {}


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_a_value_that_is_not_plain_data_is_a_type_error_that_does_not_quote_it(name):
    with pytest.raises(TypeError) as caught:
        dumps_record({"secret": object(), "password": b"hunter2"}, name)
    assert not isinstance(caught.value, PktcapError)
    assert "hunter2" not in str(caught.value) and "object at" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


@pytest.mark.parametrize("name", RECORD_FORMATS)
@pytest.mark.parametrize("record", [None, "text", [("a", 1)], 5])
def test_a_record_that_is_not_a_mapping_is_a_type_error(name, record):
    with pytest.raises(TypeError, match="a record is a mapping"):
        dumps_record(record, name)


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_a_mapping_that_is_not_a_dict_is_accepted(name):
    from types import MappingProxyType

    assert _loads(dumps_record(MappingProxyType({"a": 1}), name), name) == {"a": 1}


# -- choosing a format ----------------------------------------------------


def test_the_default_format_is_json():
    assert dumps_record({"a": 1}) == '{"a": 1}\n'


@pytest.mark.parametrize("name", ["JSON", " yaml ", "Toml"])
def test_a_name_is_matched_whatever_its_case(name):
    assert dumps_record({"a": 1}, name)


@pytest.mark.parametrize("name", ["xml", "pcap", "", "json5"])
def test_an_unknown_record_format_names_the_ones_there_are(name):
    with pytest.raises(UnsupportedFormatError) as caught:
        dumps_record({"a": 1}, name)
    assert "json, yaml, toml, ini" in str(caught.value)
    assert isinstance(caught.value, PktcapError) and isinstance(
        caught.value, ValueError
    )


def test_a_format_named_by_something_that_is_not_text_is_a_type_error():
    with pytest.raises(TypeError):
        dumps_record({"a": 1}, None)
    with pytest.raises(TypeError):
        has_output_format(5)


# -- extras ---------------------------------------------------------------


def test_every_format_can_be_written_with_the_dev_extra_installed():
    assert [has_output_format(name) for name in OUTPUT_FORMATS] == [True] * 6
    with pytest.raises(UnsupportedFormatError):
        has_output_format("xml")


@pytest.mark.parametrize("name", sorted(EXTRAS))
def test_a_missing_extra_is_named_where_the_format_is_used(name, monkeypatch):
    """The format stays a known name; using it says what to install."""
    monkeypatch.setitem(sys.modules, EXTRAS[name], None)
    assert name in OUTPUT_FORMATS and name in RECORD_FORMATS
    assert has_output_format(name) is False
    with pytest.raises(ImportError) as caught:
        dumps_record({"a": 1}, name)
    assert isinstance(caught.value, MissingExtraError)
    assert isinstance(caught.value, PktcapError)
    assert (caught.value.format, caught.value.extra) == (name, name)
    assert str(
        caught.value
    ) == '%s output needs the %r extra: pip install "pktcap[%s]"' % (
        name.upper(),
        name,
        name,
    )


def test_the_formats_that_need_no_extra_work_without_any(monkeypatch):
    for module in EXTRAS.values():
        monkeypatch.setitem(sys.modules, module, None)
    assert dumps_record({"a": 1}, "json") == '{"a": 1}\n'
    assert dumps_record({"a": 1}, "ini") == "[record]\na = 1\n"
    assert (
        has_output_format("json")
        and has_output_format("ini")
        and has_output_format("pcap")
    )


def test_only_the_named_import_is_caught(monkeypatch):
    """A failure inside the dependency is not dressed as a missing extra."""
    yaml = pytest.importorskip("yaml")

    def broken(*args, **kwargs):
        raise RuntimeError("a defect in the dependency")

    monkeypatch.setattr(yaml, "safe_dump", broken)
    with pytest.raises(RuntimeError, match="a defect in the dependency"):
        dumps_record({"a": 1}, "yaml")


# -- JSON -----------------------------------------------------------------


def test_json_is_one_line_per_record():
    text = dumps_record(RECORD, "json")
    assert text.count("\n") == 1
    assert '"note": "caf\\u00e9 \\u001b[2J \\u2028 end"' in text


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_json_refuses_what_json_cannot_write(value):
    with pytest.raises(ValueError, match="NaN"):
        dumps_record({"a": value}, "json")


def test_json_refuses_a_record_that_holds_itself_or_is_nested_without_end():
    circular = {}
    circular["self"] = circular
    with pytest.raises(ValueError):
        dumps_record(circular, "json")
    deep = current = {}
    for _ in range(100_000):
        current["d"] = {}
        current = current["d"]
    with pytest.raises(ValueError):
        dumps_record(deep, "json")


# -- YAML -----------------------------------------------------------------


def test_yaml_is_block_style_and_never_a_python_tag():
    pytest.importorskip("yaml")
    text = dumps_record({"op": "x", "options": {"a": [1, 2]}}, "yaml")
    assert text == "op: x\noptions:\n  a:\n  - 1\n  - 2\n"
    assert "!!python" not in dumps_record(RECORD, "yaml")


# -- TOML -----------------------------------------------------------------


def test_toml_has_no_null():
    pytest.importorskip("tomli_w")
    with pytest.raises(TypeError, match="no null"):
        dumps_record({"a": None}, "toml")


def test_toml_escapes_what_is_not_ascii_in_keys_and_values():
    pytest.importorskip("tomli_w")
    record = {"clé": "naïve \U0001f600", "t": {"ü": ["é"]}}
    text = dumps_record(record, "toml")
    assert text.isascii() and "\\U0001F600" in text
    assert _loads(text, "toml") == record


def test_toml_writes_text_that_is_not_unicode_as_the_replacement_character():
    pytest.importorskip("tomli_w")
    assert _loads(dumps_record({"n": "a\udcffb"}, "toml"), "toml") == {"n": "a�b"}


# -- INI ------------------------------------------------------------------


def test_ini_puts_mappings_in_sections_and_the_rest_in_record():
    text = dumps_record(
        {"op": "x", "n": 1, "options": {"53": "y"}, "none": None}, "ini"
    )
    assert text == ('[record]\nop = "x"\nn = 1\nnone = null\n\n[options]\n53 = "y"\n')


def test_ini_writes_the_layout_a_caller_shapes():
    text = dumps_record({"message": {"op": "x"}, "options": {"53": "y"}}, "ini")
    assert text == '[message]\nop = "x"\n\n[options]\n53 = "y"\n'


def test_an_ini_name_from_the_wire_cannot_break_out_of_its_line():
    hostile = {"a]\n[injected": 1, "k=v": {"x\ny": 2, "#c": 3}, "default": {"d": 4}}
    text = dumps_record(hostile, "ini")
    assert text.count("[") == 3 and "injected]" not in text
    assert _loads(text, "ini") == {
        "a%5D%0A%5Binjected": 1,
        "k%3Dv": {"x%0Ay": 2, "%23c": 3},
        "%64efault": {"d": 4},
    }


def test_ini_refuses_two_names_that_would_be_one():
    with pytest.raises(ValueError, match="two options"):
        dumps_record({1: "a", "1": "b"}, "ini")
    with pytest.raises(ValueError, match="two sections"):
        dumps_record({1: {"a": 1}, "1": {"b": 2}}, "ini")
    with pytest.raises(ValueError, match="also"):
        dumps_record({"x": 1, "record": {"y": 2}}, "ini")


def test_nothing_about_formats_is_reachable_but_through_the_root():
    assert not hasattr(pktcap, "formats")
