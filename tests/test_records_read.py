"""``loads_record``: a record read back from the text ``dumps_record`` writes.

The text is a file somebody hands the library, so these tests are about what
is refused as much as what is read: each refusal, the errors and their types,
and that no message ever quotes the text. The round trip over generated
records and the hostile texts are in ``test_records_hostile.py``.
"""

import math
import pickle
import sys

import pytest

import pktcap
from pktcap import (
    RECORD_FORMATS,
    MissingExtraError,
    PktcapError,
    RecordFormatError,
    UnsupportedFormatError,
    dumps_record,
    loads_record,
)

MARKER = "PLANTED-MARKER-7f3a"

#: A record with every kind of value every format can hold (no null: TOML has
#: none, so ``NULLS`` adds it for the others).
RECORD = {
    "op": "BOOTREQUEST",
    "xid": 2**70,
    "negative": -5,
    "ratio": 1.5,
    "tiny": 5e-324,
    "yes": True,
    "no": False,
    "note": 'caf\u00e9 \x1b[2J \u4e2d \U0001f600 "q" \\ \n\t end',
    "digits": "123",
    "word": "null",
    "empty": "",
    "hops": [1, "x", [2, {"k": "v"}], 1.0],
    "nothing": [],
    "options": {"53": "DHCPDISCOVER", "sizes": [576, 1500], "deep": {"a": {"b": 1}}},
    "none": {},
}
NULLS = {"gap": None, "list": [None, {"k": None}]}


def same(a, b):
    """Equal in value and in type, key order included; NaN equals NaN."""
    if isinstance(a, float) and isinstance(b, float):
        return (math.isnan(a) and math.isnan(b)) or (a == b and str(a) == str(b))
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return list(a) == list(b) and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b


def record_for(name):
    return RECORD if name == "toml" else {**RECORD, **NULLS}


def as_ini_orders_it(record):
    """INI lists the top-level values first and the mappings after them."""
    values = {k: v for k, v in record.items() if not isinstance(v, dict)}
    return {**values, **{k: v for k, v in record.items() if isinstance(v, dict)}}


def message_chain(error):
    """Every message an exception carries or is chained to."""
    seen = []
    while error is not None:
        seen.append(str(error))
        seen.extend(str(arg) for arg in error.args)
        error = error.__cause__ or error.__context__
    return seen


def refused(text, name):
    with pytest.raises(RecordFormatError) as caught:
        loads_record(text, name)
    assert caught.value.format == name
    return caught.value


# -- the call ----------------------------------------------------------------


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_a_record_with_every_kind_of_value_reads_back_as_it_was_written(name):
    record = record_for(name)
    back = loads_record(dumps_record(record, name), name)
    assert back == record
    assert same(back, as_ini_orders_it(record) if name == "ini" else record)


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_the_format_name_is_matched_in_any_letter_case(name):
    text = dumps_record({"a": 1}, name)
    assert loads_record(text, name.upper()) == {"a": 1}
    assert loads_record(text, " %s " % name.title()) == {"a": 1}


def test_json_is_the_default_format():
    assert loads_record('{"a": [1, 2]}') == {"a": [1, 2]}


def test_the_result_is_a_dict():
    for name in RECORD_FORMATS:
        assert type(loads_record(dumps_record({"a": {"b": 1}}, name), name)) is dict


def test_an_unknown_format_is_unsupported_as_for_dumps_record():
    for name in ("xml", "pcap", "pcapng", ""):
        with pytest.raises(UnsupportedFormatError) as read:
            loads_record("{}", name)
        with pytest.raises(UnsupportedFormatError) as written:
            dumps_record({}, name)
        assert str(read.value) == str(written.value)
    with pytest.raises(TypeError):
        loads_record("{}", None)


@pytest.mark.parametrize("name", RECORD_FORMATS)
@pytest.mark.parametrize("text", [b"{}", None, 5, ["a"], bytearray(b"{}")])
def test_the_text_is_a_str_and_never_a_file_name(name, text):
    with pytest.raises(TypeError):
        loads_record(text, name)


def test_a_file_name_is_text_like_any_other(tmp_path):
    path = tmp_path / "record.json"
    path.write_text('{"a": 1}', encoding="utf-8")
    refused(str(path), "json")
    refused(path.name, "ini")


# -- the error ------------------------------------------------------------------


def test_the_error_is_a_pktcap_error_and_a_value_error():
    error = refused("[", "json")
    assert isinstance(error, PktcapError) and isinstance(error, ValueError)
    assert (error.format, error.lineno) == ("json", 1)


def test_the_error_says_where_when_the_reader_knows():
    assert refused('{\n"a": 1,\n"b": \n}', "json").lineno == 4
    assert refused("a: 1\nb: [\n", "yaml").lineno is not None
    assert refused("a = 1\nb = \n", "toml").lineno == 2
    assert refused("[record]\na = 1\n[record]\n", "ini").lineno == 3
    # A reader that keeps no line says so.
    assert refused('{"a": 1, "a": 2}', "json").lineno is None
    assert str(refused("a = 1\nb = \n", "toml")).endswith("(at line 2)")


def test_the_error_survives_a_pickle():
    error = refused("a = 1\nb = \n", "toml")
    clone = pickle.loads(pickle.dumps(error))
    assert (type(clone), clone.format, clone.lineno) == (RecordFormatError, "toml", 2)
    assert str(clone) == str(error)


HOSTILE = {
    "json": [
        '{"%s": }' % MARKER,
        '{"%s": 1, "%s": 2}' % (MARKER, MARKER),
        '["%s"]' % MARKER,
        '{"a": "%s"} {"b": 1}' % MARKER,
        '{"a": "%s", "n": NaN}' % MARKER,
        "%s" % MARKER,
        '{"%s": "\\ud800\\' % MARKER,
    ],
    "yaml": [
        "%s: [" % MARKER,
        "%s: 1\n%s: 2\n" % (MARKER, MARKER),
        "a: !%s x\n" % MARKER,
        "a: !!python/object:%s x\n" % MARKER,
        "- %s\n" % MARKER,
        "? [%s]\n: 1\n" % MARKER,
        "a: %s\n---\nb: 1\n" % MARKER,
        "a: *%s\n" % MARKER,
        "a: \x00%s\n" % MARKER,
        "a: !!binary %s\n" % MARKER,
        "a: &x\n  <<: {%s: 1}\n" % MARKER,
    ],
    "toml": [
        "%s = \n" % MARKER,
        "%s = 1\n%s = 2\n" % (MARKER, MARKER),
        "[%s]\n[%s]\n" % (MARKER, MARKER),
        'a = "%s' % MARKER,
        "d = 2020-01-01 # %s\n" % MARKER,
        "%s\n" % MARKER,
        'a = "\\uD800%s"\n' % MARKER,
        "%s = [1]\n[[%s]]\n" % (MARKER, MARKER),
        "a = {%s = 1, %s = 2}\n" % (MARKER, MARKER),
    ],
    "ini": [
        "%s = 1\n" % MARKER,
        "[a]\n%s\n" % MARKER,
        "[%s]\n[%s]\n" % (MARKER, MARKER),
        "[a]\n%s = 1\n%s = 2\n" % (MARKER, MARKER),
        "[a]\n%%FF%s = 1\n" % MARKER,
        "# %s\n" % MARKER,
        "[a]\nk = 1\n[%s\n" % MARKER,
    ],
}


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_no_message_quotes_the_text_and_nothing_is_chained(name):
    for text in HOSTILE[name]:
        assert MARKER in text
        error = refused(text, name)
        assert error.__cause__ is None and error.__context__ is None
        assert all(MARKER not in message for message in message_chain(error))
        assert MARKER not in repr(error)


# -- what is one record --------------------------------------------------------


NOT_ONE_RECORD = {
    "json": [
        "",
        "  \n",
        "[1, 2]",
        "5",
        '"text"',
        "null",
        "true",
        "{} {}",
        '{"a": 1}\n{"b": 2}\n',
    ],
    "yaml": [
        "",
        "\n",
        "- 1\n- 2\n",
        "5\n",
        "text\n",
        "null\n",
        "---\n",
        "a: 1\n---\nb: 2\n",
    ],
    "toml": ["", "a = 1\n[a]\n", "= 1\n"],
    "ini": ["", "# only a comment\n", "a = 1\n", "[a]\n[a]\n"],
}


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_text_that_is_not_one_record_is_refused(name):
    for text in NOT_ONE_RECORD[name]:
        refused(text, name)


def test_text_with_nothing_in_it_is_the_empty_record_only_where_it_is_written():
    # dumps_record writes a line feed for an empty record in these two.
    assert dumps_record({}, "toml") == dumps_record({}, "ini") == "\n"
    assert loads_record("\n", "toml") == {}
    assert loads_record("\n", "ini") == {}
    assert loads_record("{}\n", "json") == {} == loads_record("{}\n", "yaml")
    refused("\n", "json")
    refused("\n", "yaml")
    for name in RECORD_FORMATS:
        refused("", name)


def test_json_takes_surrounding_space_but_not_a_second_value():
    assert loads_record('  \n{"a": 1}\n\n') == {"a": 1}
    refused('{"a": 1}\n{"a": 1}\n', "json")
    refused('{"a": 1} x', "json")
    refused("\ufeff{}", "json")


def test_yaml_takes_a_leading_marker_on_one_document():
    assert loads_record("---\na: 1\n", "yaml") == {"a": 1}
    assert loads_record("---\na: 1\n...\n", "yaml") == {"a": 1}
    refused("---\na: 1\n---\nb: 2\n", "yaml")
    refused("---\na: 1\n---\n", "yaml")


# -- what is refused though a looser reader takes it ---------------------------


@pytest.mark.parametrize(
    "name, text",
    [
        ("json", '{"a": 1, "a": 2}'),
        ("json", '{"a": {"b": 1, "b": 2}}'),
        ("json", '{"a": [{"b": 1, "b": 1}]}'),
        ("yaml", "a: 1\na: 2\n"),
        ("yaml", "a:\n  b: 1\n  b: 2\n"),
        ("yaml", "a: 1\n'a': 1\n"),
        ("yaml", "1: x\n1.0: y\n"),
        ("toml", "a = 1\na = 2\n"),
        ("toml", "[a]\nb = 1\n[a]\nc = 1\n"),
        ("toml", "[a]\nb = 1\nb = 2\n"),
        ("ini", "[a]\nb = 1\nb = 2\n"),
        ("ini", "[a]\nb = 1\n[a]\nc = 1\n"),
        ("ini", "[record]\na = 1\n[a]\nb = 1\n"),
        ("ini", "[a]\nk%20x = 1\nk x = 2\n"),
        ("ini", "[a%20b]\nx = 1\n[a b]\nx = 1\n"),
        ("ini", '[a]\nv = {"k": 1, "k": 2}\n'),
    ],
)
def test_a_key_written_twice_is_refused(name, text):
    refused(text, name)


def test_json_refuses_nan_and_the_infinities_dumps_record_refuses_to_write():
    for text in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999", "[NaN]"):
        refused('{"a": %s}' % text, "json")
        with pytest.raises(ValueError):
            dumps_record(
                {"a": float(text.strip("[]").replace("Infinity", "inf"))}, "json"
            )
    assert loads_record('{"a": 1e308, "b": -1e-999}') == {"a": 1e308, "b": 0.0}


def test_yaml_and_toml_read_the_nan_and_infinity_their_writers_write():
    for name in ("yaml", "toml"):
        record = {"n": math.nan, "i": math.inf, "m": -math.inf, "z": -0.0}
        assert same(loads_record(dumps_record(record, name), name), record)


@pytest.mark.parametrize(
    "text",
    [
        "a: !!python/object/apply:os.getcwd []\n",
        "a: !!python/name:os.getcwd\n",
        "a: !!python/tuple [1]\n",
        "a: !custom x\n",
        "!!python/object:collections.OrderedDict {}\n",
        "a: !!map {b: !!python/str x}\n",
    ],
)
def test_yaml_is_read_with_the_safe_loader_only(text):
    refused(text, "yaml")


@pytest.mark.parametrize(
    "text",
    [
        "a: 2020-01-01\n",
        "a: 2020-01-01 10:00:00\n",
        "a: !!set {x}\n",
        "a: !!omap [b: 1]\n",
        "a: !!pairs [b: 1]\n",
        "a: !!timestamp 2020-01-01\n",
        "? [1, 2]\n: x\n",
        "? {a: b}\n: x\n",
    ],
)
def test_yaml_values_that_are_not_plain_data_are_refused(text):
    refused(text, "yaml")


def test_yaml_dates_written_as_text_stay_text():
    record = {"d": "2020-01-01", "t": "12:30", "n": "~", "y": "yes", "o": "0o17"}
    assert same(loads_record(dumps_record(record, "yaml"), "yaml"), record)


def test_yaml_explicit_core_tags_are_plain():
    text = "a: !!str 5\nb: !!int '7'\nc: !!float 1\nd: !!bool true\ne: !!null ''\n"
    assert loads_record(text, "yaml") == {
        "a": "5",
        "b": 7,
        "c": 1.0,
        "d": True,
        "e": None,
    }


def test_yaml_binary_is_the_one_type_beyond_plain_data_and_reads_back():
    record = {"raw": b"\x00\xffab"}
    text = dumps_record(record, "yaml")
    assert "!!binary" in text
    assert same(loads_record(text, "yaml"), record)
    refused("a: !!binary 'A'\n", "yaml")


def test_yaml_keeps_the_type_of_a_key_it_was_given():
    for record in ({1: "a", None: "b", 2.5: "d", "s": "e"}, {True: "c", False: "d"}):
        back = loads_record(dumps_record(record, "yaml"), "yaml")
        assert same(back, record)


def test_a_yaml_merge_key_is_refused():
    refused("base: &b {x: 1}\nother:\n  <<: *b\n  y: 2\n", "yaml")
    refused("a: {<<: [{x: 1}, {y: 2}]}\n", "yaml")


def test_an_object_a_record_holds_twice_is_written_twice_in_yaml():
    """No anchor and no alias is written, so what is written is read back."""
    record_list = [1, 2]
    text = dumps_record({"a": record_list, "b": record_list}, "yaml")
    assert "&" not in text and "*" not in text
    back = loads_record(text, "yaml")
    assert back == {"a": [1, 2], "b": [1, 2]}
    assert back["a"] is not back["b"]


def test_a_yaml_value_that_contains_itself_is_refused():
    refused("a: &x [*x]\n", "yaml")
    refused("&x\na: *x\n", "yaml")
    refused("a: &x {b: *x}\n", "yaml")


def test_toml_dates_and_times_are_refused():
    for text in (
        "d = 2020-01-01\n",
        "d = 10:00:00\n",
        "d = 2020-01-01T10:00:00Z\n",
        "d = [2020-01-01]\n",
    ):
        refused(text, "toml")


def deeply(text, name):
    """The record read from nesting no parser can recurse through, or the error
    that says so: the interpreter decides which, never a RecursionError."""
    try:
        return loads_record(text, name)
    except RecordFormatError as error:
        assert "nested too deeply" in str(error)
        return None


def test_nesting_past_what_the_interpreter_can_parse_is_an_error_not_a_crash():
    depth = 100_000
    brackets = "[" * depth + "]" * depth
    deeply('{"a": %s}' % brackets, "json")
    deeply("a = %s\n" % brackets, "toml")
    deeply("[x]\na = %s\n" % brackets, "ini")
    # Where the parser recurses in Python, as every parser does on 3.9 and
    # PyYAML does everywhere, the error is certain.
    assert deeply("a: %s\n" % brackets, "yaml") is None


# -- INI -------------------------------------------------------------------------


def test_a_value_that_is_not_json_is_its_text_so_a_hand_written_file_reads():
    text = (
        "# written by a person\n"
        "[record]\n"
        "op = BOOTREQUEST\n"
        "xid: 305441741\n"
        "ok = true\n"
        "name = null\n"
        "hops = [1, 2\n"
        "ratio = 1.5.3\n"
        "empty =\n"
        "nan = NaN\n"
        "big = 1e999\n"
        'quoted = "x"\n'
        "\n"
        "; and a section\n"
        "[options]\n"
        "53 = DHCPDISCOVER\n"
        "Mixed Case = 1\n"
    )
    assert same(
        loads_record(text, "ini"),
        {
            "op": "BOOTREQUEST",
            "xid": 305441741,
            "ok": True,
            "name": None,
            "hops": "[1, 2",
            "ratio": "1.5.3",
            "empty": "",
            "nan": "NaN",
            "big": "1e999",
            "quoted": "x",
            "options": {"53": "DHCPDISCOVER", "Mixed Case": 1},
        },
    )


def test_ini_names_are_percent_decoded_and_case_is_kept():
    record = {"a b": 1, "A": 2, "[x]": {"k=v": 3, "K": 4, "100%": 5, "\u00e9\u4e2d": 6}}
    text = dumps_record(record, "ini")
    assert "a%20b" in text and "%5Bx%5D" in text
    assert same(loads_record(text, "ini"), record)


def test_ini_default_is_a_section_like_any_other():
    record = {"DEFAULT": {"a": 1}, "default": {"b": 2}, "x": {"c": 3}}
    text = dumps_record(record, "ini")
    assert "[%44EFAULT]" in text
    assert same(loads_record(text, "ini"), record)
    # Written by hand, the section holds only what it holds: nothing is
    # inherited by the others.
    assert loads_record("[DEFAULT]\na = 1\n[x]\nb = 2\n", "ini") == {
        "DEFAULT": {"a": 1},
        "x": {"b": 2},
    }


def test_ini_percent_is_text_and_a_value_is_not_interpolated():
    text = '[x]\na = 100%\nb = %(a)s\nc = "%(a)s"\nd%25 = 1\n'
    assert loads_record(text, "ini") == {
        "x": {"a": "100%", "b": "%(a)s", "c": "%(a)s", "d%": 1}
    }


def test_ini_top_level_values_and_sections_come_back_in_the_order_written():
    record = {"z": 1, "m": {"b": 1, "a": 2}, "a": [1]}
    text = dumps_record(record, "ini")
    assert list(loads_record(text, "ini")) == ["z", "a", "m"]
    assert same(loads_record(text, "ini"), {"z": 1, "a": [1], "m": {"b": 1, "a": 2}})


def test_ini_text_before_the_first_section_or_with_no_section_is_refused():
    refused("a = 1\n[x]\nb = 2\n", "ini")
    refused("a = 1\n", "ini")
    refused("# a comment\n", "ini")
    refused("[x]\nnot an option\n", "ini")
    refused("[x\na = 1\n", "ini")
    refused("[a]\nb = 1\n[a%FF]\n", "ini")


def test_ini_a_section_named_record_cannot_be_told_from_the_top_level():
    # What dumps_record refuses to write beside top-level values:
    with pytest.raises(ValueError):
        dumps_record({"record": {"a": 1}, "b": 2}, "ini")
    # And read, [record] is always the top-level values.
    assert loads_record("[record]\na = 1\n", "ini") == {"a": 1}
    refused("[record]\na = 1\n[a]\nb = 1\n", "ini")


# -- the extras -------------------------------------------------------------------


def test_yaml_without_pyyaml_names_the_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(ImportError) as caught:
        loads_record("a: 1\n", "yaml")
    assert isinstance(caught.value, MissingExtraError)
    assert isinstance(caught.value, PktcapError)
    assert (caught.value.format, caught.value.extra) == ("yaml", "yaml")
    assert (
        str(caught.value)
        == "YAML input needs the 'yaml' extra: pip install \"pktcap[yaml]\""
    )


def test_toml_without_a_reader_names_the_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "tomllib", None)
    monkeypatch.setitem(sys.modules, "tomli", None)
    with pytest.raises(ImportError) as caught:
        loads_record("a = 1\n", "toml")
    assert isinstance(caught.value, MissingExtraError)
    assert (caught.value.format, caught.value.extra) == ("toml", "toml")
    assert (
        str(caught.value)
        == "TOML input needs the 'toml' extra: pip install \"pktcap[toml]\""
    )


def test_toml_reads_with_tomli_when_the_interpreter_has_no_tomllib(monkeypatch):
    pytest.importorskip("tomli")
    monkeypatch.setitem(sys.modules, "tomllib", None)
    assert loads_record("a = [1, 2]\n[b]\nc = 'x'\n", "toml") == {
        "a": [1, 2],
        "b": {"c": "x"},
    }
    refused("a = 1\na = 2\n", "toml")


def test_reading_toml_needs_no_writer(monkeypatch):
    monkeypatch.setitem(sys.modules, "tomli_w", None)
    if sys.version_info < (3, 11):
        pytest.importorskip("tomli")
    assert loads_record("a = 1\n", "toml") == {"a": 1}


def test_a_defect_inside_the_reader_is_a_record_error_and_not_a_traceback(monkeypatch):
    yaml = pytest.importorskip("yaml")

    def broken(*args, **kwargs):
        raise RuntimeError("a defect in the dependency")

    monkeypatch.setattr(yaml.SafeLoader, "check_data", broken)
    with pytest.raises(RecordFormatError):
        loads_record("a: 1\n", "yaml")


def test_formats_that_need_no_extra_read_without_any(monkeypatch):
    for module in ("yaml", "tomli_w", "tomli", "tomllib"):
        monkeypatch.setitem(sys.modules, module, None)
    assert loads_record('{"a": 1}\n', "json") == {"a": 1}
    assert loads_record("[record]\na = 1\n", "ini") == {"a": 1}


def test_importing_pktcap_imports_no_reader():
    import subprocess

    code = (
        "import sys, pktcap\n"
        "bad = [m for m in ('yaml', 'tomli', 'tomllib', 'tomli_w') if m in sys.modules]\n"
        "assert not bad, bad\n"
        "pktcap.loads_record('{}')\n"
        "pktcap.loads_record('[record]', 'ini')\n"
        "bad = [m for m in ('yaml', 'tomli', 'tomllib', 'tomli_w') if m in sys.modules]\n"
        "assert not bad, bad\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr[-1000:]


def test_the_example_in_the_formats_header_runs():
    import re
    from pathlib import Path

    header = Path(pktcap.__file__).parent / "_formats" / "AGENTS.md"
    blocks = re.findall(
        r"```python\n(.*?)```", header.read_text(encoding="utf-8"), re.DOTALL
    )
    assert len(blocks) == 1
    exec(compile(blocks[0], "AGENTS.md", "exec"), {"pktcap": pktcap})


# -- what each refusal says ----------------------------------------------------

#: (format, text, what the message holds, the line it names or None)
SAYS = [
    ("json", "", "is empty", None),
    ("json", "[1]", "not a mapping", None),
    ("json", '{"a": 1} {"b": 2}', "more than one value", 1),
    ("json", '{"a": 1, "a": 2}', "written twice", None),
    ("json", '{"a": NaN}', "NaN or an infinity", None),
    ("json", '{"a": 1e999}', "NaN or an infinity", None),
    ("json", '{\n"a": }', "not valid JSON", 2),
    ("yaml", "", "no document", None),
    ("yaml", "- 1\n", "not a mapping", None),
    ("yaml", "a: 1\n---\nb: 2\n", "more than one document", None),
    ("yaml", "a: 1\nb: 1\nb: 2\n", "written twice", 3),
    ("yaml", "a: 1\nb:\n  <<: {c: 1}\n", "merge key", 3),
    ("yaml", "a: 1\nb: !!python/name:os.getcwd\n", "not plain data", 2),
    ("yaml", "a: 1\nb: 2020-01-01\n", "not plain data", None),
    ("yaml", "2020-01-01: x\n", "not plain data", None),
    ("yaml", "a: 1\nb: \x00\n", "forbids", 2),
    ("yaml", "a: &x [*x]\n", "alias", 1),
    ("yaml", "a: [\n", "not valid YAML", 2),
    ("toml", "", "is empty", None),
    ("toml", "a = 1\na = 2\n", "written twice", 2),
    ("toml", "a = 2020-01-01\n", "not plain data", None),
    ("toml", "a = 1\nb = \n", "not valid TOML", 2),
    ("ini", "", "is empty", None),
    ("ini", "# nothing\n", "no section", None),
    ("ini", "a = 1\n[x]\n", "before its first section", 1),
    ("ini", "[x]\nb = 1\nnot an option\n", "no section, option or comment", 3),
    ("ini", "[x]\nb = 1\nb = 2\n", "option is written twice", 3),
    ("ini", "[x]\n[x]\n", "section is written twice", 2),
    ("ini", "[x]\nk%20x = 1\nk x = 2\n", "option is written twice", None),
    ("ini", "[record]\nx = 1\n[x]\n", "top-level key is written twice", None),
    ("ini", "[x]\nk%FF = 1\n", "not UTF-8", None),
]


@pytest.mark.parametrize("name, text, says, lineno", SAYS)
def test_each_refusal_says_what_is_wrong_and_where(name, text, says, lineno):
    error = refused(text, name)
    assert says in str(error)
    assert error.lineno == lineno


def test_a_number_too_long_is_said_so():
    if hasattr(sys, "set_int_max_str_digits"):
        text = "9" * (sys.get_int_max_str_digits() + 1)
        for name, line in (
            ("json", '{"a": %s}' % text),
            ("yaml", "a: %s\n" % text),
            ("toml", "a = %s\n" % text),
            ("ini", "[x]\na = %s\n" % text),
        ):
            assert "number too long to convert" in str(refused(line, name))


def test_running_out_of_memory_is_not_dressed_as_a_record_error(monkeypatch):
    import configparser
    import json

    def boom(*args, **kwargs):
        raise MemoryError

    monkeypatch.setattr(json, "loads", boom)
    monkeypatch.setattr(configparser.RawConfigParser, "read_string", boom)
    for name in ("json", "ini"):
        with pytest.raises(MemoryError):
            loads_record("{}", name)
    yaml = pytest.importorskip("yaml")
    monkeypatch.setattr(yaml.SafeLoader, "check_data", boom)
    with pytest.raises(MemoryError):
        loads_record("a: 1", "yaml")
    try:
        import tomllib
    except ImportError:
        tomllib = pytest.importorskip("tomli")
    monkeypatch.setattr(tomllib, "loads", boom)
    with pytest.raises(MemoryError):
        loads_record("a = 1", "toml")
