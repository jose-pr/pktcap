"""``loads_record`` over generated records and over hostile text.

The round trip is a law (``loads_record(dumps_record(r, f), f) == r``), so it
is checked over thousands of seeded random records per format, and every
exception to it is pinned by a test of its own. The text is untrusted, so the
second half feeds each reader text built to hurt it: nesting, aliases, huge
numbers, noise, a written record cut at every position. Whatever the text,
the answer is a ``dict`` or a ``RecordFormatError`` and nothing else, and no
message holds a piece of the text.
"""

import math
import random
import sys
import time
import tracemalloc

import pytest

import pktcap
from pktcap import RECORD_FORMATS, RecordFormatError, dumps_record, loads_record

MARKER = "PLANTED-MARKER-7f3a"

ALPHABETS = (
    [chr(c) for c in range(0x20, 0x7F)] * 3,
    [chr(c) for c in range(0x00, 0x20)] + ["\x7f", "\x85", "\u2028", "\u2029"],
    list("\u00e9\u00df\u4e2d\u65e5\u00a0\ufeff\ufffd\u0301\u202e\uffff\ufffe"),
    ["\U0001f600", "\U00010000", "\U0010ffff", "\U0001f1e9"],
    ["\ud800", "\udbff", "\udc00", "\udfff"],
)
#: Characters a key is likely to need escaping for in INI.
KEY_ALPHABET = list("ab.-_ []=:;#%\n\t\"'\\/DEFAULTdefaultrecord ")


def same(a, b, ordered=True):
    """Equal in value and type, and in key order when ``ordered``; NaN equals
    NaN."""
    if isinstance(a, float) and isinstance(b, float):
        return (math.isnan(a) and math.isnan(b)) or (a == b and str(a) == str(b))
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        if (list(a) != list(b)) if ordered else (set(a) != set(b)):
            return False
        return all(same(a[k], b[k], ordered) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same(x, y, ordered) for x, y in zip(a, b))
    return a == b


class Generator:
    def __init__(self, seed, *, nulls, empty_names=True):
        self.random = random.Random(seed)
        self.nulls = nulls
        self.empty_names = empty_names

    def text(self, keyish=False):
        pick = self.random.choice
        length = self.random.choice([0, 1, 1, 2, 3, 5, 8, 20])
        out = []
        for _ in range(length):
            if keyish and self.random.random() < 0.5:
                out.append(pick(KEY_ALPHABET))
            else:
                out.append(pick(pick(ALPHABETS)))
        return "".join(out)

    def scalar(self):
        r = self.random
        kind = r.choice(["int", "bigint", "float", "bool", "str", "str", "null"])
        if kind == "int":
            return r.randint(-1000, 1000)
        if kind == "bigint":
            return r.choice([-1, 1]) * r.getrandbits(r.choice([31, 63, 64, 200]))
        if kind == "float":
            return r.choice(
                [
                    r.uniform(-1e6, 1e6),
                    r.uniform(-1, 1) * 10 ** r.randint(-300, 300),
                    -0.0,
                    0.0,
                    1.5,
                    1e22,
                    1e16,
                    5e-324,
                    1.7976931348623157e308,
                ]
            )
        if kind == "bool":
            return r.random() < 0.5
        if kind == "null":
            return None if self.nulls else r.randint(0, 9)
        return self.text()

    def value(self, depth):
        kind = self.random.choice(["scalar", "scalar", "list", "dict"])
        if depth <= 0 or kind == "scalar":
            return self.scalar()
        if kind == "list":
            return [self.value(depth - 1) for _ in range(self.random.randint(0, 4))]
        return self.mapping(depth - 1)

    def key(self):
        text = self.text(keyish=True)
        return text if text or self.empty_names else "k"

    def mapping(self, depth):
        return {self.key(): self.value(depth) for _ in range(self.random.randint(0, 4))}


def mapped(value, convert):
    """``value`` with ``convert`` applied to every string, key or value."""
    if isinstance(value, str):
        return convert(value)
    if isinstance(value, dict):
        return {mapped(k, convert): mapped(v, convert) for k, v in value.items()}
    if isinstance(value, list):
        return [mapped(v, convert) for v in value]
    return value


def toml_writes(text):
    """TOML cannot hold half of a surrogate pair: it writes U+FFFD."""
    return "".join("\ufffd" if "\ud800" <= c <= "\udfff" else c for c in text)


def key_count(value):
    if isinstance(value, dict):
        return len(value) + sum(key_count(v) for v in value.values())
    if isinstance(value, list):
        return sum(key_count(v) for v in value)
    return 0


def json_reads(text):
    """A high surrogate followed by a low one is the one character they spell."""
    return text.encode("utf-16-le", "surrogatepass").decode(
        "utf-16-le", "surrogatepass"
    )


def expected(record, name):
    if name == "toml":
        record = mapped(record, toml_writes)
    if name in ("json", "ini"):
        record = mapped(record, json_reads)
    return record


# -- the law, over generated records ------------------------------------------

RECORDS = 3000


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_the_round_trip_holds_over_generated_records(name):
    generator = Generator(
        20261008 + RECORD_FORMATS.index(name),
        nulls=name != "toml",
        empty_names=name != "ini",  # the empty name is an exception, pinned below
    )
    checked = skipped = 0
    while checked < RECORDS:
        record = generator.mapping(3)
        if name == "ini" and isinstance(record.get("record"), dict):
            skipped += 1  # an exception, pinned below
            continue
        if name == "toml" and key_count(record) != key_count(expected(record, name)):
            skipped += 1  # two keys that are one once written: pinned below
            continue
        try:
            text = dumps_record(record, name)
        except ValueError:
            skipped += 1  # a record the writer refuses
            continue
        back = loads_record(text, name)
        # TOML and INI write a mapping after the other values: the order is
        # pinned by tests of its own.
        ordered = name in ("json", "yaml")
        assert same(back, expected(record, name), ordered), (name, text)
        checked += 1
    assert checked == RECORDS and skipped < 2 * RECORDS


# -- every exception to the law, each pinned ------------------------------------


def test_json_and_ini_return_a_key_that_was_not_text_as_its_text():
    record = {1: "a", None: "b", 2.5: "d"}
    assert loads_record(dumps_record(record, "json"), "json") == {
        "1": "a",
        "null": "b",
        "2.5": "d",
    }
    assert loads_record(dumps_record(record, "ini"), "ini") == {
        "1": "a",
        "None": "b",
        "2.5": "d",
    }
    assert loads_record(dumps_record({True: 1, False: 2}, "json"), "json") == {
        "true": 1,
        "false": 2,
    }
    assert loads_record(dumps_record({True: 1}, "ini"), "ini") == {"True": 1}
    # YAML keeps the key as it was.
    for kept in (record, {True: 1, False: 2}):
        assert same(loads_record(dumps_record(kept, "yaml"), "yaml"), kept)


def test_toml_writes_two_names_that_differ_in_half_surrogates_as_one_twice():
    record = {"a\ud800": 1, "a\udc00": 2, "t": {"\ud800": 1, "\udc00": 2}}
    text = dumps_record(record, "toml")
    assert text.count('"a\\uFFFD"') == 2
    with pytest.raises(RecordFormatError) as caught:
        loads_record(text, "toml")
    assert "twice" in str(caught.value)


def test_json_and_ini_join_a_high_surrogate_and_the_low_one_after_it():
    halves = ["a" + chr(0xD83D) + chr(0xDE00), chr(0xDE00) + chr(0xD83D)]
    # The two halves are written as the escapes of one character, and read as it.
    for name in ("json", "ini"):
        back = loads_record(dumps_record({"v": halves}, name), name)
        assert back == {"v": ["a\U0001f600", chr(0xDE00) + chr(0xD83D)]}
    # The other way round is two lone surrogates, which stay two.
    assert loads_record(dumps_record({"v": halves}, "yaml"), "yaml") == {"v": halves}
    # INI cannot write one in a name at all, and says so as a ValueError.
    with pytest.raises(ValueError):
        dumps_record({"k\ud800": 1}, "ini")


def test_toml_returns_half_of_a_surrogate_pair_as_the_replacement_character():
    back = loads_record(dumps_record({"k\ud800": ["a\udfffb"]}, "toml"), "toml")
    assert back == {"k\ufffd": ["a\ufffdb"]}
    for name in ("json", "yaml"):
        record = {"k\ud800": ["a\udfffb"]}
        assert loads_record(dumps_record(record, name), name) == record
    record = {"k": ["a\udfffb"]}
    assert loads_record(dumps_record(record, "ini"), "ini") == record


def test_ini_cannot_read_the_empty_name_it_writes():
    for record in ({"": 1}, {"a": {"": 1}}, {"": {"a": 1}}):
        text = dumps_record(record, "ini")
        with pytest.raises(RecordFormatError):
            loads_record(text, "ini")
    for name in ("json", "yaml", "toml"):
        record = {"": 1, "a": {"": [2]}}
        assert loads_record(dumps_record(record, name), name) == record


def test_ini_reads_a_lone_section_named_record_as_the_top_level_values():
    record = {"record": {"a": 1}}
    assert dumps_record(record, "ini") == "[record]\na = 1\n"
    assert loads_record(dumps_record(record, "ini"), "ini") == {"a": 1}
    for name in ("json", "yaml", "toml"):
        assert loads_record(dumps_record(record, name), name) == record


def test_ini_lists_the_top_level_values_before_the_mappings():
    record = {"m": {"a": 1}, "v": 2, "n": {}}
    back = loads_record(dumps_record(record, "ini"), "ini")
    assert back == record and list(back) == ["v", "m", "n"]
    for name in ("json", "yaml"):
        assert list(loads_record(dumps_record(record, name), name)) == ["m", "v", "n"]


def test_toml_lists_the_tables_of_a_table_after_its_other_values():
    record = {"m": {"s": {"x": 1}, "a": 2}, "v": 3, "l": [{"t": {"u": 1}, "w": 2}]}
    back = loads_record(dumps_record(record, "toml"), "toml")
    assert back == record and list(back) == ["v", "l", "m"]
    assert list(back["m"]) == ["a", "s"]
    # Inside an array a table is written inline, in its own order.
    assert list(back["l"][0]) == ["t", "w"]


def test_a_tuple_comes_back_a_list_and_a_nan_comes_back_a_nan():
    for name in RECORD_FORMATS:
        back = loads_record(dumps_record({"t": (1, (2, 3))}, name), name)
        assert same(back, {"t": [1, [2, 3]]})
    for name in ("yaml", "toml"):
        back = loads_record(dumps_record({"n": math.nan, "i": -math.inf}, name), name)
        assert math.isnan(back["n"]) and back["n"] != back["n"]
        assert back["i"] == -math.inf


# -- hostile text -----------------------------------------------------------------


def verdict(text, name):
    """The dict, or the RecordFormatError, and nothing else; no marker in it."""
    try:
        return loads_record(text, name)
    except RecordFormatError as error:
        assert error.__cause__ is None and error.__context__ is None
        assert MARKER not in str(error) and MARKER not in repr(error)
        assert len(str(error)) < 200
        return error


DEPTH = 100_000

NESTED = {
    "json": '{"a": ' + "[" * DEPTH + "]" * DEPTH + "}",
    "yaml": "a: " + "[" * DEPTH + "]" * DEPTH + "\n",
    "toml": "a = " + "[" * DEPTH + "]" * DEPTH + "\n",
    "ini": "[x]\na = " + "[" * DEPTH + "]" * DEPTH + "\n",
}


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_text_nested_a_hundred_thousand_deep_is_an_error_and_not_a_crash(name):
    started = time.monotonic()
    result = verdict(NESTED[name], name)
    if isinstance(result, RecordFormatError):
        assert "nested too deeply" in str(result)
    else:
        # A parser whose recursion is in C and bounded by the stack may read it.
        assert name in ("json", "toml", "ini") and sys.version_info >= (3, 11)
    assert time.monotonic() - started < 10


def test_yaml_block_nesting_is_an_error_too():
    text = "".join("%s- \n" % (" " * i) for i in range(3000))
    assert isinstance(verdict("a:\n" + text, "yaml"), (RecordFormatError, dict))
    flow = "a: " + "{b: " * DEPTH + "1" + "}" * DEPTH + "\n"
    assert isinstance(verdict(flow, "yaml"), RecordFormatError)


def aliases(levels, fan):
    """Each level holds ``fan`` aliases to the one before: its expansion is
    ``fan ** levels`` items from a document a few kilobytes long."""
    lines = ["l0: &l0 [%s]" % ", ".join(["x"] * fan)]
    for level in range(1, levels):
        lines.append(
            "l%d: &l%d [%s]" % (level, level, ", ".join(["*l%d" % (level - 1)] * fan))
        )
    return "\n".join(lines) + "\n"


def test_an_alias_is_refused_however_few_there_are():
    """A reader that took aliases would hand back a small object that costs
    whoever walks it the whole expansion. None is read, and the line is told."""
    error = verdict("a: &a [x, y]\nb: *a\n", "yaml")
    assert isinstance(error, RecordFormatError) and error.lineno == 2
    many = "a: &a [x, y]\nb: [%s]\n" % ", ".join(["*a"] * 1000)
    assert isinstance(verdict(many, "yaml"), RecordFormatError)
    assert loads_record("a: &a [x, y]\nb: [x, y]\n", "yaml") == {
        "a": ["x", "y"],
        "b": ["x", "y"],
    }


def test_aliases_that_would_expand_to_billions_are_refused_at_the_first():
    text = aliases(levels=12, fan=10)  # 10**12 items if expanded
    assert len(text) < 2000
    tracemalloc.start()
    try:
        started = time.monotonic()
        error = verdict(text, "yaml")
        elapsed = time.monotonic() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # An expansion would take terabytes; refusing costs the first two lines.
    assert isinstance(error, RecordFormatError)
    assert peak < 2_000_000 and elapsed < 5


def test_a_chain_of_merge_keys_is_refused_before_it_can_double():
    lines = ["l0: &l0 {k0: 1}"]
    for level in range(1, 60):
        lines.append(
            "l%d: &l%d {<<: [*l%d, *l%d], k%d: 1}"
            % ((level,) * 2 + (level - 1,) * 2 + (level,))
        )
    started = time.monotonic()
    error = verdict("\n".join(lines) + "\n", "yaml")
    assert isinstance(error, RecordFormatError) and time.monotonic() - started < 5


def test_a_value_that_contains_itself_is_refused_at_any_depth():
    assert isinstance(verdict("a: &x [1, [2, *x]]\n", "yaml"), RecordFormatError)
    assert isinstance(verdict("a: &x\n  b: [*x]\n", "yaml"), RecordFormatError)


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_a_number_of_a_hundred_thousand_digits_is_read_or_refused(name):
    digits = "9" * 100_000
    text = {
        "json": '{"a": %s}' % digits,
        "yaml": "a: %s\n" % digits,
        "toml": "a = %s\n" % digits,
        "ini": "[x]\na = %s\n" % digits,
    }[name]
    started = time.monotonic()
    result = verdict(text, name)
    assert time.monotonic() - started < 10
    if isinstance(result, dict):
        # An interpreter with no limit on converting digits reads it whole.
        assert not hasattr(sys, "set_int_max_str_digits")
        value = result["a"] if name != "ini" else result["x"]["a"]
        assert value == int(digits)
    else:
        assert hasattr(sys, "set_int_max_str_digits")


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_a_float_of_a_hundred_thousand_digits_is_read_or_refused(name):
    digits = "1" * 100_000 + "." + "1" * 100_000
    text = {
        "json": '{"a": %s}' % digits,
        "yaml": "a: %s\n" % digits,
        "toml": "a = %s\n" % digits,
        "ini": "[x]\na = %s\n" % digits,
    }[name]
    result = verdict(text, name)
    assert isinstance(result, (dict, RecordFormatError))


def noise(rng, length):
    return bytes(rng.randrange(256) for _ in range(length)).decode("latin-1")


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_random_octets_decoded_as_latin_1_give_a_dict_or_a_record_error(name):
    rng = random.Random(77 + RECORD_FORMATS.index(name))
    refused = 0
    for _ in range(4000):
        result = verdict(noise(rng, rng.randrange(0, 120)), name)
        refused += isinstance(result, RecordFormatError)
    assert refused > 3000


def damaged(rng, text, name):
    """``text`` with a few random edits and the marker planted."""
    chars = list(text)
    for _ in range(rng.randint(1, 4)):
        at = rng.randrange(len(chars) + 1)
        how = rng.choice(["drop", "put", "swap", "marker", "dup"])
        if how == "drop" and chars:
            del chars[min(at, len(chars) - 1)]
        elif how == "put":
            chars.insert(at, rng.choice("{}[]:,\"'=#;%&*!-?|>\n \t\x00\ufeff\\"))
        elif how == "swap" and chars:
            chars[min(at, len(chars) - 1)] = chr(rng.randrange(0x7F))
        elif how == "marker":
            chars.insert(at, MARKER)
        elif how == "dup" and chars:
            start = min(at, len(chars) - 1)
            chars[start:start] = chars[start : start + rng.randint(1, 12)]
    return "".join(chars)


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_a_written_record_with_random_edits_gives_a_dict_or_a_record_error(name):
    rng = random.Random(991 + RECORD_FORMATS.index(name))
    generator = Generator(5 + RECORD_FORMATS.index(name), nulls=name != "toml")
    errors = 0
    for _ in range(1500):
        record = generator.mapping(2)
        try:
            text = dumps_record(record, name)
        except ValueError:
            continue
        result = verdict(damaged(rng, text, name), name)
        errors += isinstance(result, RecordFormatError)
    assert errors > 300


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_a_written_record_cut_at_every_position_is_a_dict_or_a_record_error(name):
    record = {
        "op": "BOOTREQUEST",
        "xid": 305441741,
        "note": 'caf\u00e9 \x1b "q"',
        "hops": [1, 2.5, [True]],
        "options": {"53": "DHCPDISCOVER", "sizes": [576, 1500], "a b": {"c": "d"}},
    }
    if name != "toml":
        record["gap"] = None
    text = dumps_record(record, name)
    whole = loads_record(text, name)
    assert same(whole, expected(record, name), name in ("json", "yaml"))
    for end in range(len(text)):
        result = verdict(text[:end], name)
        if isinstance(result, dict):
            if name == "json":
                # Only the line feed was cut.
                assert end == len(text) - 1 and result == whole
            else:
                # Cut between lines: what was read is part of the record.
                assert all(key in whole for key in result)
        else:
            assert end == 0 or result.format == name


@pytest.mark.parametrize("name", RECORD_FORMATS)
def test_text_with_the_marker_in_every_position_never_leaks_it(name):
    text = dumps_record({"a": {"b": [1, "x"]}, "c": 2}, name)
    for at in range(len(text) + 1):
        verdict(text[:at] + MARKER + text[at:], name)
