"""The capture-filter grammar: clauses, negation, conjunction, and nothing
about what a key means."""

import random

import pytest

from pktcap import (
    CaptureFilterError,
    FilterClause,
    PktcapError,
    compile_capture_filter,
    parse_capture_filter,
)

C = FilterClause


# -- the grammar ----------------------------------------------------------


@pytest.mark.parametrize(
    "text, clauses",
    [
        # The shapes a TFTP capture filter takes.
        ("op=RRQ", [C("op", "RRQ")]),
        ("op=rrq,wrq", [C("op", "rrq,wrq")]),
        ("host=10.0.0.0/8", [C("host", "10.0.0.0/8")]),
        ("src=10.0.0.5:2000", [C("src", "10.0.0.5:2000")]),
        ("src=:2000 and dst=:69", [C("src", ":2000"), C("dst", ":69")]),
        ("src=[::1]:69", [C("src", "[::1]:69")]),
        ("file=*.efi", [C("file", "*.efi")]),
        ("op=RRQ and file=boot/*", [C("op", "RRQ"), C("file", "boot/*")]),
        ("op!=RRQ", [C("op", "RRQ", True)]),
        ("session!=c1", [C("session", "c1", True)]),
        ("op=ERROR and code=1,2", [C("op", "ERROR"), C("code", "1,2")]),
        # The shapes a DHCP capture filter takes.
        ("op=BOOTREQUEST", [C("op", "BOOTREQUEST")]),
        (
            "msg_type=DHCPDISCOVER and src_port=68",
            [C("msg_type", "DHCPDISCOVER"), C("src_port", "68")],
        ),
        ("xid=0x1234ABCD", [C("xid", "0x1234ABCD")]),
        ("client_id=01:00:11:22:33:44:55", [C("client_id", "01:00:11:22:33:44:55")]),
        ("chaddr=68-F7-D8-E5-1E-84", [C("chaddr", "68-F7-D8-E5-1E-84")]),
        ("interface=eth-test", [C("interface", "eth-test")]),
        (
            "option.DHCP_MESSAGE_TYPE=DHCPDISCOVER",
            [C("option.DHCP_MESSAGE_TYPE", "DHCPDISCOVER")],
        ),
        ("option.53=DHCPDISCOVER", [C("option.53", "DHCPDISCOVER")]),
    ],
)
def test_an_expression_parses_to_its_clauses(text, clauses):
    assert parse_capture_filter(text) == tuple(clauses)


@pytest.mark.parametrize("text", [None, "", "   ", "\t\n"])
def test_no_expression_is_no_clause(text):
    assert parse_capture_filter(text) == ()


@pytest.mark.parametrize("joiner", ["and", "AND", "And", "  and\t"])
def test_clauses_are_joined_by_and_in_any_case(joiner):
    """An upper-case AND read as part of the value before it would compile to
    one clause that matches nothing: the same output as a quiet network."""
    assert parse_capture_filter("src=192.0.2.55 %s type=x" % joiner) == (
        C("src", "192.0.2.55"),
        C("type", "x"),
    )


def test_space_around_a_clause_and_its_operator_is_not_part_of_it():
    assert parse_capture_filter("  op = RRQ   and   file != a b  ") == (
        C("op", "RRQ"),
        C("file", "a b", True),
    )


def test_a_key_keeps_its_case_and_a_value_keeps_everything_after_the_operator():
    (clause,) = parse_capture_filter("option.Vendor_Class=a=b!=c")
    assert clause == C("option.Vendor_Class", "a=b!=c")


def test_values_reads_a_comma_as_any_of_and_value_stays_whole():
    (clause,) = parse_capture_filter("op= RRQ , WRQ,,ERROR ")
    assert clause.value == "RRQ , WRQ,,ERROR"
    assert clause.values == ("RRQ", "WRQ", "ERROR")
    assert C("key", ",").values == ()


def test_a_clause_writes_itself_back():
    assert str(C("op", "RRQ")) == "op=RRQ"
    assert str(C("op", "RRQ", True)) == "op!=RRQ"
    assert repr(C("op", "RRQ")) == "FilterClause(key='op', value='RRQ', negated=False)"


def test_the_canonical_text_parses_back_to_the_same_clauses():
    random.seed(20261005)
    keys = ["op", "host", "src_port", "option.53", "file", "a-b", "X_1"]
    alphabet = "abcXYZ019.:/*,[]-_=!"
    for _ in range(2000):
        clauses = tuple(
            C(
                random.choice(keys),
                "".join(random.choice(alphabet) for _ in range(random.randint(1, 12))),
                random.random() < 0.3,
            )
            for _ in range(random.randint(1, 5))
        )
        text = " and ".join(str(clause) for clause in clauses)
        assert parse_capture_filter(text) == clauses, text


# -- what is refused ------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "op",
        "=RRQ",
        "op=",
        "op= ",
        "!=RRQ",
        "two words=1",
        "op=RRQ and",
        "and op=RRQ",
        "op=RRQ and and file=x",
        "file=rock and roll",
        "op=RRQ & file=x and",
        "colour@=red",
    ],
)
def test_a_clause_that_is_not_key_value_is_refused(text):
    with pytest.raises(CaptureFilterError, match="expected key=value"):
        parse_capture_filter(text)


@pytest.mark.parametrize("joiner", ["or", "OR", "Or"])
def test_or_is_refused_by_name_in_any_case(joiner):
    with pytest.raises(CaptureFilterError, match="'and' only"):
        parse_capture_filter("type=a %s type=b" % joiner)
    with pytest.raises(CaptureFilterError, match="'and' only"):
        parse_capture_filter("%s=1" % joiner)


def test_a_word_that_contains_or_is_not_an_or():
    assert parse_capture_filter("vendor=oracle and port=67") == (
        C("vendor", "oracle"),
        C("port", "67"),
    )


def test_the_error_is_a_value_error_of_this_package():
    with pytest.raises(CaptureFilterError) as caught:
        parse_capture_filter("op")
    assert isinstance(caught.value, PktcapError) and isinstance(
        caught.value, ValueError
    )


def test_an_expression_has_a_longest_length():
    clause = "key=value"
    longest = " and ".join([clause] * 292)  # 4,083 characters
    assert len(parse_capture_filter(longest)) == 292
    with pytest.raises(CaptureFilterError, match="over the limit of 4096"):
        parse_capture_filter("k=" + "v" * 4095)


@pytest.mark.parametrize("text", [5, b"op=RRQ", ["op=RRQ"]])
def test_an_expression_that_is_not_text_is_a_type_error(text):
    with pytest.raises(TypeError):
        parse_capture_filter(text)


# -- compiling ------------------------------------------------------------


def _build(clause):
    """A stand-in for a protocol library: items are dicts."""
    if clause.key not in ("op", "port", "tag"):
        raise ValueError("unknown filter key %r" % clause.key)
    if clause.key == "port":
        wanted = {int(value) for value in clause.values}
        return lambda item: item["port"] in wanted
    wanted_text = set(clause.values)
    return lambda item: item[clause.key] in wanted_text


ITEM = {"op": "RRQ", "port": 69, "tag": "a"}


@pytest.mark.parametrize(
    "text, matches",
    [
        ("op=RRQ", True),
        ("op=WRQ", False),
        ("op=RRQ,WRQ", True),
        ("op!=RRQ", False),
        ("op!=WRQ", True),
        ("op=RRQ and port=69", True),
        ("op=RRQ and port=70", False),
        ("op=RRQ and port!=70 and tag=a", True),
        ("op=RRQ and port!=69 and tag=a", False),
        ("", True),
        (None, True),
    ],
)
def test_the_predicate_is_every_clause_each_inverted_where_asked(text, matches):
    assert compile_capture_filter(text, _build)(ITEM) is matches


def test_build_is_called_once_per_clause_when_compiling_and_never_after():
    seen = []

    def build(clause):
        seen.append(clause)
        return lambda item: True

    predicate = compile_capture_filter("a=1 and b!=2", build)
    assert seen == [C("a", "1"), C("b", "2", True)]
    for _ in range(3):
        predicate(object())
    assert len(seen) == 2


def test_a_key_or_value_the_builder_refuses_is_one_error_at_compile_time():
    with pytest.raises(
        CaptureFilterError, match="colour=red: unknown filter key"
    ) as caught:
        compile_capture_filter("op=RRQ and colour=red", _build)
    assert isinstance(caught.value.__cause__, ValueError)
    with pytest.raises(CaptureFilterError, match="port=x: invalid literal"):
        compile_capture_filter("port=x", _build)


def test_a_filter_error_from_the_builder_is_not_wrapped_twice():
    def build(clause):
        raise CaptureFilterError("my own message")

    with pytest.raises(CaptureFilterError, match="^my own message$"):
        compile_capture_filter("a=1", build)


def test_a_bug_in_the_builder_is_not_dressed_as_a_bad_filter():
    def build(clause):
        raise KeyError("oops")

    with pytest.raises(KeyError):
        compile_capture_filter("a=1", build)
    with pytest.raises(TypeError, match="must return a callable"):
        compile_capture_filter("a=1", lambda clause: True)


def test_a_test_that_returns_something_truthy_counts_as_true():
    predicate = compile_capture_filter("a=1 and b!=2", lambda clause: lambda item: item)
    assert predicate([]) is False  # a=1 fails
    assert predicate([0]) is False  # b!=2 is inverted
    assert compile_capture_filter("a=1", lambda clause: lambda item: item)([0]) is True
