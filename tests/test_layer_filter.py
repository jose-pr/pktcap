"""Layers and filter keys in a registry: ``LAYER.KEY`` and ``LAYER.FIELD``.

Every layer, dissector and key here is written by the test and registered into
a registry of its own, so nothing is shared with the process-wide one.
"""

import enum
import logging
from typing import Any, Dict, NamedTuple, Optional, Tuple

import pytest

import captures as build
from pktcap import (
    FRAME_FILTER_KEYS,
    CaptureFilterError,
    CapturedFrame,
    Dissected,
    DissectorRegistry,
    FilterClause,
    FrameDissector,
    compile_capture_filter,
    default_registry,
    frame_filter,
    frame_filter_for,
    frame_filter_keys,
)


class Mode(enum.Enum):
    BOOT = 1
    LEASE = "lease"


class DemoLayer(NamedTuple):
    opcode: int
    name: str
    flag: bool
    raw: bytes
    mode: Mode
    peer: str
    message: Dict[str, Any]
    items: Tuple[Any, ...]
    note: Optional[int]
    ratio: float


FIRST = DemoLayer(
    1,
    "boot.efi",
    True,
    b"\xaa\xbb\xcc",
    Mode.BOOT,
    "10.0.0.5",
    {"giaddr": "10.9.9.9", "options": {"53": 1, "Host": "pc1"}},
    (1, 2, ("nested", 9), {"deep": 4}),
    None,
    1.5,
)
SECOND = DemoLayer(
    2, "Other", False, b"", Mode.LEASE, "::ffff:10.0.0.7", {}, (), 7, 2.0
)


def registry_for(layer, records, *, keys=None, name=None):
    """A registry whose dissector for UDP 9999 makes ``records[payload[0]]``."""
    registry = DissectorRegistry()
    registry.register_layer(layer, name=name, keys=keys)
    registry.register("udp", 9999, lambda data: Dissected(records[data[0]], data[1:]))
    return registry


def frames(registry, count=1):
    dissector = FrameDissector(registry)
    return [
        dissector.dissect(
            CapturedFrame(
                0.0,
                1,
                build.ethernet(
                    build.ipv4(
                        "10.0.0.5", "192.0.2.1", build.udp(50000, 9999, bytes([i]))
                    )
                ),
            )
        )
        for i in range(count)
    ]


def selects(registry, text, item):
    return compile_capture_filter(text, frame_filter_for(registry))(item)


DEMO = registry_for(DemoLayer, [FIRST, SECOND])
ONE, TWO = frames(DEMO, 2)


# -- the done-when of the plan ----------------------------------------------


def test_a_layers_field_and_a_builtin_fields_are_keys_of_one_filter():
    text = "demo.opcode=0x01 and ipv4.ttl=64 and udp.destination_port=9999"
    assert selects(DEMO, text, ONE) is True
    assert selects(DEMO, text, TWO) is False


def test_without_the_registry_the_layer_is_an_unknown_key_naming_it():
    with pytest.raises(CaptureFilterError, match="demo.opcode=1: unknown filter key"):
        compile_capture_filter("demo.opcode=1", frame_filter)
    assert compile_capture_filter("ipv4.ttl=64", frame_filter)(ONE) is True


def test_a_value_the_field_can_never_take_is_refused_when_compiled():
    with pytest.raises(
        CaptureFilterError, match="ipv4.ttl takes an integer, not 'abc'"
    ):
        compile_capture_filter("ipv4.ttl=abc", frame_filter)


def test_the_keys_that_compile_follow_the_registry():
    plain = frame_filter_keys()
    assert "ipv4.ttl" in plain and "udp.source_port" in plain
    assert set(FRAME_FILTER_KEYS) <= set(plain)
    assert not [key for key in plain if key.startswith("demo.")]
    assert list(plain) == sorted(plain)
    assert "demo.opcode" in frame_filter_keys(DEMO)
    assert frame_filter_keys(None) == plain
    with pytest.raises(TypeError):
        frame_filter_keys(object())  # type: ignore[arg-type]


def test_no_listed_key_is_refused_as_unknown():
    registry = registry_for(DemoLayer, [FIRST], keys={"op": lambda c: lambda l: True})
    for key in frame_filter_keys(registry):
        try:
            compile_capture_filter("%s=1" % key, frame_filter_for(registry))
        except CaptureFilterError as exc:
            # A value of the wrong kind is refused; the key itself is known.
            assert not any(
                word in str(exc)
                for word in ("unknown filter key", "no key or field", "names a layer")
            ), key


def test_the_process_wide_registry_is_not_touched():
    before = default_registry().selectors()
    registry_for(DemoLayer, [FIRST])
    assert default_registry().selectors() == before
    assert default_registry().layers() == {}


# -- each row of the comparison table ---------------------------------------


@pytest.mark.parametrize(
    "text, first, second",
    [
        # an integer, in any base; a bool is not one
        ("demo.opcode=1", True, False),
        ("demo.opcode=01", True, False),
        ("demo.opcode=0x1", True, False),
        ("demo.opcode=0X02", False, True),
        ("demo.opcode=0o2", False, True),
        ("demo.opcode=0b10", False, True),
        ("demo.opcode=1,2", True, True),
        ("demo.opcode=3,4", False, False),
        ("demo.opcode!=1", False, True),
        ("demo.opcode=010", False, False),
        # a bool
        ("demo.flag=yes", True, False),
        ("demo.flag=TRUE", True, False),
        ("demo.flag=1", True, False),
        ("demo.flag=off", False, True),
        ("demo.flag=0", False, True),
        # an enumeration: the name in any case, or its value by the same rules
        ("demo.mode=boot", True, False),
        ("demo.mode=LEASE", False, True),
        ("demo.mode=1", True, False),
        ("demo.mode=Lease", False, True),
        ("demo.mode=nosuch", False, False),
        # text: equal ignoring case, or an address inside a network
        ("demo.name=BOOT.EFI", True, False),
        ("demo.name=other", False, True),
        ("demo.name=boot.efi,other", True, True),
        ("demo.peer=10.0.0.0/8", True, True),
        ("demo.peer=10.0.0.5", True, False),
        ("demo.peer=192.0.2.0/24", False, False),
        ("demo.peer=::ffff:0:0/96", False, False),
        # octets, with the separators of a MAC address or a hex dump
        ("demo.raw=aabbcc", True, False),
        ("demo.raw=AA:BB:CC", True, False),
        ("demo.raw=aa-bb-cc", True, False),
        ("demo.raw=aabb.cc", True, False),
        ("demo.raw=aabb.cc00", False, False),
        ("demo.raw=aabbcc,", True, False),
        # a mapping is read by path, exact or ignoring case
        ("demo.message.giaddr=10.9.9.0/24", True, False),
        ("demo.message.GIADDR=10.9.9.9", True, False),
        ("demo.message.options.53=1", True, False),
        ("demo.message.options.host=PC1", True, False),
        ("demo.message.options.host=pc2", False, False),
        ("demo.message.nosuch=1", False, False),
        ("demo.message=1", False, False),
        # a list: an index, or any of its plain items
        ("demo.items=1", True, False),
        ("demo.items=3", False, False),
        ("demo.items.1=2", True, False),
        ("demo.items.0=2", False, False),
        ("demo.items.9=1", False, False),
        ("demo.items.x=1", False, False),
        ("demo.items.2.1=9", True, False),
        ("demo.items.3.deep=4", True, False),
        ("demo.items=9", False, False),
        ("demo.items=4", False, False),
        # nothing never matches; the rest by its text
        ("demo.note=7", False, True),
        ("demo.note=0", False, False),
        ("demo.note!=7", True, False),
        ("demo.ratio=1.5", True, False),
        ("demo.ratio=2.0", False, True),
        ("DEMO.Opcode=1", True, False),
    ],
)
def test_a_field_is_compared_by_the_type_of_its_value(text, first, second):
    assert selects(DEMO, text, ONE) is first
    assert selects(DEMO, text, TWO) is second


def test_a_frame_without_the_layer_fails_the_clause_so_its_negation_holds():
    plain = frames(DEMO)[0]._replace(layers=(), payloads=())
    assert selects(DEMO, "demo.opcode=1", plain) is False
    assert selects(DEMO, "demo.opcode!=1", plain) is True


def test_the_clause_holds_when_any_layer_of_the_class_passes():
    class Tag(NamedTuple):
        number: int

    registry = DissectorRegistry()
    registry.register_layer(Tag)
    two = frames(DEMO)[0]._replace(layers=(Tag(1), Tag(2)), payloads=(b"", b""))
    assert selects(registry, "tag.number=2", two) and selects(
        registry, "tag.number=1", two
    )
    assert not selects(registry, "tag.number=3", two)


# -- what is refused when the filter is compiled ----------------------------


@pytest.mark.parametrize(
    "text, problem",
    [
        ("demo.nosuch=1", "demo has no key or field 'nosuch' .*opcode"),
        ("nosuch.opcode=1", "unknown filter key 'nosuch.opcode'"),
        ("demo=1", "demo names a layer: write demo.KEY, one of .*opcode"),
        ("demo..opcode=1", "empty segment"),
        (".opcode=1", "empty segment"),
        ("ipv4.nosuch=1", "ipv4 has no key or field 'nosuch' .*ttl"),
        ("ipv4=1", "ipv4 names a layer"),
        ("ipv4.ttl=abc", "ipv4.ttl takes an integer, not 'abc'"),
        ("ipv4.ttl=64,x", "ipv4.ttl takes an integer, not 'x'"),
        ("ipv4.ttl=-1", "takes an integer"),
        ("ipv4.ttl=1_0", "takes an integer"),
        ("ipv4.ttl=0x", "takes an integer"),
        ("ipv4.ttl=٣", "takes an integer"),
        ("ipv4.dont_fragment=maybe", "takes yes or no"),
        ("tcp.options=xyz", "tcp.options takes hexadecimal octets, not 'xyz'"),
        ("tcp.options=abc", "takes hexadecimal octets"),
        ("demo.note=abc", "demo.note takes an integer, not 'abc'"),
        ("demo.opcode=", "expected key=value"),
        ("demo.opcode=,", "demo.opcode has no value"),
        ("a.b.c.d.e.f.g.h.i=1", "has 9 segments; a key has at most 8"),
    ],
)
def test_a_wrong_key_or_a_value_that_can_never_match_is_refused_at_compile(
    text, problem
):
    with pytest.raises(CaptureFilterError, match=problem):
        compile_capture_filter(text, frame_filter_for(DEMO))


def test_a_value_is_refused_by_the_type_the_hints_say_even_when_optional():
    with pytest.raises(CaptureFilterError, match="takes an integer"):
        selects(DEMO, "demo.note=abc", ONE)
    assert selects(DEMO, "demo.note=7", TWO) is True


def test_hints_that_do_not_resolve_refuse_nothing():
    class Loose(NamedTuple):
        number: "NoSuchName"  # noqa: F821

    registry = registry_for(Loose, [Loose(3)])
    (item,) = frames(registry)
    assert selects(registry, "loose.number=3", item) is True
    assert selects(registry, "loose.number=abc", item) is False


def test_a_union_of_two_types_refuses_nothing():
    class Either(NamedTuple):
        value: "int | str"

    registry = registry_for(Either, [Either("abc")])
    (item,) = frames(registry)
    assert selects(registry, "either.value=abc", item) is True


def test_a_key_of_nine_segments_is_refused_and_one_of_eight_is_read():
    deep = {"b": {"c": {"d": {"e": {"f": 5}}}}}

    class Nest(NamedTuple):
        a: Dict[str, Any]

    registry = registry_for(Nest, [Nest(deep)])
    (item,) = frames(registry)
    assert selects(registry, "nest.a.b.c.d.e.f=5", item) is True  # 7 segments
    assert selects(registry, "nest.a.b.c.d.e.f.g=5", item) is False  # 8
    with pytest.raises(CaptureFilterError, match="9 segments"):
        selects(registry, "nest.a.b.c.d.e.f.g.h=5", item)


def test_only_the_first_1024_items_of_a_list_are_looked_at():
    class Big(NamedTuple):
        items: Tuple[int, ...]

    registry = registry_for(Big, [Big(tuple(range(1024)) + (5000,))])
    (item,) = frames(registry)
    assert selects(registry, "big.items=1023", item) is True
    assert selects(registry, "big.items=5000", item) is False
    assert selects(registry, "big.items.1024=5000", item) is True  # by index


def test_only_the_first_1024_keys_of_a_mapping_are_searched_ignoring_case():
    class Wide(NamedTuple):
        table: Dict[str, int]

    table = {"k%d" % i: i for i in range(1024)}
    table["Zed"] = 1
    registry = registry_for(Wide, [Wide(table)])
    (item,) = frames(registry)
    assert selects(registry, "wide.table.k5=5", item) is True
    assert selects(registry, "wide.table.K5=5", item) is True
    assert selects(registry, "wide.table.Zed=1", item) is True  # exact
    assert selects(registry, "wide.table.zed=1", item) is False  # past the scan


def test_a_number_text_over_its_bound_is_not_a_number():
    huge = "9" * 65
    with pytest.raises(CaptureFilterError, match="demo.opcode takes an integer"):
        selects(DEMO, "demo.opcode=%s" % huge, ONE)
    assert selects(DEMO, "demo.opcode=%s" % ("9" * 64), ONE) is False
    assert selects(DEMO, "demo.ratio=%s" % huge, ONE) is False  # not declared int


def test_a_long_text_in_a_field_is_not_read_as_an_address():
    class Wide(NamedTuple):
        peer: str

    short, long = "::ffff:10.0.0.5%" + "x" * 8, "::ffff:10.0.0.5%" + "x" * 60
    registry = registry_for(Wide, [Wide(short), Wide(long)])
    first, second = frames(registry, 2)
    assert selects(registry, "wide.peer=10.0.0.0/8", first) is True
    assert len(long) > 64
    assert selects(registry, "wide.peer=10.0.0.0/8", second) is False


def test_an_error_lists_at_most_32_names_of_a_layer():
    fields = ["field%02d" % i for i in range(40)]
    Wide = NamedTuple("Wide", [(name, int) for name in fields])
    registry = registry_for(Wide, [Wide(*range(40))])
    with pytest.raises(CaptureFilterError) as caught:
        selects(registry, "wide.nosuch=1", frames(registry)[0])
    assert "field31" in str(caught.value) and "field32" not in str(caught.value)
    assert str(caught.value).endswith(", ...)")


# -- a library's own keys ----------------------------------------------------


def test_a_registered_key_answers_by_layer_and_bare():
    seen = []

    def builder(clause):
        seen.append(clause)
        return lambda layer: layer.opcode == int(clause.value)

    registry = registry_for(DemoLayer, [FIRST, SECOND], keys={"code": builder})
    one, two = frames(registry, 2)
    assert selects(registry, "demo.code=1", one) and not selects(
        registry, "demo.code=1", two
    )
    assert selects(registry, "code=2", two) and selects(registry, "code!=2", one)
    assert [c.key for c in seen] == ["code", "code", "code", "code"]
    assert "code" in frame_filter_keys(registry)
    assert "demo.code" in frame_filter_keys(registry)


def test_the_builder_gets_the_key_without_the_layer_lower_cased_to_its_first_dot():
    seen = []
    registry = registry_for(
        DemoLayer,
        [FIRST],
        keys={"option": lambda clause: (seen.append(clause), lambda layer: True)[1]},
    )
    for text in ("Demo.OPTION.Host_Name=a", "option.HOST_NAME=a", "DEMO.option=b"):
        compile_capture_filter(text, frame_filter_for(registry))
    assert [(c.key, c.value, c.negated) for c in seen] == [
        ("option.Host_Name", "a", False),
        ("option.HOST_NAME", "a", False),
        ("option", "b", False),
    ]
    compile_capture_filter("demo.option!=a", frame_filter_for(registry))
    assert seen[-1].negated is True


def test_a_registered_key_named_like_a_field_replaces_the_rule_for_that_field():
    registry = registry_for(
        DemoLayer,
        [FIRST],
        keys={
            "opcode": lambda clause: lambda layer: layer.opcode + 100
            == int(clause.value)
        },
    )
    (item,) = frames(registry)
    assert selects(registry, "demo.opcode=101", item) is True
    assert selects(registry, "demo.opcode=1", item) is False


def test_a_builtin_key_always_wins_the_bare_name():
    registry = registry_for(
        DemoLayer,
        [FIRST],
        keys={
            "port": lambda clause: lambda layer: False,
            "src": lambda c: lambda l: False,
        },
    )
    (item,) = frames(registry)
    assert selects(registry, "port=9999", item) is True
    assert selects(registry, "src=10.0.0.5", item) is True
    assert selects(registry, "demo.port=1", item) is False  # reached through the layer
    assert "port" in frame_filter_keys(registry) and "demo.port" in frame_filter_keys(
        registry
    )
    with pytest.raises(CaptureFilterError, match="unknown filter key 'port.x'"):
        selects(registry, "port.x=1", item)


def test_a_layer_named_like_a_builtin_key_is_no_conflict():
    class Host(NamedTuple):
        address: str

    registry = registry_for(Host, [Host("10.0.0.5")])
    (item,) = frames(registry)
    assert selects(registry, "host.address=10.0.0.5", item) is True
    assert selects(registry, "host=10.0.0.5", item) is True  # the key, as ever
    assert selects(registry, "host=10.0.0.6", item) is False


def two_layers(order=(0, 1)):
    class OneLayer(NamedTuple):
        value: int

    class TwoLayer(NamedTuple):
        value: int

    registry = DissectorRegistry()
    pairs = [
        (
            OneLayer,
            {"op": lambda clause: lambda layer: layer.value == int(clause.value)},
        ),
        (
            TwoLayer,
            {"op": lambda clause: lambda layer: layer.value == int(clause.value)},
        ),
    ]
    for index in order:
        layer, keys = pairs[index]
        registry.register_layer(layer, keys=keys)
    return registry


@pytest.mark.parametrize("order", [(0, 1), (1, 0)])
def test_a_bare_key_two_layers_have_is_ambiguous_whatever_the_order(order):
    registry = two_layers(order)
    with pytest.raises(CaptureFilterError) as caught:
        compile_capture_filter("op=1", frame_filter_for(registry))
    assert "ambiguous: write one.op or two.op" in str(caught.value)
    compile_capture_filter("one.op=1 and two.op=2", frame_filter_for(registry))
    keys = frame_filter_keys(registry)
    assert "op" not in keys and "one.op" in keys and "two.op" in keys


def test_an_unknown_key_lists_what_there_is_and_stops_at_32_names():
    registry = registry_for(
        DemoLayer,
        [FIRST],
        keys={"key%02d" % i: (lambda c: lambda l: True) for i in range(40)},
    )
    with pytest.raises(CaptureFilterError) as caught:
        compile_capture_filter("colour=red", frame_filter_for(registry))
    text = str(caught.value)
    assert text.startswith("colour=red: unknown filter key 'colour' (known: src, dst")
    assert "key00" in text and "key22" in text and "key23" not in text
    assert text.endswith(", ...)")
    short = registry_for(DemoLayer, [FIRST], keys={"only": lambda c: lambda l: True})
    with pytest.raises(CaptureFilterError) as caught:
        compile_capture_filter("colour=red", frame_filter_for(short))
    assert "only; layers: demo, ethernet" in str(caught.value)
    assert "..." not in str(caught.value)


def test_a_builder_that_refuses_a_value_is_an_error_naming_the_clause():
    registry = registry_for(
        DemoLayer,
        [FIRST],
        keys={"op": lambda clause: (_ for _ in ()).throw(ValueError("no such op"))},
    )
    with pytest.raises(CaptureFilterError, match="demo.op=x: no such op"):
        selects(registry, "demo.op=x", frames(registry)[0])


def test_a_builder_that_returns_something_not_callable_is_a_type_error():
    registry = registry_for(DemoLayer, [FIRST], keys={"op": lambda clause: 5})
    with pytest.raises(TypeError, match="demo.op"):
        compile_capture_filter("demo.op=1", frame_filter_for(registry))


def test_a_registered_test_that_raises_is_false_for_that_layer_and_logged_once(caplog):
    def explode(clause):
        def test(layer):
            raise RuntimeError("defect")

        return test

    registry = registry_for(
        DemoLayer, [FIRST], keys={"k%d" % i: explode for i in range(10)}
    )
    (item,) = frames(registry)
    build_ = frame_filter_for(registry)
    with caplog.at_level(logging.WARNING, logger="pktcap"):
        for _ in range(2):
            for i in range(10):
                assert compile_capture_filter("k%d=1" % i, build_)(item) is False
                assert compile_capture_filter("k%d!=1" % i, build_)(item) is True
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(messages) == 8
    assert all("demo.k" in m and "RuntimeError" in m for m in messages)
    assert len(set(messages)) == 8


def test_frame_filter_for_takes_a_registry():
    with pytest.raises(TypeError):
        frame_filter_for(None)  # type: ignore[arg-type]
    assert callable(frame_filter_for(DissectorRegistry()))
    build_ = frame_filter_for(DissectorRegistry())
    assert callable(build_(FilterClause("port", "9999")))


def test_a_layer_class_without_fields_offers_its_registered_keys_only():
    class Plain(dict):  # type: ignore[type-arg]
        pass

    registry = DissectorRegistry()
    registry.register_layer(
        Plain, name="plain", keys={"size": lambda c: lambda l: len(l) == int(c.value)}
    )
    registry.register("udp", 9999, lambda data: Dissected(Plain(a=1), data))
    (item,) = frames(registry)
    assert selects(registry, "plain.size=1", item) is True
    with pytest.raises(
        CaptureFilterError, match="plain has no key or field 'a' .*size"
    ):
        selects(registry, "plain.a=1", item)


def test_the_frame_filter_itself_is_unchanged_for_its_nine_keys():
    assert compile_capture_filter("port=9999 and proto=udp", frame_filter)(ONE)
