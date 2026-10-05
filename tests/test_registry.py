"""The dissector registry, and the contract check a dissector is held to."""

import pytest

import pktcap
from pktcap import (
    Dissected,
    DissectError,
    DissectorRegistry,
    Fragment,
    check_dissector,
    default_registry,
    register_dissector,
)


def _dhcp(data):
    """A stand-in for a protocol library's dissector."""
    if len(data) < 4:
        raise ValueError("a message is at least 4 octets")
    return Dissected({"op": data[0]}, data[4:])


# -- registering ----------------------------------------------------------


def test_a_dissector_is_found_by_the_selector_it_was_registered_under():
    registry = DissectorRegistry()
    assert registry.get("udp", 67) is None
    registry.register("udp", 67, _dhcp)
    registry.register("udp", 68, _dhcp)
    assert registry.get("udp", 67) is _dhcp and registry.get("udp", 68) is _dhcp
    assert ("udp", 67) in registry.selectors()


def test_a_selector_that_is_taken_is_an_error_unless_replacing_is_asked_for():
    registry = DissectorRegistry()
    registry.register("udp", 67, _dhcp)
    with pytest.raises(ValueError, match="already registered for udp 67"):
        registry.register("udp", 67, lambda data: Dissected(None, data))
    assert registry.get("udp", 67) is _dhcp
    other = lambda data: Dissected(None, data)  # noqa: E731
    registry.register("udp", 67, other, replace=True)
    assert registry.get("udp", 67) is other


def test_a_built_in_dissector_can_only_be_replaced_on_purpose():
    registry = DissectorRegistry()
    with pytest.raises(ValueError, match="already registered for ip 17"):
        registry.register("ip", 17, _dhcp)
    registry.register("ip", 17, _dhcp, replace=True)
    assert registry.get("ip", 17) is _dhcp
    assert DissectorRegistry().get("ip", 17) is not _dhcp


def test_unregistering_forgets_a_dissector_and_says_when_there_is_none():
    registry = DissectorRegistry()
    registry.register("udp", 67, _dhcp)
    registry.unregister("udp", 67)
    assert registry.get("udp", 67) is None
    with pytest.raises(ValueError, match="no dissector is registered for udp 67"):
        registry.unregister("udp", 67)


def test_two_registries_share_nothing():
    one, two = DissectorRegistry(), DissectorRegistry()
    one.register("udp", 67, _dhcp)
    assert two.get("udp", 67) is None
    clone = one.copy()
    assert clone.get("udp", 67) is _dhcp
    clone.unregister("udp", 67)
    clone.register("tcp", 80, _dhcp)
    assert one.get("udp", 67) is _dhcp and one.get("tcp", 80) is None


def test_the_built_ins_are_listed_and_an_empty_registry_has_none():
    selectors = DissectorRegistry().selectors()
    assert selectors == tuple(sorted(selectors))
    for selector in [
        ("linktype", 1),
        ("linktype", 276),
        ("ethertype", 0x0800),
        ("ethertype", 0x86DD),
        ("ethertype", 0x8100),
        ("ip", 6),
        ("ip", 17),
        ("ip", 44),
    ]:
        assert selector in selectors
    assert {number for kind, number in selectors if kind == "linktype"} == set(
        pktcap.LINKTYPES
    )
    assert not any(kind in ("udp", "tcp") for kind, _number in selectors)
    assert DissectorRegistry(builtins=False).selectors() == ()


def test_a_selector_may_be_of_a_kind_nobody_has_used_before():
    registry = DissectorRegistry(builtins=False)
    registry.register("dhcp-option", 43, _dhcp)
    assert registry.selectors() == (("dhcp-option", 43),)


@pytest.mark.parametrize(
    "kind, value, dissector",
    [
        (17, 67, _dhcp),
        ("", 67, _dhcp),
        ("udp", "67", _dhcp),
        ("udp", True, _dhcp),
        ("udp", 67, "not callable"),
    ],
)
def test_a_registration_of_the_wrong_shape_is_a_type_error(kind, value, dissector):
    with pytest.raises(TypeError):
        DissectorRegistry().register(kind, value, dissector)


# -- the default registry -------------------------------------------------


def test_there_is_one_default_registry_and_the_module_function_acts_on_it():
    assert default_registry() is default_registry()
    try:
        register_dissector("udp", 40067, _dhcp)
        assert default_registry().get("udp", 40067) is _dhcp
        with pytest.raises(ValueError, match="already registered"):
            register_dissector("udp", 40067, _dhcp)
        register_dissector("udp", 40067, _dhcp, replace=True)
        assert DissectorRegistry().get("udp", 40067) is None  # a new one is clean
    finally:
        default_registry().unregister("udp", 40067)


def test_importing_the_package_registers_nothing_but_the_built_ins():
    assert default_registry().selectors() == DissectorRegistry().selectors()


# -- the contract check ---------------------------------------------------


def test_a_dissector_that_keeps_the_contract_passes():
    check_dissector(_dhcp, [bytes(range(16)), b"\x01\x02\x03\x04"], rounds=500)


def test_the_check_needs_a_sample():
    with pytest.raises(ValueError, match="at least one sample"):
        check_dissector(_dhcp, [])


def _raises_key_error(data):
    return Dissected({}, data[{}["missing"] :])


def _raises_index_error(data):
    return Dissected(data[40], data[41:])


def _returns_a_tuple(data):
    return ({}, data)


def _returns_text(data):
    return Dissected({}, data.hex())


def _grows(data):
    return Dissected({}, data + b"more")


def _bad_selector(data):
    return Dissected({}, data, (("udp", "67"),))


def _bad_fragment(data):
    return Dissected({}, data, (), Fragment(1, -8, False))


@pytest.mark.parametrize(
    "dissector, problem",
    [
        (_raises_key_error, "raised KeyError, not ValueError"),
        (_raises_index_error, "raised IndexError, not ValueError"),
        (_returns_a_tuple, "returned tuple, not Dissected"),
        (_returns_text, "the payload is str, not bytes"),
        (_grows, "longer than the octets given"),
        (_bad_selector, "not a .kind, number. pair"),
        (_bad_fragment, "offset of zero or more"),
    ],
)
def test_a_dissector_that_breaks_the_contract_fails_the_check(dissector, problem):
    with pytest.raises(AssertionError, match=problem):
        check_dissector(dissector, [bytes(8)], rounds=50)


def test_the_check_is_the_same_run_for_the_same_seed():
    seen = [[], []]
    for run in seen:

        def record(data, run=run):
            run.append(data)
            return Dissected(None, data)

        check_dissector(record, [bytes(range(32))], rounds=100, seed=7)
    assert seen[0] == seen[1] and len(seen[0]) == 101


def test_dissect_error_is_a_value_error_of_this_package():
    assert issubclass(DissectError, ValueError)
    assert issubclass(DissectError, pktcap.PktcapError)
