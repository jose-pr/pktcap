"""The value types and the exceptions: what a caller may rely on in each."""

import copy
import pickle

import pytest

import pktcap
from pktcap import (
    CapturedDatagram,
    CapturedFrame,
    CaptureFilterError,
    CaptureFormatError,
    DecodeStats,
    FilterClause,
    LiveCaptureError,
    PktcapError,
    ReplayResult,
    UnsupportedFormatError,
)

VALUES = [
    CapturedFrame(1.5, 101, b"\x45\x00"),
    CapturedDatagram(1.5, ("10.0.0.5", 68), ("10.0.0.1", 67), b"payload"),
    CapturedDatagram(1.5, ("::1", 1), ("::1", 2), b"", fragmented=True),
    DecodeStats(1, 2, 3, 4, 5, 6, 7, 8),
    FilterClause("op", "RRQ,WRQ", True),
    ReplayResult(3, 1),
]


@pytest.mark.parametrize("value", VALUES, ids=lambda v: type(v).__name__)
def test_a_value_cannot_be_changed(value):
    field = value._fields[0]
    with pytest.raises(AttributeError):
        setattr(value, field, None)
    changed = value._replace(**{field: getattr(value, field)})
    assert changed == value and changed is not value


@pytest.mark.parametrize("value", VALUES, ids=lambda v: type(v).__name__)
def test_equal_values_hash_equal_and_copy_and_pickle_as_themselves(value):
    twin = type(value)(*value)
    assert twin == value and hash(twin) == hash(value)
    assert len({value, twin}) == 1
    for clone in (
        copy.copy(value),
        copy.deepcopy(value),
        pickle.loads(pickle.dumps(value)),
    ):
        assert clone == value and type(clone) is type(value)


@pytest.mark.parametrize("value", VALUES, ids=lambda v: type(v).__name__)
def test_the_repr_is_the_call_that_makes_the_value(value):
    assert repr(value).startswith(type(value).__name__ + "(")
    assert eval(repr(value), vars(pktcap)) == value


@pytest.mark.parametrize("value", VALUES, ids=lambda v: type(v).__name__)
def test_a_value_neither_equals_nor_fails_against_something_else(value):
    assert value != object() and value != "text" and value is not None
    assert not (value == 5)


def test_the_defaults_of_a_datagram_are_a_whole_datagram():
    datagram = CapturedDatagram(0.0, ("10.0.0.5", 1), ("10.0.0.1", 2), b"x")
    assert (datagram.fragmented, datagram.truncated) == (False, False)


# -- the exceptions -------------------------------------------------------

BUILTIN = {
    CaptureFormatError: ValueError,
    CaptureFilterError: ValueError,
    UnsupportedFormatError: ValueError,
    LiveCaptureError: OSError,
}


def test_there_is_one_base_and_every_other_exception_descends_from_it():
    exported = {
        obj
        for obj in (getattr(pktcap, name) for name in pktcap.__all__)
        if isinstance(obj, type) and issubclass(obj, BaseException)
    }
    assert exported == set(BUILTIN) | {PktcapError}
    assert PktcapError.__bases__ == (Exception,)
    for error in BUILTIN:
        assert issubclass(error, PktcapError)


@pytest.mark.parametrize("error", sorted(BUILTIN, key=lambda e: e.__name__))
def test_each_exception_is_also_the_builtin_a_caller_already_catches(error):
    assert issubclass(error, BUILTIN[error])
    assert error.__name__.endswith("Error")
    assert error.__module__ == "pktcap._exceptions"


def test_a_callers_mistake_is_not_a_package_error():
    assert not issubclass(ValueError, PktcapError)
    with pytest.raises(TypeError) as caught:
        pktcap.read_frames(None)
    assert not isinstance(caught.value, PktcapError)


def test_a_format_error_keeps_its_offset_through_a_pickle():
    error = CaptureFormatError("the capture ends inside a block", offset=24)
    assert str(error) == "the capture ends inside a block (at octet 24)"
    clone = pickle.loads(pickle.dumps(error))
    assert type(clone) is CaptureFormatError and clone.offset == 24
    assert str(clone) == str(error)
    assert CaptureFormatError("no offset known").offset is None
