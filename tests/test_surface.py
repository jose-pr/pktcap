"""The public surface: exactly what ``pktcap.__all__`` exports.

A name added, removed or renamed has to change this list in the same commit,
so the surface never moves by accident.
"""

import inspect
from importlib.metadata import version

import pktcap

EXPECTED = [
    "CaptureFilterError",
    "CaptureFormatError",
    "CaptureSource",
    "CaptureWriter",
    "CapturedDatagram",
    "CapturedFrame",
    "DecodeStats",
    "FilterClause",
    "FrameDecoder",
    "LINKTYPES",
    "OUTPUT_FORMATS",
    "PcapWriter",
    "PktcapError",
    "RECORD_FORMATS",
    "ReplayResult",
    "ReplaySource",
    "UnsupportedFormatError",
    "compile_capture_filter",
    "datagram_record",
    "dumps_record",
    "has_output_format",
    "parse_capture_filter",
    "read_datagrams",
    "read_frames",
    "replay",
    "replay_schedule",
    "replay_to",
]

#: Positional parameters a callable may take: the thing it acts on, and one
#: more operand where it has one. Everything else is keyword-only.
POSITIONAL = {
    # A datagram is four things, and there is nothing to name among them.
    "PcapWriter.write": 4,
    # The expression and what turns a clause into a test: both are operands.
    "compile_capture_filter": 2,
    # What to write and the format to write it in, as `json.dump(obj, fp)`.
    "dumps_record": 2,
    "CaptureWriter": 2,
    # The datagram and the record made of it.
    "CaptureWriter.write": 2,
    # What to replay and who receives it.
    "replay": 2,
    # What to replay and where to: a host and a port, as `sendto` takes them.
    "replay_to": 3,
}

#: Named tuples are positional by nature.
NAMED_TUPLES = (
    "CapturedDatagram",
    "CapturedFrame",
    "DecodeStats",
    "FilterClause",
    "ReplayResult",
)


def test_all_is_exactly_the_expected_names():
    assert sorted(pktcap.__all__) == sorted(EXPECTED)
    assert len(set(pktcap.__all__)) == len(pktcap.__all__)


def test_every_export_exists_and_nothing_else_is_public():
    for name in pktcap.__all__:
        assert hasattr(pktcap, name), name
    public = {
        name
        for name, value in vars(pktcap).items()
        if not name.startswith("_") and not inspect.ismodule(value)
    }
    assert public - {"annotations"} == set(pktcap.__all__)


def test_every_export_says_it_comes_from_pktcap():
    for name in pktcap.__all__:
        obj = getattr(pktcap, name)
        if inspect.isclass(obj) or inspect.isfunction(obj):
            assert obj.__module__.split(".")[0] == "pktcap", name


def test_the_version_is_the_installed_metadata():
    assert pktcap.__version__ == version("pktcap")


def _functions():
    for name in pktcap.__all__:
        obj = getattr(pktcap, name)
        if name in NAMED_TUPLES or (
            inspect.isclass(obj) and issubclass(obj, BaseException)
        ):
            continue
        if inspect.isfunction(obj):
            yield name, obj
        elif inspect.isclass(obj):
            yield name, obj.__init__
            for member, value in vars(obj).items():
                if member.startswith("_"):
                    continue
                if isinstance(value, (staticmethod, classmethod)):
                    value = value.__func__
                if inspect.isfunction(value):
                    yield "%s.%s" % (name, member), value


def test_options_are_keyword_only_past_the_counted_positionals():
    wrong = {}
    for name, function in _functions():
        parameters = [
            p
            for p in inspect.signature(function).parameters.values()
            if p.name not in ("self", "cls")
        ]
        count = sum(
            1
            for p in parameters
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        )
        allowed = POSITIONAL.get(name, 1)
        if count > allowed:
            wrong[name] = (count, allowed)
    assert wrong == {}, "too many positional parameters: %r" % (wrong,)
    stale = [name for name in POSITIONAL if name not in dict(_functions())]
    assert stale == [], "POSITIONAL names nothing: %r" % (stale,)


def test_every_public_callable_is_fully_annotated():
    missing = []
    for name, function in _functions():
        signature = inspect.signature(function)
        for parameter in signature.parameters.values():
            if parameter.name in ("self", "cls"):
                continue
            if parameter.annotation is inspect.Parameter.empty:
                missing.append("%s(%s)" % (name, parameter.name))
        if signature.return_annotation is inspect.Signature.empty:
            missing.append("%s -> ?" % name)
    assert missing == []
