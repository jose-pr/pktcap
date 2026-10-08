"""The public surface: exactly what ``pktcap.__all__`` exports.

A name added, removed or renamed has to change this list in the same commit,
so the surface never moves by accident.
"""

import inspect
from importlib.metadata import version

import pktcap

EXPECTED = [
    "CaptureConfigError",
    "CaptureFilterError",
    "CaptureFormatError",
    "CapturePluginError",
    "CaptureSource",
    "CaptureWriter",
    "CapturedDatagram",
    "CapturedFrame",
    "CopyResult",
    "DissectError",
    "DissectStats",
    "Dissected",
    "DissectedFrame",
    "Dissector",
    "DissectorRegistry",
    "EthernetLayer",
    "FRAME_FILTER_KEYS",
    "FilterClause",
    "Fragment",
    "FrameDissector",
    "IPv4Layer",
    "IPv6ExtensionLayer",
    "IPv6FragmentLayer",
    "IPv6Layer",
    "LINKTYPES",
    "LinuxCookedLayer",
    "LiveCapture",
    "LiveCaptureError",
    "LoadedPlugin",
    "LoopbackLayer",
    "MissingExtraError",
    "OUTPUT_FORMATS",
    "PcapWriter",
    "PcapngWriter",
    "PktcapError",
    "RECORD_FORMATS",
    "RecordFormatError",
    "ReplayResult",
    "ReplaySource",
    "Selector",
    "TCPLayer",
    "TCPReassembler",
    "TCPStreamData",
    "TCPStreamStats",
    "UDPLayer",
    "UnsupportedFormatError",
    "VLANLayer",
    "check_dissector",
    "compile_capture_filter",
    "copy_frames",
    "datagram_record",
    "default_registry",
    "dumps_record",
    "frame_filter",
    "frame_filter_for",
    "frame_filter_keys",
    "frame_record",
    "load_plugins",
    "loads_record",
    "capture_config_path",
    "has_live_capture",
    "has_output_format",
    "parse_capture_filter",
    "read_datagrams",
    "read_dissected",
    "read_frames",
    "read_tcp_streams",
    "register_dissector",
    "replay",
    "replay_schedule",
    "replay_to",
    "sniff",
    "sniff_frames",
]

#: Positional parameters a callable may take: the thing it acts on, and one
#: more operand where it has one. Everything else is keyword-only.
POSITIONAL = {
    # A datagram is four things, and there is nothing to name among them.
    "PcapWriter.write": 4,
    "PcapngWriter.write": 4,
    # The expression and what turns a clause into a test: both are operands.
    "compile_capture_filter": 2,
    # The frames to copy and the writer that takes them.
    "copy_frames": 2,
    # What to write and the format to write it in, as `json.dump(obj, fp)`.
    "dumps_record": 2,
    # The text to read and the format it is in, as `json.loads` and `dumps_record`.
    "loads_record": 2,
    "CaptureWriter": 2,
    # What was captured and the record made of it.
    "CaptureWriter.write": 2,
    # What to replay and who receives it.
    "replay": 2,
    # What to replay and where to: a host and a port, as `sendto` takes them.
    "replay_to": 3,
    # A selector is two things, and a registration is a selector and a dissector.
    "DissectorRegistry.register": 3,
    "DissectorRegistry.unregister": 2,
    "DissectorRegistry.get": 2,
    "register_dissector": 3,
    # The registry that receives the hooks, and the list that names them.
    "load_plugins": 2,
    # The dissector under test and the octets to try it on.
    "check_dissector": 2,
}

#: Named tuples are positional by nature.
NAMED_TUPLES = (
    "CapturedDatagram",
    "CapturedFrame",
    "CopyResult",
    "DissectStats",
    "Dissected",
    "DissectedFrame",
    "EthernetLayer",
    "FilterClause",
    "Fragment",
    "IPv4Layer",
    "IPv6ExtensionLayer",
    "IPv6FragmentLayer",
    "IPv6Layer",
    "LinuxCookedLayer",
    "LoadedPlugin",
    "LoopbackLayer",
    "ReplayResult",
    "TCPLayer",
    "TCPStreamData",
    "TCPStreamStats",
    "UDPLayer",
    "VLANLayer",
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
            # Inherited methods too: the two capture writers share theirs.
            for member, value in inspect.getmembers(obj, inspect.isfunction):
                if not member.startswith("_"):
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
