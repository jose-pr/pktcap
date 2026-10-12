"""The contract of the command classes: what a library with a protocol of its own
can rely on when it subclasses them.

Each demonstration subclass uses the override points of one command, and is
mixed with a base class of another library that has a ``config`` field and a
``listen`` field of its own: the command classes declare no configuration
option, so the first meets no clash. What is shown working here is what
``cli/AGENTS.md`` promises.
"""

import ast
import importlib
import inspect
import json
import pathlib
import re
import socket
import sys
import threading
import time
from typing import Annotated, Optional

import pytest

pytest.importorskip("duho")

import captures as build  # noqa: E402
from duho import Cmd, Meta, main as run  # noqa: E402
from netimps import UDPEndpoint, bind  # noqa: E402

import pktcap.cli  # noqa: E402
from pktcap import read_dissected  # noqa: E402
from pktcap.cli import (
    Capture,
    Convert,
    Loading,
    Plugins,
    Replay,
    Selecting,
    Writing,
)  # noqa: E402

WAIT = 10.0


class Foreign(Cmd):
    """A base class of another library: its own settings file and its own
    listening grammar."""

    config: Optional[pathlib.Path] = None
    "the other library's settings file"
    ("--config",)

    listen: Optional[str] = None
    "the other library's listen specification"
    ("--listen", "-l")


def frame(payload, port=9999, dst="10.0.0.1"):
    return build.ethernet(build.ipv4("10.0.0.5", dst, build.udp(50000, port, payload)))


BOOT, LEASE, OTHER = frame(b"\x01boot"), frame(b"\x02lease"), frame(b"query", 53)


@pytest.fixture
def trace(tmp_path):
    path = tmp_path / "trace.pcap"
    path.write_bytes(build.pcap([BOOT, LEASE, OTHER]))
    return path


def status_of(command, argv):
    """What ``pktcap.cli.main`` makes of a command class that escapes."""
    try:
        status = run(command, argv)
    except SystemExit as stop:
        return stop.code
    except ValueError:
        return 2
    except OSError:
        return 1
    return 0 if status is None else status


@pytest.fixture
def calls():
    return []


@pytest.fixture
def demo(plugin_module, calls):
    """The demonstration subclasses, for a plugin module written by the test."""
    mod = plugin_module().name

    class Base(Loading):
        _plugins_ = (mod,)
        _logger_name_ = "demo"

    class DemoConvert(Foreign, Base, Convert):
        _parsername_ = "convert"
        _filter_ = "proto=demo"
        _fields_ = ("opcode",)
        _format_ = "text"

        def _select(self, registry):
            calls.append("select")
            assert "demo" in registry.layers()
            return super()._select(registry)

        def _frames(self, dissector):
            calls.append("frames")
            return super()._frames(dissector)

        def _names(self, frame):
            calls.append("names")
            return {"opcode": frame.layers[-1].opcode}

        def _hook(self):
            calls.append("hook")
            return lambda frame: calls.append("each")

        def _report(self, result, dissector):
            calls.append("report")
            return super()._report(result, dissector)

    class Loop(Capture):
        _parsername_ = "capture"
        _default_port_ = 0

    return type("Demo", (), {"mod": mod, "Convert": DemoConvert, "Loop": Loop})


# -- Loading ------------------------------------------------------------------


def test_the_plugin_a_command_always_loads_needs_no_option(demo, trace, capsys):
    argv = ["-i", str(trace), "--format", "json", "-f", "demo.opcode=1"]
    assert status_of(demo.Convert, argv) == 0
    (record,) = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert record["layers"][-1]["name"] == "boot"


def test_the_users_list_naming_the_same_plugin_is_not_an_error(demo, trace, capsys):
    argv = ["-i", str(trace), "--load", demo.mod, "--format", "json"]
    assert status_of(demo.Convert, argv) == 0
    assert (
        capsys.readouterr().err.strip().endswith("3 frames read, 2 written, 1 skipped")
    )


def test_a_foreign_config_field_is_never_taken_for_the_plugin_list(demo, trace):
    """The other library's ``--config`` names a file that does not exist; it is
    that library's, so the registry is built without ever reading it, and no
    option of the base class has to be renamed for it."""
    missing = trace.parent / "missing.ini"
    argv = ["-i", str(trace), "--config", str(missing), "--format", "json"]
    assert status_of(demo.Convert, argv) == 0


def test_a_tool_call_cannot_name_plugins_even_for_a_subclass(demo, trace):
    from duho.mcp import call_tool

    from pktcap.cli._root import Pktcap

    class Root(Pktcap):
        _parsername_ = "demo"
        _subcommands_ = [demo.Convert]

    result = call_tool(Root, "demo.convert", {"input": str(trace), "load": ["x"]})
    assert result["isError"] is True


# -- Selecting and Writing ------------------------------------------------------


def test_filter_and_select_are_called_before_the_source_and_both_apply(
    demo, trace, calls, capsys
):
    assert status_of(demo.Convert, ["-i", str(trace), "-f", "demo.opcode=2"]) == 0
    assert calls.index("select") < calls.index("hook") < calls.index("frames")
    assert calls.count("select") == calls.count("frames") == 1
    assert calls.count("report") == 1 and calls[-1] == "report"
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1  # proto=demo from the class, opcode=2 from the user


def test_names_are_asked_for_the_frames_the_filter_kept_and_each_follows_the_write(
    demo, trace, calls
):
    argv = ["-i", str(trace), "-o", str(trace.parent / "{opcode}-{index}.json")]
    argv += ["--per-record"]
    assert status_of(demo.Convert, argv) == 0
    names = sorted(p.name for p in trace.parent.glob("*-*.json"))
    assert names == ["1-0.json", "2-1.json"]  # the dropped frame has no file
    assert calls.count("names") == 2 and calls.count("each") == 2


def test_the_class_format_applies_when_nothing_names_one(demo, trace, capsys, tmp_path):
    assert status_of(demo.Convert, ["-i", str(trace)]) == 0
    assert capsys.readouterr().out.splitlines()[0].count("{") == 0
    out = tmp_path / "listing.out"  # no known ending: the class decides
    assert status_of(demo.Convert, ["-i", str(trace), "-o", str(out)]) == 0
    assert "10.0.0.5:50000" in out.read_text(encoding="ascii")
    assert status_of(demo.Convert, ["-i", str(trace), "--format", "json"]) == 0
    json.loads(capsys.readouterr().out.splitlines()[-1])


def test_the_ending_of_the_output_beats_the_class_format(demo, trace, tmp_path):
    out = tmp_path / "records.json"
    assert status_of(demo.Convert, ["-i", str(trace), "-o", str(out)]) == 0
    json.loads(out.read_text(encoding="ascii").splitlines()[0])


def test_a_class_without_a_format_writes_json_as_before(trace, capsys):
    assert status_of(Convert, ["-i", str(trace)]) == 0
    json.loads(capsys.readouterr().out.splitlines()[0])


def test_append_adds_to_a_record_file(trace, tmp_path, capsys):
    out = tmp_path / "all.jsonl"
    argv = ["-i", str(trace), "-o", str(out), "--format", "json"]
    assert status_of(Convert, argv) == 0
    assert status_of(Convert, argv + ["--append"]) == 0
    assert len(out.read_text(encoding="ascii").splitlines()) == 6
    assert status_of(Convert, argv + ["--append", "--format", "pcap"]) == 2


class Source(Writing):
    """A command whose source is its own and whose points are all overridden."""

    _parsername_ = "source"
    _interruptible_ = False
    seen = None

    def _frames(self, dissector):
        class Frames:
            closed = 0

            def __init__(self, items):
                self.items = iter(items)

            def __iter__(self):
                return self

            def __next__(self):
                return next(self.items)

            def close(self):
                Frames.closed += 1

        Source.seen = Frames
        items = read_dissected(self.input, dissector=dissector)
        return Frames(items)

    def _limit(self):
        return 1

    input: str = ""
    ("--input",)


def test_the_source_is_closed_by_the_loop_and_the_limit_is_asked_of_the_class(
    trace, capsys
):
    assert status_of(Source, ["--input", str(trace)]) == 0
    assert Source.seen.closed == 1
    assert len(capsys.readouterr().out.splitlines()) == 1


@pytest.mark.parametrize(
    "raised, status",
    [(ValueError("bad"), 2), (OSError("gone"), 1), (KeyboardInterrupt(), "interrupt")],
)
def test_what_the_source_raises_is_a_status(raised, status, trace):
    class Failing(Source):
        def _frames(self, dissector):
            raise raised

    class Midway(Source):
        def _frames(self, dissector):
            yield from read_dissected(self.input, dissector=dissector)
            raise raised

        def _limit(self):
            return None

    if status == "interrupt":
        # Not _interruptible_: the interrupt is not the command's to absorb,
        # whether it comes before the first frame or in the middle of the copy.
        for command in (Failing, Midway):
            with pytest.raises(KeyboardInterrupt):
                run(command, ["--input", str(trace)])
    else:
        assert status_of(Failing, ["--input", str(trace)]) == status
        assert status_of(Midway, ["--input", str(trace)]) == status


def test_an_interruptible_command_ends_with_its_summary_and_status_0(trace, capsys):
    class Interrupted(Source):
        _interruptible_ = True

        def _frames(self, dissector):
            yield from read_dissected(self.input, dissector=dissector)
            raise KeyboardInterrupt

        def _limit(self):
            return None

    assert status_of(Interrupted, ["--input", str(trace)]) == 0
    assert "3 frames read, 3 written" in capsys.readouterr().err


def test_selecting_alone_is_a_base_with_no_source():
    assert issubclass(Writing, Selecting) and issubclass(Selecting, Loading)
    assert set(pktcap.cli.__all__) == {
        "main", "Loading", "Selecting", "Writing", "Capture", "Convert", "Replay",
        "Plugins",
    }  # fmt: skip


# -- _env_prefix_: a variable for every option ---------------------------------------


class Prefixed(Convert):
    _parsername_ = "convert"
    _env_prefix_ = "MYPROG_CONVERT_"


class Unprefixed(Convert):
    _parsername_ = "convert"


def test_a_class_with_an_env_prefix_takes_an_inherited_option_from_its_variable(
    trace, monkeypatch, capsys
):
    monkeypatch.setenv("MYPROG_CONVERT_FORMAT", "text")
    monkeypatch.setenv("MYPROG_CONVERT_LIMIT", "2")
    assert status_of(Prefixed, ["-i", str(trace)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2 and not any(line.startswith("{") for line in lines)
    monkeypatch.setenv("MYPROG_CONVERT_FILTER", "proto=nothing")
    assert status_of(Prefixed, ["-i", str(trace)]) == 0
    assert capsys.readouterr().out == ""


def test_the_variable_names_are_the_prefix_and_the_field_in_upper_case():
    found = {b.name: b.env for b in Prefixed._getargs_()}
    assert found["format"] == "MYPROG_CONVERT_FORMAT"
    assert found["per_record"] == "MYPROG_CONVERT_PER_RECORD"
    assert found["input"] == "MYPROG_CONVERT_INPUT"
    assert found["load"] == "PKTCAP_LOAD"
    assert {found[n] for n in ("verbose", "quiet", "loglevels")} == {None}
    assert {b.env for b in Unprefixed._getargs_()} == {None, "PKTCAP_LOAD"}


def test_an_empty_variable_name_keeps_an_option_without_one(trace, monkeypatch, capsys):
    class Quiet(Prefixed):
        _parsername_ = "convert"

        limit: Annotated[Optional[int], Meta(env="")] = None
        "the most frames"
        ("--limit",)

    monkeypatch.setenv("MYPROG_CONVERT_LIMIT", "1")
    monkeypatch.setenv("MYPROG_CONVERT_FORMAT", "text")
    assert status_of(Quiet, ["-i", str(trace)]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 3  # the limit was not read
    assert {b.name: b.env for b in Quiet._getargs_()}["limit"] == ""


def test_the_command_line_beats_the_variable_of_a_prefixed_class(
    trace, monkeypatch, capsys
):
    monkeypatch.setenv("MYPROG_CONVERT_FORMAT", "text")
    assert status_of(Prefixed, ["-i", str(trace), "--format", "json"]) == 0
    assert capsys.readouterr().out.startswith("{")


def test_a_class_without_a_prefix_reads_no_variable(trace, monkeypatch, capsys):
    monkeypatch.setenv("MYPROG_CONVERT_FORMAT", "text")
    monkeypatch.setenv("CONVERT_FORMAT", "text")
    assert status_of(Unprefixed, ["-i", str(trace)]) == 0
    assert capsys.readouterr().out.startswith("{")


def test_a_prefix_gives_no_variable_to_an_option_that_has_one(
    demo, trace, monkeypatch, capsys
):
    # `load` is PKTCAP_LOAD whatever the prefix, as the header says; the
    # prefixed name for it is not read.
    monkeypatch.setenv("MYPROG_CONVERT_LOAD", "no.such.module")
    monkeypatch.setenv("PKTCAP_LOAD", demo.mod)
    argv = ["-i", str(trace), "-f", "demo.opcode=1"]
    assert status_of(Prefixed, argv) == 0
    assert len(capsys.readouterr().out.splitlines()) == 1


def test_a_subclass_of_a_prefixed_class_can_change_the_prefix(
    trace, monkeypatch, capsys
):
    class Other(Prefixed):
        _parsername_ = "convert"
        _env_prefix_ = "OTHER_"

    monkeypatch.setenv("MYPROG_CONVERT_FORMAT", "text")
    monkeypatch.setenv("OTHER_FORMAT", "yaml")
    assert status_of(Other, ["-i", str(trace)]) == 0
    assert capsys.readouterr().out.startswith("---")


# -- Capture --------------------------------------------------------------------


def test_endpoints_and_stop_and_default_port_are_the_subclasses(demo, calls, capsys):
    """The foreign ``listen`` replaces pktcap's, and the subclass binds what it
    names: the base class never sees a ``HOST:PORT`` of its own."""
    published = {}

    class Mine(Foreign, demo.Loop):
        def _endpoints(self, dissector):
            calls.append("endpoints")
            endpoint = UDPEndpoint(bind("127.0.0.1", 0))
            published["port"] = endpoint.socket.getsockname()[1]
            return (endpoint,)

        def _stop(self):
            calls.append("stop")
            return super()._stop()

    result = {}

    def go():
        result["status"] = status_of(
            Mine,
            ["--listen", "the-foreign-grammar", "--count", "1", "--format", "text"],
        )

    thread = threading.Thread(target=go)
    thread.start()
    deadline = time.monotonic() + WAIT
    while "port" not in published and time.monotonic() < deadline:
        time.sleep(0.02)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(b"x", ("127.0.0.1", published["port"]))
    thread.join(WAIT)
    assert result["status"] == 0 and calls.count("endpoints") == 1
    assert "stop" in calls  # asked although the command gave no --duration
    assert len(capsys.readouterr().out.splitlines()) == 1


def test_stop_ends_a_capture_whose_source_is_quiet(demo, capsys):
    class Quiet(demo.Loop):
        def _endpoints(self, dissector):
            return (UDPEndpoint(bind("127.0.0.1", 0)),)

        def _stop(self):
            return True

    outcome = {}

    def go():
        outcome["status"] = status_of(Quiet, ["--listen", "127.0.0.1"])

    # No --duration: the override alone ends it. A daemon thread, so a capture
    # that ignores the override does not hold the process.
    thread = threading.Thread(target=go, daemon=True)
    thread.start()
    thread.join(WAIT)
    assert not thread.is_alive() and outcome["status"] == 0
    assert "0 frames read, 0 written" in capsys.readouterr().err


def test_endpoints_is_given_the_dissector_the_frames_are_read_with(demo, capsys):
    """A subclass registers its protocol on the port it bound, whichever the
    kernel chose, in the registry the frames are dissected with."""
    module = importlib.import_module(demo.mod)
    seen = {}

    class Mine(demo.Loop):
        _plugins_ = (demo.mod,)

        def _frames(self, dissector):
            seen["frames"] = dissector
            return super()._frames(dissector)

        def _endpoints(self, dissector):
            seen["endpoints"] = dissector
            endpoint = UDPEndpoint(bind("127.0.0.1", 0))
            seen["port"] = endpoint.socket.getsockname()[1]
            dissector.registry.register("udp", seen["port"], module.dissect)
            return (endpoint,)

    result = {}
    thread = threading.Thread(
        target=lambda: result.update(
            status=status_of(Mine, ["--listen", "x", "--count", "1"])
        )
    )
    thread.start()
    deadline = time.monotonic() + WAIT
    while "port" not in seen and time.monotonic() < deadline:
        time.sleep(0.02)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(b"\x01boot", ("127.0.0.1", seen["port"]))
    thread.join(WAIT)
    assert result["status"] == 0
    assert seen["endpoints"] is seen["frames"]
    (record,) = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert record["layers"][-1]["name"] == "boot"


def test_a_subclass_without_a_listen_of_its_own_keeps_the_exclusion(demo):
    flags = {o for a in demo.Loop._parser_()._actions for o in a.option_strings}
    assert {"--listen", "--interface"} <= flags
    assert status_of(demo.Loop, ["--listen", "127.0.0.1", "--interface", "x"]) == 2


# -- Replay ---------------------------------------------------------------------


def test_replay_points_are_the_subclasses(trace, capsys):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(WAIT)
    port = sock.getsockname()[1]
    calls = []

    class Mine(Foreign, Replay):
        _parsername_ = "replay"
        _default_port_ = port

        def _datagrams(self, registry):
            calls.append("datagrams")
            return (d for i, d in enumerate(super()._datagrams(registry)) if i == 0)

        def _replay(self, datagrams, host, to_port):
            calls.append((host, to_port))
            return super()._replay(datagrams, host, to_port)

        def _report(self, result):
            calls.append("report")
            print("mine: %d" % result.sent)

    try:
        argv = ["-i", str(trace), "--to", "127.0.0.1", "--no-delay"]
        assert status_of(Mine, argv + ["--config", "x"]) == 0
        assert sock.recvfrom(2048)[0] == b"\x01boot"
    finally:
        sock.close()
    assert calls == ["datagrams", ("127.0.0.1", port), "report"]
    assert capsys.readouterr().out.strip() == "mine: 1"


def test_a_destination_without_a_port_is_refused_when_the_class_has_no_default(
    trace,
):
    argv = ["-i", str(trace), "--to", "127.0.0.1"]
    with pytest.raises(ValueError, match="needs a port"):
        run(Replay, argv)


def test_the_worked_subclass_of_the_header_runs(trace, capsys):
    """The Python block of ``cli/AGENTS.md`` is executed, and the class it
    defines converts a capture as the header says."""
    header = pathlib.Path(pktcap.cli.__file__).with_name("AGENTS.md")
    text = header.read_text(encoding="utf-8")
    block = text.split("```python\n", 1)[1].split("\n```", 1)[0]
    namespace = {}
    exec(compile(block, "cli/AGENTS.md", "exec"), namespace)
    assert status_of(namespace["Listing"], ["-i", str(trace)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3 and all("10.0.0.5:50000" in line for line in lines)
    # The capture subclass uses the three points of the Capture class: it
    # listens with no option, reads its protocol on the ports it bound, and
    # has a variable for each option.
    watching = namespace["Watching"]
    assert watching._listen_ == "*" and watching._default_port_ == (6767, 6768)
    names = {builder.name: builder.env for builder in watching._getargs_()}
    assert names["format"] == "MYPROG_WATCHING_FORMAT"
    assert names["load"] == "PKTCAP_LOAD" and names["verbose"] is None
    assert "dissector" in inspect.signature(watching._endpoints).parameters


# -- the base's private names are its own --------------------------------------------

#: Every private member the base once had without a prefix: a subclass that
#: keeps its own data in one of them must not change what the base does.
FORMER_PRIVATE_NAMES = (
    "_origin", "_taken_from", "_list_source", "_registry", "_built", "_chosen",
    "_noted", "_writer", "_written", "_open", "_bound", "_deadline", "_hooked",
    "_listening", "_permitted", "_source", "_until", "_name", "_named",
    "_destination", "_endpoint", "_text",
)  # fmt: skip
#: Names duho reads on a class (and the ones it adds, which begin `_duho_`).
DUHO_NAMES = {"_parsername_", "_logger_name_", "_mcp_", "_getargs_"}
THE_SEVEN = (
    "Loading",
    "Selecting",
    "Writing",
    "Capture",
    "Convert",
    "Replay",
    "Plugins",
)


def _shadowing(base):
    attributes = {name: "mine" for name in FORMER_PRIVATE_NAMES}
    attributes["_parsername_"] = base._parsername_
    return type("Shadowing" + base.__name__, (base,), attributes)


def _subclassing_section():
    header = pathlib.Path(pktcap.cli.__file__).with_name("AGENTS.md")
    return header.read_text(encoding="utf-8").split("## Subclassing", 1)[1]


def test_every_private_name_a_command_class_defines_is_listed_or_carries_the_prefix():
    section = _subclassing_section()
    listed = set(re.findall(r"(?<![A-Za-z0-9_])(_[a-z][a-z_]*)", section))
    assert "_pk_" in listed, "the header must say what the prefix is"
    stray = {}
    for name in THE_SEVEN:
        defined = [
            n
            for n in vars(getattr(pktcap.cli, name))
            if n.startswith("_") and not (n.startswith("__") and n.endswith("__"))
        ]
        stray[name] = sorted(
            n
            for n in defined
            if n not in listed
            and n not in DUHO_NAMES
            and not n.startswith(("_pk_", "_duho_"))
        )
    assert stray == {name: [] for name in THE_SEVEN}


def test_no_command_class_stores_an_instance_attribute_outside_the_prefix():
    directory = pathlib.Path(pktcap.cli.__file__).parent
    stray = []
    for path in sorted(directory.glob("*.py")):
        for cls in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(cls, ast.ClassDef) and cls.name in THE_SEVEN):
                continue
            for node in ast.walk(cls):
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.ctx, ast.Store)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "self"
                    and node.attr.startswith("_")
                    and not node.attr.startswith("_pk_")
                ):
                    stray.append("%s.%s" % (cls.name, node.attr))
    assert stray == []


def test_a_subclass_that_keeps_data_in_a_former_private_name_still_converts(
    trace, capsys
):
    assert status_of(_shadowing(Convert), ["-i", str(trace), "--format", "json"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 3


def test_a_subclass_that_keeps_data_in_a_former_private_name_still_lists_plugins(
    capsys,
):
    assert status_of(_shadowing(Plugins), ["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["plugins"] == []


def test_a_subclass_that_keeps_data_in_a_former_private_name_still_replays(
    trace, capsys
):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(WAIT)
    try:
        to = "127.0.0.1:%d" % sock.getsockname()[1]
        argv = ["-i", str(trace), "--to", to, "--no-delay", "--source-port", "0"]
        assert status_of(_shadowing(Replay), argv) == 0
        assert sock.recvfrom(2048)[0] == b"\x01boot"
    finally:
        sock.close()
    assert capsys.readouterr().out.strip() == "sent 3, partial 0"


def test_a_subclass_that_keeps_data_in_a_former_private_name_still_captures_with_a_hook(
    tmp_path, monkeypatch, caplog
):
    from test_cli_listen import listen_and_send

    directory = tmp_path / "mods"
    directory.mkdir()
    (directory / "shadowmod.py").write_bytes(
        b"seen = []\n\ndef keep(frame):\n    seen.append(frame.datagram().payload)\n"
    )
    monkeypatch.syspath_prepend(str(directory))
    Shadowing = _shadowing(Capture)
    Shadowing._hook_from_ = ("argument",)
    Shadowing._default_port_ = 0
    argv = ["--listen", "127.0.0.1:0", "--count", "1", "--format", "text"]
    argv += ["--hook", "shadowmod:keep"]
    status, _ = listen_and_send(
        argv, caplog, [b"hello"], runner=lambda a: status_of(Shadowing, a)
    )
    import shadowmod

    try:
        assert status == 0 and shadowmod.seen == [b"hello"]
    finally:
        sys.modules.pop("shadowmod", None)


def test_the_missing_live_capture_line_names_the_program_that_runs(monkeypatch):
    from duho import Cli, LoggingArgs

    from pktcap import LiveCaptureError

    monkeypatch.setattr("pktcap.cli.capture.has_live_capture", lambda: False)

    class Mine(Capture):
        _parsername_ = "capture"

    root = type(
        "Root", (LoggingArgs, Cli), {"_parsername_": "mytool", "_subcommands_": [Mine]}
    )
    with pytest.raises(LiveCaptureError) as caught:
        run(root, ["capture"])
    text = str(caught.value)
    assert "tcpdump -w - | mytool convert --input -" in text and "pktcap" not in text


def test_the_help_of_interface_names_no_option_a_subclass_may_not_have():
    parser = Capture._parser_()
    (action,) = [a for a in parser._actions if "--interface" in a.option_strings]
    assert "--listen" not in action.help
