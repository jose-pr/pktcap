"""``pktcap capture --listen``: datagrams arriving at sockets the command binds.

The command binds port 0 and says where it listens at ``-v``; the test reads
that line, sends a datagram to the address and waits for the command to end.
Every socket is on loopback and every wait has a bound of seconds.
"""

import logging
import socket
import subprocess
import sys
import threading
import time

import pytest

pytest.importorskip("duho")

from netimps import UDPEndpoint, bind, get_interface  # noqa: E402

from pktcap.cli import Capture, main  # noqa: E402

WAIT = 10.0
SAFETY = ["--duration", "30"]


def _has_ipv6_loopback():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        return False
    return True


def _listening(records):
    """``[(host, port)]`` from the command's "listening on" lines so far."""
    found = []
    for record in records:
        text = record.getMessage()
        if text.startswith("listening on "):
            for item in text[len("listening on ") :].split(", "):
                host, _, port = item.rpartition(":")
                found.append((host, int(port)))
    return found


def listen_and_send(argv, caplog, payloads, *, to=None, wanted=1, targets=None):
    """Run ``capture`` with ``argv`` (which binds port 0) in a thread, send each
    payload to the address it reports, and return its status once it ends."""
    caplog.set_level(logging.INFO)
    outcome = {}

    def run():
        outcome["status"] = main(argv + ["-v"])

    thread = threading.Thread(target=run)
    thread.start()
    try:
        deadline = time.monotonic() + WAIT
        addresses = []
        while len(addresses) < wanted and time.monotonic() < deadline:
            if "status" in outcome:
                break
            addresses = _listening(caplog.records)
            time.sleep(0.02)
        assert len(addresses) >= wanted, "the command never said where it listens"
        for number, payload in enumerate(payloads):
            host, port = addresses[targets[number] if targets else 0]
            host = to or host
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as sender:
                sender.sendto(payload, (host, port))
        thread.join(WAIT)
        assert not thread.is_alive(), "the command did not stop after --count"
    finally:
        thread.join(1)
    return outcome["status"], addresses


# -- one datagram, as a line a person reads -----------------------------------


def test_a_datagram_sent_to_the_address_is_one_line_of_text(caplog, capsys):
    argv = ["capture", "--listen", "127.0.0.1:0", "--count", "1", "--format", "text"]
    status, addresses = listen_and_send(argv + SAFETY, caplog, [b"hello"])
    out, err = capsys.readouterr()
    assert status == 0
    lines = out.splitlines()
    assert len(lines) == 1
    assert "127.0.0.1:%d" % addresses[0][1] in lines[0] and "udp" in lines[0].lower()
    assert err.strip().endswith("1 frames read, 1 written")


@pytest.mark.skipif(not _has_ipv6_loopback(), reason="this host has no IPv6 loopback")
def test_an_ipv6_address_in_brackets_is_listened_on(caplog, capsys):
    argv = ["capture", "--listen", "[::1]:0", "--count", "1", "--format", "text"]
    status, addresses = listen_and_send(argv + SAFETY, caplog, [b"v6"])
    assert status == 0 and addresses[0][0] == "::1"
    (line,) = capsys.readouterr().out.splitlines()
    assert "::1" in line


def test_the_record_is_the_frame_with_made_up_headers_and_the_payload(caplog, capsys):
    argv = ["capture", "--listen", "127.0.0.1:0", "--count", "1", "--datagrams"]
    status, addresses = listen_and_send(argv + SAFETY, caplog, [b"\x01payload"])
    assert status == 0
    import json

    (record,) = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert record["payload"] == b"\x01payload".hex()
    assert record["destination"] == "127.0.0.1:%d" % addresses[0][1]


def test_a_wildcard_form_binds_the_ipv4_wildcard(caplog):
    argv = ["capture", "--count", "1", "--format", "text", "--listen", ":0"]
    status, addresses = listen_and_send(argv + SAFETY, caplog, [b"x"], to="127.0.0.1")
    assert status == 0 and addresses[0][0] == "0.0.0.0"


def test_an_adapter_name_binds_a_socket_limited_to_that_adapter(caplog):
    name = get_interface("127.0.0.1").name
    argv = ["capture", "--count", "1", "--format", "text"]
    argv += ["--listen", "%s:0" % name]
    status, addresses = listen_and_send(argv + SAFETY, caplog, [b"x"], to="127.0.0.1")
    assert status == 0 and addresses[0][0] == "0.0.0.0"


def test_several_values_bind_several_sockets_in_the_order_written(caplog):
    argv = ["capture", "--count", "1", "--format", "text"]
    argv += ["--listen", "127.0.0.1:0", "--listen", "127.0.0.2:0,127.0.0.3:0"]
    status, addresses = listen_and_send(argv + SAFETY, caplog, [b"x"], wanted=3)
    assert status == 0
    assert [host for host, _ in addresses] == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]


def test_a_datagram_from_an_interface_a_socket_does_not_serve_is_counted_in_the_summary(
    caplog, capsys
):
    from netimps import get_interfaces

    loopback = get_interface("127.0.0.1").index
    others = [i for i in get_interfaces() if i.index and i.index != loopback]
    if not others:
        pytest.skip("this host has no adapter besides loopback")
    probe = UDPEndpoint(bind("127.0.0.1", 0))
    has_pktinfo = probe.has_pktinfo
    probe.close()
    if not has_pktinfo:
        pytest.skip("this host reports no arrival interface")
    argv = ["capture", "--count", "1", "--format", "text"]
    argv += ["--listen", "%s:0" % others[0].name, "--listen", "127.0.0.1:0"]
    status, _ = listen_and_send(
        argv + SAFETY,
        caplog,
        [b"dropped", b"kept"],
        to="127.0.0.1",
        wanted=2,
        targets=[0, 1],
    )
    assert status == 0
    out, err = capsys.readouterr()
    assert len(out.splitlines()) == 1
    assert err.strip().endswith("1 frames read, 1 written, 1 not admitted")


# -- what is refused ------------------------------------------------------------


@pytest.mark.parametrize(
    "spec", ["", ":99999", "[127.0.0.1]:5", "a/b", "127.0.0.1:1:2:z"], ids=str
)
def test_a_wrong_specification_is_status_2_before_anything_is_opened(
    spec, monkeypatch, capsys
):
    opened = []
    real = socket.socket.bind
    monkeypatch.setattr(
        socket.socket, "bind", lambda self, *a: opened.append(a) or real(self, *a)
    )
    assert main(["capture", "--listen", spec, "--count", "1"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and err.startswith("pktcap: error: ") and err.count("\n") == 1
    assert opened == []


def test_a_value_with_no_port_and_no_default_is_refused_with_the_message_of_netimps(
    capsys,
):
    assert main(["capture", "--listen", "127.0.0.1", "--count", "1"]) == 2
    err = capsys.readouterr().err
    assert "127.0.0.1" in err and "port" in err


def test_listen_and_interface_exclude_each_other(capsys):
    argv = ["capture", "--listen", "127.0.0.1:0", "--interface", "lo"]
    assert main(argv) == 2
    assert "not allowed with" in capsys.readouterr().err


def test_a_taken_port_is_status_1_and_one_line_naming_the_address(capsys):
    held = UDPEndpoint(bind("127.0.0.1", 0), pktinfo=False)
    port = held.socket.getsockname()[1]
    try:
        spec = "127.0.0.1:%d" % port
        assert main(["capture", "--listen", spec, "--count", "1"]) == 1
    finally:
        held.close()
    out, err = capsys.readouterr()
    assert out == "" and err.count("\n") == 1
    assert err.startswith("pktcap: error: cannot listen on %s" % spec)


# -- the points a subclass overrides --------------------------------------------


class Port(Capture):
    _parsername_ = "port"
    _default_port_ = 0


def test_a_subclass_default_port_is_what_a_value_without_one_gets(caplog, capsys):
    from duho import parse

    command = parse(Port, ["--listen", "127.0.0.1", "--count", "1"])
    caplog.set_level(logging.INFO)
    result = {}
    thread = threading.Thread(target=lambda: result.update(status=command()))
    thread.start()
    deadline = time.monotonic() + WAIT
    while not _listening(caplog.records) and time.monotonic() < deadline:
        time.sleep(0.02)
    ((host, port),) = _listening(caplog.records)
    assert host == "127.0.0.1" and port != 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(b"x", (host, port))
    thread.join(WAIT)
    assert result["status"] == 0


# -- the real command line --------------------------------------------------------


def test_the_real_command_prints_one_line_for_a_datagram_sent_to_it():
    process = subprocess.Popen(
        [sys.executable, "-m", "pktcap", "capture", "-v", "--listen", "127.0.0.1:0"]
        + ["--count", "1", "--format", "text", "--duration", "30"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        port = None
        deadline = time.monotonic() + 60
        while port is None and time.monotonic() < deadline:
            line = process.stderr.readline()
            assert line, "the command ended before it listened"
            if "listening on " in line:
                port = int(line.strip().rsplit(":", 1)[1])
        assert port, "the command never said where it listens"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"the real one", ("127.0.0.1", port))
        out, err = process.communicate(timeout=60)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    assert process.returncode == 0
    assert len(out.splitlines()) == 1 and "127.0.0.1:%d" % port in out
