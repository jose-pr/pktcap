"""``pktcap replay``: datagrams sent to loopback sockets the test owns.

The destination is only ever ``--to``: the capture's own addresses (10.0.0.x
here) are never sent to, which the suite's network guard would fail on.
"""

import json
import socket
import subprocess
import sys
import time

import pytest

pytest.importorskip("duho")

import captures as build  # noqa: E402
from pktcap.cli import main  # noqa: E402


def _frame(src, dst, sport, dport, payload, *, stated=None):
    return build.ethernet(
        build.ipv4(src, dst, build.udp(sport, dport, payload, length=stated))
    )


FIRST = _frame("10.0.0.5", "10.0.0.1", 68, 67, b"first")
# The UDP header states 58 octets and 5 are captured: a snap length cut it.
CUT = _frame("10.0.0.5", "10.0.0.1", 68, 67, b"cut-x", stated=58)
THIRD = _frame("10.0.0.6", "10.0.0.1", 69, 53, b"third")
TCP = build.ethernet(
    build.ipv4("10.0.0.5", "10.0.0.2", build.tcp(40000, 80, b"GET"), protocol=6)
)


@pytest.fixture
def trace(tmp_path):
    path = tmp_path / "trace.pcap"
    path.write_bytes(build.pcap([FIRST, CUT, THIRD, TCP]))
    return path


@pytest.fixture
def listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)
    yield sock
    sock.close()


def _to(sock):
    return "127.0.0.1:%d" % sock.getsockname()[1]


def _received(sock, count):
    return [sock.recvfrom(2048)[0] for _ in range(count)]


def _nothing_more(sock):
    sock.settimeout(0.3)
    with pytest.raises(socket.timeout):
        sock.recvfrom(2048)


def test_the_whole_datagrams_arrive_in_order_and_the_partial_one_is_counted(
    trace, listener, capsys
):
    assert main(["replay", "-i", str(trace), "--to", _to(listener), "--no-delay"]) == 0
    out, err = capsys.readouterr()
    assert out == "sent 2, partial 1\n" and err == ""
    assert _received(listener, 2) == [b"first", b"third"]
    _nothing_more(listener)


def test_json_prints_the_result_as_one_object(trace, listener, capsys):
    argv = ["replay", "-i", str(trace), "--to", _to(listener), "--no-delay", "--json"]
    assert main(argv) == 0
    assert json.loads(capsys.readouterr().out) == {"sent": 2, "partial": 1}


def test_limit_sends_that_many_and_no_more(trace, listener, capsys):
    argv = ["replay", "-i", str(trace), "--to", _to(listener), "--no-delay"]
    assert main(argv + ["--limit", "1"]) == 0
    assert capsys.readouterr().out == "sent 1, partial 0\n"
    assert _received(listener, 1) == [b"first"]
    _nothing_more(listener)


def test_a_filter_chooses_the_datagrams(trace, listener, capsys):
    argv = ["replay", "-i", str(trace), "--to", _to(listener), "--no-delay"]
    assert main(argv + ["-f", "dport=53"]) == 0
    assert capsys.readouterr().out == "sent 1, partial 0\n"
    assert _received(listener, 1) == [b"third"]


def test_the_destination_is_the_only_one(trace, listener):
    """The capture is of 10.0.0.x: reaching it would fail the suite's guard."""
    assert main(["replay", "-i", str(trace), "--to", _to(listener), "--no-delay"]) == 0
    assert _received(listener, 2)


def test_the_recorded_pace_is_kept_up_to_max_delay(tmp_path, listener):
    path = tmp_path / "slow.pcap"
    path.write_bytes(build.pcap([FIRST, THIRD], start=1_000_000))  # one second apart
    started = time.monotonic()
    argv = ["replay", "-i", str(path), "--to", _to(listener), "--max-delay", "0.3"]
    assert main(argv) == 0
    elapsed = time.monotonic() - started
    assert 0.25 <= elapsed < 3, elapsed
    assert _received(listener, 2) == [b"first", b"third"]


def test_speed_divides_the_recorded_wait(tmp_path, listener):
    path = tmp_path / "slow.pcap"
    path.write_bytes(build.pcap([FIRST, THIRD]))
    started = time.monotonic()
    assert (
        main(["replay", "-i", str(path), "--to", _to(listener), "--speed", "10"]) == 0
    )
    assert 0.08 <= time.monotonic() - started < 3


def test_speed_and_no_delay_conflict(trace, listener, capsys):
    argv = ["replay", "-i", str(trace), "--to", _to(listener), "--speed", "2"]
    assert main(argv + ["--no-delay"]) == 2
    assert "not allowed with" in capsys.readouterr().err
    _nothing_more(listener)


@pytest.mark.parametrize(
    "to, words",
    [
        ("127.0.0.1", "port"),
        ("127.0.0.1:0", "port"),
        ("127.0.0.1:70000", "port"),
        ("127.0.0.1:x", "port"),
    ],
)
def test_a_destination_without_a_usable_port_is_a_usage_error(to, words, trace, capsys):
    assert main(["replay", "-i", str(trace), "--to", to, "--no-delay"]) == 2
    assert words in capsys.readouterr().err


def test_no_destination_is_a_usage_error(trace, capsys):
    assert main(["replay", "-i", str(trace)]) == 2
    assert "--to" in capsys.readouterr().err


def test_a_destination_that_does_not_resolve_is_status_1(trace, monkeypatch, capsys):
    """The suite's guard refuses a lookup of a real name, so the lookup fails
    here as an unknown name does, without asking a resolver."""

    def unknown(host, *args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, unknown)
    argv = ["replay", "-i", str(trace), "--to", "nobody.example:9", "--no-delay"]
    assert main(argv) == 1
    err = capsys.readouterr().err
    assert err.startswith("pktcap: error: ") and err.count("\n") == 1


def test_a_capture_cut_mid_record_sends_what_was_whole_then_is_status_2(
    tmp_path, listener, capsys
):
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(build.pcap([FIRST, THIRD, TCP])[:-10])
    assert main(["replay", "-i", str(cut), "--to", _to(listener), "--no-delay"]) == 2
    assert str(cut) in capsys.readouterr().err
    assert _received(listener, 2) == [b"first", b"third"]


def test_a_missing_file_is_status_1(tmp_path, listener, capsys):
    argv = ["replay", "-i", str(tmp_path / "none.pcap"), "--to", _to(listener)]
    assert main(argv) == 1
    assert "pktcap: error: " in capsys.readouterr().err


def test_the_source_port_is_the_one_asked_for(trace, listener):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    argv = ["replay", "-i", str(trace), "--to", _to(listener), "--no-delay"]
    assert main(argv + ["--source-port", str(port), "--limit", "1"]) == 0
    data, sender = listener.recvfrom(2048)
    assert data == b"first" and sender[1] == port


def test_broadcast_is_allowed_on_the_socket_asked_for(trace, listener, monkeypatch):
    options = []
    real = socket.socket.setsockopt

    def spy(self, level, name, value, *rest):
        options.append((level, name, value))
        return real(self, level, name, value, *rest)

    monkeypatch.setattr(socket.socket, "setsockopt", spy)
    argv = ["replay", "-i", str(trace), "--to", _to(listener), "--no-delay"]
    assert main(argv + ["--broadcast", "--limit", "1"]) == 0
    assert (socket.SOL_SOCKET, socket.SO_BROADCAST, 1) in options
    assert _received(listener, 1) == [b"first"]


@pytest.mark.skipif(not socket.has_ipv6, reason="this Python has no IPv6")
def test_an_ipv6_destination_is_written_in_brackets(trace):
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind(("::1", 0))
    except OSError:
        pytest.skip("this host has no IPv6 loopback address")
    with sock:
        sock.settimeout(5)
        to = "[::1]:%d" % sock.getsockname()[1]
        assert main(["replay", "-i", str(trace), "--to", to, "--no-delay"]) == 0
        assert _received(sock, 2) == [b"first", b"third"]


def test_a_capture_on_standard_input_is_replayed(trace, listener):
    done = subprocess.run(
        [sys.executable, "-m", "pktcap", "replay", "-i", "-", "--to", _to(listener)]
        + ["--no-delay"],
        input=trace.read_bytes(),
        capture_output=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.decode().strip() == "sent 2, partial 1"
    assert _received(listener, 2) == [b"first", b"third"]
