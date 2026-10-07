"""``pktcap capture`` in three tiers.

Everywhere: the refusal off Linux. With the privileged socket stood in for by
``test_live.py``'s fixture (the one place that patches it): every option of
the command. For real, as root on Linux: a datagram sent to loopback.
"""

import json
import socket
import threading
import time

import pytest

pytest.importorskip("duho")

import captures as build  # noqa: E402
from pktcap import LiveCapture, has_live_capture, read_frames  # noqa: E402
from pktcap.cli import main  # noqa: E402
from test_live import V4, V6, _read, packet_socket  # noqa: E402,F401

ARP = (bytes(28), 0x0806)


def _records(text):
    return [json.loads(line) for line in text.splitlines()]


def test_off_linux_the_command_says_how_to_pipe_a_capture_in(monkeypatch, capsys):
    if has_live_capture():  # on Linux, stand in for a platform without it
        monkeypatch.setattr("pktcap._live._AF_PACKET", None)
    assert main(["capture", "--count", "1"]) == 1
    out, err = capsys.readouterr()
    assert out == "" and err.count("\n") == 1
    assert err.startswith("pktcap: error: ")
    assert "tcpdump -w - | pktcap convert --input -" in err


def test_off_linux_nothing_is_created(monkeypatch, tmp_path):
    monkeypatch.setattr("pktcap._live._AF_PACKET", None)
    out = tmp_path / "out.pcapng"
    assert main(["capture", "-o", str(out)]) == 1
    assert list(tmp_path.iterdir()) == []


def test_count_records_are_written_and_the_command_returns_0(packet_socket, capsys):
    fake = packet_socket(
        _read(V4, 0x0800), _read(*ARP), _read(V6, 0x86DD), _read(V4, 0x0800)
    )
    assert main(["capture", "--count", "2", "--format", "json"]) == 0
    out, err = capsys.readouterr()
    records = _records(out)
    assert len(records) == 2
    assert [layer["layer"] for layer in records[0]["layers"]] == [
        "linuxcooked",
        "ipv4",
        "udp",
    ]
    assert [layer["layer"] for layer in records[1]["layers"]] == ["linuxcooked"]
    assert err.strip() == "2 frames read, 2 written"
    assert fake.closed and len(fake.reads) == 2


def test_the_filter_and_the_datagram_view_choose_what_is_written(packet_socket, capsys):
    fake = packet_socket(
        _read(V4, 0x0800), _read(*ARP), _read(V6, 0x86DD), _read(V4, 0x0800)
    )
    argv = ["capture", "--count", "2", "--datagrams", "-f", "src=10.0.0.5"]
    assert main(argv) == 0
    out, err = capsys.readouterr()
    assert [r["source"] for r in _records(out)] == ["10.0.0.5:50000"] * 2
    assert err.strip() == "4 frames read, 2 written, 2 skipped"
    assert fake.closed and fake.reads == []


def test_a_capture_is_written_to_the_file_named_and_read_back(packet_socket, tmp_path):
    packet_socket(_read(V4, 0x0800), _read(*ARP))
    out = tmp_path / "live.pcapng"
    assert main(["capture", "--count", "2", "-o", str(out)]) == 0
    frames = list(read_frames(out))
    assert [f.linktype for f in frames] == [276, 276]
    assert frames[0].data.endswith(V4) and frames[1].data.endswith(ARP[0])


def test_a_quiet_capture_ends_within_a_second_of_its_duration(packet_socket, capsys):
    packet_socket()
    started = time.monotonic()
    assert main(["capture", "--duration", "0.3"]) == 0
    elapsed = time.monotonic() - started
    assert 0.3 <= elapsed < 1.3, elapsed
    assert capsys.readouterr().err.strip() == "0 frames read, 0 written"


def test_a_negative_duration_is_a_usage_error(packet_socket, capsys):
    assert main(["capture", "--duration", "-1"]) == 2
    assert "--duration" in capsys.readouterr().err


def test_ctrl_c_ends_the_capture_with_status_0_and_the_summary(packet_socket, capsys):
    fake = packet_socket(_read(V4, 0x0800), _read(*ARP), _read(V4, 0x0800))
    real = fake.recvfrom

    def interrupted(size):
        if not fake.reads:
            raise KeyboardInterrupt
        return real(size)

    fake.recvfrom = interrupted
    assert main(["capture", "-f", "proto=udp"]) == 0
    out, err = capsys.readouterr()
    assert len(_records(out)) == 2
    assert err.strip() == "3 frames read, 2 written, 1 skipped"
    assert fake.closed


def test_a_process_without_the_capability_gets_one_line_naming_it(
    packet_socket, capsys
):
    fake = packet_socket()

    def refused(size):
        raise PermissionError(1, "Operation not permitted")

    fake.recvfrom = refused
    assert main(["capture"]) == 1
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "CAP_NET_RAW" in err


def test_an_interface_that_does_not_exist_is_a_usage_error(packet_socket, capsys):
    assert main(["capture", "--interface", "no-such-interface-0"]) == 2
    assert "no interface matches" in capsys.readouterr().err
    assert packet_socket.opened == []


def test_capture_octets_to_a_terminal_are_refused_before_the_socket_opens(
    packet_socket, monkeypatch, capsys
):
    class Terminal:
        buffer = None

        def isatty(self):
            return True

    import sys

    monkeypatch.setattr(sys, "stdout", Terminal())
    assert main(["capture", "--format", "pcap"]) == 2
    assert "--output" in capsys.readouterr().err
    assert packet_socket.opened == []


def test_the_command_sends_nothing(packet_socket, monkeypatch):
    sent = []
    monkeypatch.setattr(
        socket.socket, "sendto", lambda self, *a, **k: sent.append(a) or 0
    )
    packet_socket(_read(V4, 0x0800))
    assert main(["capture", "--count", "1"]) == 0
    assert sent == []


# -- the real socket ------------------------------------------------------


def test_the_real_command_records_a_datagram_sent_on_loopback(tmp_path):
    """Nothing is replaced: as root on Linux, ``capture`` on ``lo`` records the
    one datagram this test sends there."""
    if not has_live_capture():
        pytest.skip("this platform has no AF_PACKET: live capture is Linux only")
    try:
        with LiveCapture("lo"):
            pass
    except PermissionError:
        pytest.skip("opening AF_PACKET needs CAP_NET_RAW: run as root to cover it")
    except ValueError:
        pytest.skip("this host has no interface named lo")
    payload = b"pktcap capture command %d" % time.time_ns()
    out = tmp_path / "seen.json"
    done = threading.Event()

    def send():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            while not done.is_set():
                sender.sendto(payload, ("127.0.0.1", 9))
                done.wait(0.1)

    thread = threading.Thread(target=send)
    thread.start()
    try:
        status = main(
            ["capture", "--interface", "lo", "--count", "1", "--duration", "15"]
            + ["--filter", "proto=udp and dport=9", "--datagrams", "-o", str(out)]
        )
    finally:
        done.set()
        thread.join()
    assert status == 0
    (record,) = _records(out.read_text("ascii"))
    assert record["payload"] == payload.hex()
    assert record["destination"] == "127.0.0.1:9"
