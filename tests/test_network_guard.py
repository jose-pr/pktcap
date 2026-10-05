"""The guard in ``conftest.py`` refuses what it says it refuses.

Each refusal is asserted by catching the failure the guard raises, so a guard
that stopped refusing would turn these red and not silently let the suite out.
"""

import socket

import pytest

_Refused = pytest.fail.Exception


def test_a_datagram_to_an_off_host_address_is_refused():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        with pytest.raises(_Refused, match="reached off-host"):
            sock.sendto(b"x", ("192.0.2.1", 9))


def test_a_connect_to_an_off_host_address_is_refused():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        with pytest.raises(_Refused, match="reached off-host"):
            sock.connect(("192.0.2.1", 9))


def test_a_lookup_of_a_real_name_is_refused():
    with pytest.raises(_Refused, match="reached off-host"):
        socket.getaddrinfo("example.com", 80)


def test_loopback_and_literals_pass():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"ping", receiver.getsockname())
        assert receiver.recvfrom(16)[0] == b"ping"
    assert socket.getaddrinfo("192.0.2.1", 80, type=socket.SOCK_DGRAM)
