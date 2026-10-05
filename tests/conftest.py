"""Suite-wide fixtures: nothing a test does may leave this host.

An autouse fixture refuses, at the point of the call and naming the test, a
``connect`` or ``sendto`` to an address that is not loopback, and a name lookup
of anything but a literal or ``localhost``. A replay test sends to loopback
sockets the test owns; one that reached further would be a defect here, not a
network problem to retry.
"""

import ipaddress
import socket

import pytest

_LOOKUPS = ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr")
_SENDERS = ("connect", "connect_ex", "sendto")


def _is_loopback(host):
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if host in (None, "", "localhost"):
        return True
    try:
        address = ipaddress.ip_address(str(host).split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return (mapped or address).is_loopback


def _is_literal(host):
    try:
        ipaddress.ip_address(str(host).split("%", 1)[0])
    except ValueError:
        return False
    return True


@pytest.fixture(autouse=True)
def _nothing_leaves_the_host(request, monkeypatch):
    """Fail a test that sends off-host or asks a resolver about a real name."""
    test = request.node.nodeid

    def refuse(what):
        pytest.fail("%s reached off-host: %s" % (test, what), pytrace=True)

    for name in _LOOKUPS:
        real = getattr(socket, name)

        def lookup(host, *args, _real=real, _name=name, **kwargs):
            if not (_is_loopback(host) or _is_literal(host)):
                refuse("%s(%r)" % (_name, host))
            return _real(host, *args, **kwargs)

        monkeypatch.setattr(socket, name, lookup)

    for name in _SENDERS:
        real = getattr(socket.socket, name)

        def sender(self, *args, _real=real, _name=name, **kwargs):
            address = args[-1] if args else kwargs.get("address")
            if self.family in (socket.AF_INET, socket.AF_INET6) and isinstance(
                address, tuple
            ):
                if not _is_loopback(address[0]):
                    refuse("%s to %r" % (_name, address))
            return _real(self, *args, **kwargs)

        monkeypatch.setattr(socket.socket, name, sender)
