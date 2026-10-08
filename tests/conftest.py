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


@pytest.fixture(autouse=True)
def _no_plugins_from_the_machine(monkeypatch):
    """No test depends on the plugins, or the configuration file, of the machine
    it runs on: a test that wants either sets them itself."""
    monkeypatch.delenv("PKTCAP_LOAD", raising=False)
    monkeypatch.setenv("PKTCAP_CONFIG", "none")


_PLUGIN_BODY = """\
import os
from typing import NamedTuple

import pktcap

# Imported once per process: a test in another process reads this file to see
# whether the module was imported at all.
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "marker.txt"), "a") as _marker:
    _marker.write("imported\\n")


class DemoLayer(NamedTuple):
    opcode: int
    name: str


def dissect(data):
    if len(data) < 2:
        raise ValueError("a demo packet is at least 2 octets")
    return pktcap.Dissected(DemoLayer(data[0], data[1:].decode("ascii", "replace")), b"")


def pktcap_plugin(registry):
    registry.register_layer(DemoLayer, name="demo")
    registry.register("udp", 9999, dissect)
"""


class PluginModule:
    """A plugin module a test wrote: its name, its directory and its marker."""

    def __init__(self, name, directory):
        self.name = name
        self.directory = directory
        self.path = directory / (name + ".py")
        self.marker = directory / "marker.txt"

    @property
    def imported(self):
        return self.marker.exists() and self.marker.read_text() != ""


@pytest.fixture
def plugin_module(tmp_path, monkeypatch):
    """Write plugin modules under unique names into a temporary directory that
    is on ``sys.path``, and take them out of ``sys.modules`` afterwards.

    ``make(body=None)`` returns a :class:`PluginModule`; ``body`` replaces the
    default one, which registers a ``demo`` layer and a dissector on UDP 9999
    and appends a line to ``marker.txt`` beside the file when imported.
    """
    import importlib
    import sys
    import uuid

    directory = tmp_path / ("plugins-" + uuid.uuid4().hex[:8])
    directory.mkdir()
    monkeypatch.syspath_prepend(str(directory))
    names = []

    def make(body=None, *, name=None):
        name = name or "pktcap_demo_" + uuid.uuid4().hex[:10]
        text = body if body is not None else _PLUGIN_BODY
        (directory / (name + ".py")).write_bytes(text.encode("utf-8"))
        names.append(name)
        importlib.invalidate_caches()  # the finder has listed this directory already
        return PluginModule(name, directory)

    yield make
    for loaded in list(sys.modules):
        if any(loaded == n or loaded.startswith(n + ".") for n in names):
            del sys.modules[loaded]
