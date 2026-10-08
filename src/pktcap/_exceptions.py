"""Every exception the package raises on its own account (internal).

:class:`PktcapError` is the one base: a caller who wants "anything pktcap
reported" catches it. Each class also inherits the builtin a caller would
already catch for that kind of failure, so existing ``except`` clauses keep
working.

A caller's own mistake, such as a bad option or a wrong argument type, is not
here: it raises plain :class:`ValueError` or :class:`TypeError`.

Re-exported from :mod:`pktcap`.
"""

from __future__ import annotations

from typing import Any, Optional, Tuple

__all__ = [
    "PktcapError",
    "CaptureFormatError",
    "CaptureFilterError",
    "UnsupportedFormatError",
    "MissingExtraError",
    "LiveCaptureError",
    "DissectError",
    "CapturePluginError",
    "CaptureConfigError",
]


class PktcapError(Exception):
    """The base of every exception pktcap raises on its own account."""


class CaptureFormatError(PktcapError, ValueError):
    """The input is not a pcap or pcapng capture, or it is a damaged one.

    The one type every malformed container raises: a wrong magic number, a
    record or block cut short, a length over its ceiling, a block that
    contradicts itself. The message never quotes the file.

    :ivar offset: how many octets of the input had been read when the problem
        was found, or ``None`` when that is not known.
    """

    def __init__(self, message: str, *, offset: Optional[int] = None) -> None:
        if offset is not None:
            message = "%s (at octet %d)" % (message, offset)
        super().__init__(message)
        self.offset = offset


class CaptureFilterError(PktcapError, ValueError):
    """A capture-filter expression that cannot be compiled.

    Raised when the filter is parsed or compiled, never while it is applied:
    a clause that is not ``key=value``, an ``or``, or a key or value that the
    protocol library's own builder refused (its ``ValueError`` is chained).
    """


class UnsupportedFormatError(PktcapError, ValueError):
    """No output format of that name, or none can be told from a file name.

    The message lists the formats there are. A format that exists and whose
    extra is not installed is not this error: it raises
    :class:`MissingExtraError`.
    """


def _restore_missing_extra(
    message: str, format: str, extra: str
) -> "MissingExtraError":
    return MissingExtraError(message, format=format, extra=extra)


class MissingExtraError(PktcapError, ImportError):
    """An output format whose optional dependency is not installed.

    An :class:`ImportError`, so ``except ImportError`` still catches it. The
    message names the extra to install; a caller that offers the format under
    its own extra words its own message from the attributes.

    :ivar format: the format's name, as in ``OUTPUT_FORMATS`` (``"toml"``).
    :ivar extra: pktcap's extra that installs what the format needs.
    """

    def __init__(self, message: str, *, format: str, extra: str) -> None:
        super().__init__(message)
        self.format = format
        self.extra = extra

    def __reduce__(self) -> Tuple[Any, ...]:
        return (_restore_missing_extra, (self.args[0], self.format, self.extra))


class DissectError(PktcapError, ValueError):
    """Octets that are not the layer a dissector was asked to read: a header
    cut short, or one whose length fields contradict what is there.

    What the built-in dissectors raise. It never reaches a caller of
    :meth:`pktcap.FrameDissector.dissect`, which keeps the frame, leaves that
    layer undecoded and counts it; a caller that runs a dissector by hand
    catches it. A dissector of the caller's own may raise any ``ValueError``.
    """


class LiveCaptureError(PktcapError, OSError):
    """This platform cannot capture live: it has no ``AF_PACKET``.

    An :class:`OSError`, as the failure to open any other socket is. A process
    that lacks the capability gets the kernel's own ``PermissionError``, which
    is not this class.
    """


def _restore_plugin_error(
    message: str, plugin: str, source: str
) -> "CapturePluginError":
    return CapturePluginError(message, plugin=plugin, source=source)


class CapturePluginError(PktcapError, ValueError):
    """A plugin the user named cannot be loaded.

    Raised for a name that is no module, a module whose import failed, a
    module with no ``pktcap_plugin`` hook, a hook that takes no registry or
    raised, and an item of a list from the environment or the configuration
    file that is no dotted Python name. The registry is left as it was before
    the call. A malformed item passed as an argument is a plain
    ``ValueError`` instead.

    :ivar plugin: the item as written.
    :ivar source: where the list came from: ``"argument"``,
        ``"PKTCAP_LOAD"`` or the configuration file's path.
    """

    def __init__(self, message: str, *, plugin: str, source: str) -> None:
        super().__init__(message)
        self.plugin = plugin
        self.source = source

    def __reduce__(self) -> Tuple[Any, ...]:
        return (_restore_plugin_error, (self.args[0], self.plugin, self.source))


def _restore_config_error(
    message: str, path: Optional[str], lineno: Optional[int]
) -> "CaptureConfigError":
    return CaptureConfigError(message, path=path, lineno=lineno)


class CaptureConfigError(PktcapError, ValueError):
    """The configuration file, or ``PKTCAP_CONFIG``, cannot be used.

    The message is ``PATH:LINE: problem`` and never holds a line of the file.

    :ivar path: the file's path, or ``None`` when the problem is not a file's.
    :ivar lineno: the 1-based line of the problem, or ``None`` when the parser
        keeps none (an unknown section or key).
    """

    def __init__(
        self,
        message: str,
        *,
        path: Optional[str] = None,
        lineno: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.path = path
        self.lineno = lineno

    def __reduce__(self) -> Tuple[Any, ...]:
        return (_restore_config_error, (self.args[0], self.path, self.lineno))
