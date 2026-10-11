"""The plugin list from a variable and a file, until the root reads settings.

Resolves ``--load``, ``PKTCAP_LOAD`` and the ``load`` key of ``[pktcap]`` in
the file ``--config``, ``PKTCAP_CONFIG`` or the user's own names, and hands the
list to the library, which reads neither.
"""

from __future__ import annotations

import configparser
import os
import pathlib
from typing import Iterable, List, Optional, Tuple, Union

from .._dissectors import DissectorRegistry
from .._plugins._config import PLUGINS_ARGUMENT, named_list
from .._plugins._load import LoadedPlugin, load_named
from ._settings import SettingsError, default_path, read_octets

__all__ = ["capture_config_path", "load_configured"]

PLUGINS_VARIABLE = "PKTCAP_LOAD"
CONFIG_VARIABLE = "PKTCAP_CONFIG"
_SECTION = "pktcap"
_KEY = "load"
#: A section name no file can write, so a ``[DEFAULT]`` section is an ordinary
#: unknown one and not configparser's inherited defaults.
_NO_DEFAULT_SECTION = "\x00"


def _shown(text: str) -> str:
    return repr(text if len(text) <= 40 else text[:40] + "...")


def _is_none(text: object) -> bool:
    return isinstance(text, str) and text.strip().lower() == "none"


def _target(config: object) -> Tuple[Optional[pathlib.Path], bool]:
    """``(path, named)``: the file that applies, and whether the user named it."""
    if config is not None:
        if not isinstance(config, (str, os.PathLike)):
            raise TypeError("config is a path, or 'none'")
        if _is_none(config):
            return None, True
        return pathlib.Path(config), True
    text = os.environ.get(CONFIG_VARIABLE, "")
    if text.strip():
        if _is_none(text):
            return None, True
        if not os.path.isabs(text):
            raise SettingsError(
                None,
                None,
                "%s must be an absolute path or none: a variable outlives the "
                "directory it was set in" % CONFIG_VARIABLE,
            )
        return pathlib.Path(text), True
    return default_path(), False


def capture_config_path(config: object = None) -> Optional[pathlib.Path]:
    """The file that applies, opening nothing."""
    return _target(config)[0]


def _plugins_text(raw: bytes, path: pathlib.Path) -> Optional[str]:
    """The value of ``load`` in ``[pktcap]``, or ``None``; any other section
    or key is an error."""
    name = str(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SettingsError(name, None, "not UTF-8 (at octet %d)" % exc.start) from None
    if text.startswith("﻿"):
        text = text[1:]
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=True,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
        inline_comment_prefixes=None,
        empty_lines_in_values=False,
        default_section=_NO_DEFAULT_SECTION,
    )
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    try:
        parser.read_string(text, source=name)
    except configparser.MissingSectionHeaderError as exc:
        raise SettingsError(name, exc.lineno, "text before the first section") from None
    except configparser.ParsingError as exc:
        errors = getattr(exc, "errors", None) or [(None, "")]
        raise SettingsError(
            name, errors[0][0], "not a section header, a comment or a key = value line"
        ) from None
    except configparser.DuplicateSectionError as exc:
        raise SettingsError(name, exc.lineno, "a section written twice") from None
    except configparser.DuplicateOptionError as exc:
        raise SettingsError(name, exc.lineno, "a key written twice") from None
    except configparser.Error:
        raise SettingsError(name, None, "not a configuration file") from None
    for section in parser.sections():
        if section != _SECTION:
            raise SettingsError(
                name,
                None,
                "unknown section %s: the file has [pktcap] only" % _shown(section),
            )
        for key in parser.options(section):
            if key != _KEY:
                raise SettingsError(
                    name,
                    None,
                    "unknown key %s in [pktcap]: the only key is load" % _shown(key),
                )
    return parser.get(_SECTION, _KEY) if parser.has_option(_SECTION, _KEY) else None


def _file_items(path: Optional[pathlib.Path], named: bool) -> Optional[List[str]]:
    if path is None:
        return None
    raw = read_octets(path, named)
    if raw is None:
        return None
    text = _plugins_text(raw, path)
    if text is None or not text.strip():
        return None
    return named_list(text, str(path))


def load_configured(
    registry: DissectorRegistry,
    plugins: Union[None, str, Iterable[str]] = None,
    *,
    config: object = None,
    always: Union[str, Iterable[str]] = (),
) -> Tuple[LoadedPlugin, ...]:
    """Load the first list that names one: ``plugins``, ``PKTCAP_LOAD``, the
    file. A file named by ``config`` is read and checked even when a higher
    source names the list; any other file is opened only when asked for."""
    path: Optional[pathlib.Path] = None
    named = False
    from_file: Optional[List[str]] = None
    early = config is not None
    if early:
        path, named = _target(config)
        from_file = _file_items(path, named)
    items: Union[None, str, Iterable[str]] = plugins
    source = PLUGINS_ARGUMENT
    if plugins is None:
        text = os.environ.get(PLUGINS_VARIABLE, "")
        if text.strip():
            items, source = text, PLUGINS_VARIABLE
        else:
            if not early:
                path, named = _target(None)
                from_file = _file_items(path, named)
            if from_file is not None and path is not None:
                items, source = from_file, str(path)
    return load_named(registry, items, source, always)
