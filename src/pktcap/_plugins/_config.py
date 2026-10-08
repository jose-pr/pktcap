"""Where a plugin list comes from (internal): an argument, ``PKTCAP_LOAD``,
or the configuration file, in that order.

This is the one module that reads the environment, and only when asked, never
at import: for a list, or for the copy a hook command's process starts from
(:func:`process_environment`). A list is read from these three places and from
no other: not the working directory, not a file found by walking up from it,
and nothing a capture holds.
"""

from __future__ import annotations

import configparser
import os
import pathlib
import re
import stat
from typing import Dict, Iterable, List, Optional, Tuple, Union

from .._exceptions import CaptureConfigError, CapturePluginError

__all__ = [
    "ConfigArgument",
    "PLUGINS_ARGUMENT",
    "capture_config_path",
    "describe",
    "plugin_list",
    "process_environment",
]

PLUGINS_VARIABLE = "PKTCAP_LOAD"
CONFIG_VARIABLE = "PKTCAP_CONFIG"
#: The source of a list given as an argument.
PLUGINS_ARGUMENT = "argument"

ConfigArgument = Union[str, "os.PathLike[str]"]

#: The most octets read from a configuration file.
_MAX_CONFIG_OCTETS = 65536
#: The most items in a list, and the most characters in one.
_MAX_ITEMS = 64
_MAX_ITEM_LENGTH = 255
_SEPARATORS = re.compile(r"[,;:\s]+")
_DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
#: A section name no file can write, so a ``[DEFAULT]`` section is an ordinary
#: unknown one and not configparser's inherited defaults.
_NO_DEFAULT_SECTION = "\x00"
_SECTION = "pktcap"
_KEY = "load"


def process_environment() -> Dict[str, str]:
    """A copy of this process's environment, for a child process to start from."""
    return dict(os.environ)


def describe(source: str) -> str:
    """How an error names the source of a list."""
    if source == PLUGINS_ARGUMENT:
        return "the plugins argument"
    return source


def _shown(text: str) -> str:
    """``text`` as one short quoted line: a name from a file is bounded and
    its control characters escaped."""
    return repr(text if len(text) <= 40 else text[:40] + "...")


def _is_none(text: object) -> bool:
    return isinstance(text, str) and text.strip().lower() == "none"


def _fail(
    path: Optional[str], lineno: Optional[int], problem: str
) -> CaptureConfigError:
    if path is None:
        message = problem
    elif lineno is None:
        message = "%s: %s" % (path, problem)
    else:
        message = "%s:%d: %s" % (path, lineno, problem)
    return CaptureConfigError(message, path=path, lineno=lineno)


# -- where the file is --------------------------------------------------------


def _home() -> Optional[str]:
    home = os.path.expanduser("~")
    return None if home == "~" else home


def _default_path() -> Optional[pathlib.Path]:
    """``pktcap/pktcap.ini`` under the user's configuration directory: a
    relative ``APPDATA`` or ``XDG_CONFIG_HOME`` is ignored, so neither can
    point into the working directory."""
    if os.name == "nt":
        base = os.environ.get("APPDATA", "")
        if not os.path.isabs(base):
            home = _home()
            if home is None:
                return None
            base = os.path.join(home, "AppData", "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME", "")
        if not os.path.isabs(base):
            home = _home()
            if home is None:
                return None
            base = os.path.join(home, ".config")
    return pathlib.Path(base) / "pktcap" / "pktcap.ini"


def _target(config: Optional[ConfigArgument]) -> Tuple[Optional[pathlib.Path], bool]:
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
            raise _fail(
                None,
                None,
                "%s must be an absolute path or none: a variable outlives the "
                "directory it was set in" % CONFIG_VARIABLE,
            )
        return pathlib.Path(text), True
    return _default_path(), False


def capture_config_path(
    config: Optional[ConfigArgument] = None,
) -> Optional[pathlib.Path]:
    """The configuration file that applies, opening nothing: ``config`` when
    given, else ``PKTCAP_CONFIG``, else the user's own. ``None`` for ``none``
    and for a platform that gives no home."""
    return _target(config)[0]


# -- reading it ---------------------------------------------------------------


def _read_octets(path: pathlib.Path, named: bool) -> Optional[bytes]:
    """The file's octets, or ``None`` when the default file is absent. The
    file found by default is checked on POSIX: it must be the user's own or
    root's, and not writable by everyone, since a run as root must not import
    what another user's file names. A file the user named is read as it is."""
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except (FileNotFoundError, NotADirectoryError):
        if named:
            raise
        return None
    try:
        info = os.fstat(descriptor)
        owner = getattr(os, "geteuid", None)
        if not named and owner is not None:
            if not stat.S_ISREG(info.st_mode):
                raise _fail(str(path), None, "not read: it is not a regular file")
            if info.st_uid not in (owner(), 0):
                raise _fail(
                    str(path),
                    None,
                    "not read: another user owns it (name it with --config to read it)",
                )
            if info.st_mode & stat.S_IWOTH:
                raise _fail(
                    str(path),
                    None,
                    "not read: everyone may write it (name it with --config to read it)",
                )
        chunks: List[bytes] = []
        total = 0
        while total <= _MAX_CONFIG_OCTETS:
            chunk = os.read(descriptor, _MAX_CONFIG_OCTETS + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    if total > _MAX_CONFIG_OCTETS:
        raise _fail(str(path), None, "over %d octets" % _MAX_CONFIG_OCTETS)
    return b"".join(chunks)


def _plugins_text(raw: bytes, path: pathlib.Path) -> Optional[str]:
    """The value of ``plugins`` in ``[pktcap]``, or ``None`` when it is not
    there. Any other section or key is an error."""
    name = str(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fail(name, None, "not UTF-8 (at octet %d)" % exc.start) from None
    if text.startswith("\ufeff"):
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
        raise _fail(name, exc.lineno, "text before the first section") from None
    except configparser.ParsingError as exc:
        errors = getattr(exc, "errors", None) or [(None, "")]
        raise _fail(
            name, errors[0][0], "not a section header, a comment or a key = value line"
        ) from None
    except configparser.DuplicateSectionError as exc:
        raise _fail(name, exc.lineno, "a section written twice") from None
    except configparser.DuplicateOptionError as exc:
        raise _fail(name, exc.lineno, "a key written twice") from None
    except configparser.Error:
        raise _fail(name, None, "not a configuration file") from None
    for section in parser.sections():
        if section != _SECTION:
            raise _fail(
                name,
                None,
                "unknown section %s: the file has [%s] only"
                % (_shown(section), _SECTION),
            )
        for key in parser.options(section):
            if key != _KEY:
                raise _fail(
                    name,
                    None,
                    "unknown key %s in [%s]: the only key is %s"
                    % (_shown(key), _SECTION, _KEY),
                )
    if not parser.has_option(_SECTION, _KEY):
        return None
    return parser.get(_SECTION, _KEY)


# -- the list -----------------------------------------------------------------


def _items(texts: Iterable[str]) -> List[str]:
    items: List[str] = []
    for text in texts:
        items.extend(part for part in _SEPARATORS.split(text) if part)
    if len(items) == 1 and items[0].lower() == "none":
        return []
    return items


def _problem(item: str, source: str, problem: str) -> CapturePluginError:
    return CapturePluginError(
        "%s names %s: %s" % (describe(source), _shown(item), problem),
        plugin=item,
        source=source,
    )


def _checked(items: List[str], source: str) -> List[str]:
    """Each item is a dotted Python name, at most 64 items and none twice,
    before anything is imported: a path or a relative name never reaches the
    import system. An argument's mistake is a plain ``ValueError``."""
    seen = set()
    for index, item in enumerate(items):
        if index >= _MAX_ITEMS:
            problem = "more than %d plugins" % _MAX_ITEMS
        elif len(item) > _MAX_ITEM_LENGTH or not _DOTTED_NAME.match(item):
            problem = (
                "not a dotted Python name of at most %d characters" % _MAX_ITEM_LENGTH
            )
        elif item in seen:
            problem = "named twice"
        else:
            seen.add(item)
            continue
        error = _problem(item, source, problem)
        if source == PLUGINS_ARGUMENT:
            raise ValueError(str(error))
        raise error
    return items


def _argument_items(plugins: Union[str, Iterable[str]]) -> List[str]:
    if isinstance(plugins, str):
        return _items([plugins])
    texts = list(plugins)
    if not all(isinstance(text, str) for text in texts):
        raise TypeError("plugins is a text or an iterable of texts")
    return _items(texts)


def plugin_list(
    plugins: Union[None, str, Iterable[str]], config: Optional[ConfigArgument]
) -> Tuple[List[str], str]:
    """``(items, source)``: the first source that names a list is the list.

    A file named by the ``config`` argument is read and checked even when a
    higher source names the list; any other file is opened only when it is
    asked for.
    """
    path: Optional[pathlib.Path] = None
    named = False
    from_file: Optional[List[str]] = None
    read_early = config is not None
    if read_early:
        path, named = _target(config)
        from_file = _file_items(path, named)
    if plugins is not None:
        return _checked(_argument_items(plugins), PLUGINS_ARGUMENT), PLUGINS_ARGUMENT
    text = os.environ.get(PLUGINS_VARIABLE, "")
    if text.strip():
        return _checked(_items([text]), PLUGINS_VARIABLE), PLUGINS_VARIABLE
    if not read_early:
        path, named = _target(None)
        from_file = _file_items(path, named)
    if from_file is not None and path is not None:
        return from_file, str(path)
    return [], ""


def _file_items(path: Optional[pathlib.Path], named: bool) -> Optional[List[str]]:
    if path is None:
        return None
    raw = _read_octets(path, named)
    if raw is None:
        return None
    text = _plugins_text(raw, path)
    if text is None or not text.strip():
        return None
    return _checked(_items([text]), str(path))
