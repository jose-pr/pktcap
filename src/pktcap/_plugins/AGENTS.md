# `pktcap` plugins — public API header

Header-file-style reference for protocol plugins in the `pktcap` package: the
layers and filter keys a registry holds for a protocol, the rule by which a
filter reads a layer's fields, and what a filter refuses. It ships inside the
package and is self-contained; the top header is `pktcap/AGENTS.md`.
Development documentation lives with the source at
<https://github.com/jose-pr/pktcap>.

This directory (`pktcap/_plugins/`) is private and not an import path: every
name below is imported from `pktcap`.

## Layers and filter keys

A dissector returns a **layer record** (`Dissected.layer`). Declaring the
record's class in a registry lets a filter name the layer and read its fields,
and an error in the filter is raised when it is compiled, never per packet.

- **`DissectorRegistry.register_layer(layer, *, name=None, keys=None, replace=False) -> None`**
  — declare the class `layer` (`TypeError` for anything else). `name` is how a
  filter calls it: lower case, `[a-z][a-z0-9_]*`; omitted, the class name in
  lower case without a trailing `Layer`, the rule `proto=` and `frame_record`
  use (`TFTPLayer` is `tftp`). `ValueError` for an invalid name, for a name
  that is taken unless `replace=True`, and always for the name of a built-in
  layer: `ethernet`, `vlan`, `linuxcooked`, `loopback`, `ipv4`, `ipv6`,
  `ipv6extension`, `ipv6fragment`, `udp`, `tcp`.
- A layer class may have a method **`summary() -> str`**: one line saying what
  the layer holds, which `frame_summary` and the `text` output use for a frame
  whose innermost layer it is. A layer without one is described by its name
  (`pktcap/_formats/AGENTS.md`).
- `keys` maps a key name (`[a-z][a-z0-9_-]*`, no dot) to `build(clause)`,
  called once per clause when the filter is compiled. `clause.key` is the key
  without the layer's name: lower case up to its first dot and as written
  after it (`msg_type`, `option.HOST_NAME`); `clause.negated` is for the
  caller to ignore, the filter inverts the result. `build` raises `ValueError`
  for a value that can never match, and returns a test of **one layer record**,
  never of the frame. A `build` that returns something not callable is a
  `TypeError`.
- **`DissectorRegistry.unregister_layer(name) -> None`** — forget a
  registered layer and its keys; `ValueError` for a name that is none.
- **`DissectorRegistry.layers() -> Dict[str, type]`** — a copy of the
  registered layers by name, the built-in ones not among them.
  `DissectorRegistry.copy()` carries layers and keys.

A registered test that raises is false for that layer, and logged once per key
at `WARNING` on the logger `pktcap._plugins._keys`, for the first eight keys.

## Filtering by layer

**`frame_filter_for(registry) -> Callable[[FilterClause], Callable[[DissectedFrame], bool]]`**
— the `build` for `compile_capture_filter` that knows the registry's layers
and keys beside the built-in ones. `TypeError` for anything but a registry.
**`frame_filter` reads no registry**, the default one included, so what
another library registered never changes what a filter means: a caller with a
registry of its own passes `frame_filter_for(registry)`.

**`frame_filter_keys(registry=None) -> Tuple[str, ...]`** — every key that
compiles, sorted: the nine built-in ones, each `LAYER.KEY` and `LAYER.FIELD`
of the built-in layers and of the registry's, and the bare form of a
registered key that exactly one layer has. `None` lists the built-in layers
alone.

How a clause's key is read, in this order. The key is split on `.`, at most 8
segments, none empty, and its first segment compared in lower case.

1. The whole key is one of `FRAME_FILTER_KEYS`: the built-in key, always. No
   plugin changes what `port=` means; a registered key named like one is
   reached as `LAYER.port`.
2. The first segment names a layer, built-in or registered: the second is a
   registered key of that layer, else a field of its class (a named tuple's
   `_fields`; a class without them has its registered keys only), else
   `ValueError` listing the layer's keys and fields. A layer's name alone is a
   `ValueError`. A registered key named like a field replaces the rule for
   that field; a layer named like a built-in key (`host`) is no conflict, the
   bare word being the key and the dotted one the layer.
3. Otherwise the bare form: exactly one registered layer has a key of that
   name, else `ValueError`: `op is ambiguous: write dhcp.op or tftp.op` (the
   same whatever order the layers were registered in), or `unknown filter key
   'colour'` followed by the built-in keys, the bare registered keys and the
   layer names, 32 names at most and then `...`.

The clause holds when any layer of the class in the frame passes; a frame with
none fails it, so `!=` holds. `proto=NAME` for a name no layer has still
compiles and matches nothing.

### How a field is compared

By the type of the value the field holds in the frame. A comma in the clause's
value means "any of". The first row that fits is the rule:

| The field's value | The clause's text matches when |
| --- | --- |
| `bool` | it is `1`, `true`, `yes`, `on` or `0`, `false`, `no`, `off`, in any case, and is that value |
| `enum.Enum` | it is the member's name in any case, or its value by this table |
| `int` | it is that number: decimal (leading zeros allowed) or with `0x`, `0o`, `0b`; at most 64 characters |
| `str` | it is equal ignoring case; or it is an address or network (`10.0.0.0/8`) and the field, 64 characters at most, parses as an address inside it, a v4-mapped one as its IPv4 host |
| `bytes` | it is hexadecimal, `:`, `-` or `.` allowed between groups of two digits, of the same octets |
| a mapping | never by itself: the key goes on as a path (`dhcp.message.giaddr`), each segment a key of the mapping, exact and else ignoring case among its first 1,024 keys |
| a list or tuple | a numeric segment indexes it; with no segment left, any of its first 1,024 items that is no list, tuple or mapping matches |
| `None` | never, so `!=` holds |
| anything else | its `str()` equals the text, ignoring case |

### What is refused when the filter is compiled

Each is a `ValueError` the grammar turns into `CaptureFilterError` naming the
clause: an unknown layer, key or field (with what there is), a layer name with
no key, a key of more than 8 segments or with an empty one, an ambiguous bare
key, and, where the field's annotation (`Optional` removed) is exactly `int`,
`bool` or `bytes`, a value that is not one: `ipv4.ttl takes an integer, not
'abc'`. Annotations that do not resolve, or name more than one type, refuse
nothing. Nothing a capture holds is evaluated, imported or formatted into a
path: a field's value only ever meets the text of the filter.

## Loading plugins

A **plugin** is a module, or a callable in one, that registers a protocol
library's dissector and its layer's filter keys into a registry the caller
owns. A user names the plugins to load; nothing is loaded because it is
installed.

**`load_plugins(registry, plugins=None, *, config=None, always=()) -> Tuple[LoadedPlugin, ...]`**
— import the modules a list names and call each one's hook with `registry`.
There is no default registry, so a run changes nothing outside the one it is
given. Each result is a **`LoadedPlugin(name, source, selectors, layers)`**: the
item as written, where the list came from (`"argument"`, `"PKTCAP_LOAD"`, the
file's path, or `"always"`), the selectors its hook registered a dissector under and the
names of the layers it declared. Each plugin loaded is logged at `INFO`.

- `plugins` is `None` (the list as configured, below), one text, or an
  iterable of texts. Given, it is the list and neither the variable nor a
  default file is read.
- `config` is `None`, the path of a configuration file, or `none`. A file named
  here is read and checked even when `plugins` names the list.
- `always` is a text or an iterable of texts, written as `plugins`, for a
  command that needs its own protocol's plugin whatever the user listed. Its
  items load **first**, source `"always"`, and are checked as an argument is (a
  mistake is a `ValueError`). **They come from the caller's code and never
  from the variable or the file**, which still decide the user's list: with
  `PKTCAP_LOAD=none` the `always` items load and nothing else does. An item of
  the user's list that resolves to the same hook callable as one of `always`
  (the module and `MODULE.pktcap_plugin` are one callable) is **skipped**, not
  loaded twice and not an error, and is not in the result; a different callable
  that claims a selector already taken is the `CapturePluginError` as ever. A
  failure anywhere, `always` included, leaves the registry as it was.
- **An item is a dotted Python name**: ASCII identifiers joined by `.`, at
  most 255 characters, at most 64 items, none twice. Items are separated by
  `,` `;` `:` or white space, the same on every platform; `none` alone is the
  empty list. Anything else (a path, a relative name, `a-b`) is refused before
  anything is imported: a plain `ValueError` for an argument, a
  `CapturePluginError` for the variable and the file.
- `pktcap_plugin(registry) -> None` is the hook of a module: the item names the
  module. When no module of that name exists, the item is `MODULE.CALLABLE`,
  any callable that takes the registry as its one positional argument and
  returns anything (it is ignored). A protocol library's own
  `register_x_dissector(registry=None)` is therefore an item as it is.
- **A plugin that cannot be loaded stops the call** with `CapturePluginError`
  (`plugin`, `source`; a `PktcapError` and a `ValueError`), one line such as
  `PKTCAP_LOAD names 'pydemo.captur': no module of that name`. The same type
  covers a module whose import raised, one with no `pktcap_plugin`, a missing
  or uncallable attribute, a hook that takes no single argument and a hook that
  raised; the cause is chained. **The registry is left as it was before the
  call**, whatever the earlier plugins had registered; modules already imported
  stay imported.

**`capture_config_path(config=None) -> Optional[pathlib.Path]`** — the
configuration file that applies, opening nothing: `config`, else
`PKTCAP_CONFIG`, else the user's own. `None` for `none` and for a platform
with no home.

### Where the list comes from

**A module is imported because a string names it, which runs its code, so a
list is read from exactly three places**: the argument, the variable
`PKTCAP_LOAD`, and one configuration file. It is never read from the working
directory, from a file found by walking up from it, or from a capture or
anything a capture holds. The first of the three that names a list is the list:
lists never add up, and a source below it is not opened. A command line adds
no fourth: a list a program's own settings file or variable put in the
`plugins` field of a command is refused (status 2), not read as the argument.

**The configuration file** is `pktcap/pktcap.ini` under the user's
configuration directory: `$XDG_CONFIG_HOME` (else `~/.config`) on Linux, macOS
and the BSDs; `%APPDATA%` (else `~\AppData\Roaming`) on Windows. A relative
`XDG_CONFIG_HOME` or `APPDATA` is ignored. `config` and `PKTCAP_CONFIG` name
another file, which must exist (`FileNotFoundError`); `PKTCAP_CONFIG` must be
absolute or `none`. The default file may be absent; an unreadable one is the
`OSError`. **A file found by default must be the user's own, or root's, and not
writable by everyone** (POSIX; a `CaptureConfigError` otherwise), so a capture
run as root imports nothing another user wrote; **a file you name is read as it
is**, whoever owns it.

The dialect is INI: strict UTF-8 with one leading byte-order mark ignored, at
most 65,536 octets, `#` and `;` comment lines (no inline comments), `=` the
only delimiter, no interpolation, a value continued on indented lines, a
duplicate section or key an error. One section, `[pktcap]`, one key,
`load`; any other section, key or `[DEFAULT]` is an error naming it, and an
empty value is unset. A malformed file is a **`CaptureConfigError`**
(`path`, `lineno`; a `PktcapError` and a `ValueError`) whose message is
`PATH:LINE: problem` and never holds a line of the file; `lineno` is `None`
for an unknown section or key, which the parser keeps no line for.

### Environment variables

`PKTCAP_LOAD` is the list, `PKTCAP_CONFIG` the file; empty means unset.
Both are read when a list is asked for and never at import, in one module.
`import pktcap` reads no variable and imports no plugin.
