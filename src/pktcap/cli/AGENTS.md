# `pktcap` command line — reference

Header-file-style reference for the `pktcap` command: its commands, every
option, what it prints and the statuses it ends with, so it can be used
without running `--help`. It ships inside the package and is self-contained;
the library's header is `pktcap/AGENTS.md`. Development documentation lives
with the source at <https://github.com/jose-pr/pktcap>.

`pktcap.cli` is the command line's package. It is absent from
`pktcap.__all__`, and **only `main` and the command classes in "Subclassing" are
API**, for a library with a protocol of its own to subclass; everything else in
the package is private. Every command is a call into the library that a program
can make itself (`copy_frames`, `replay_to`, `sniff_frames`, `load_plugins`,
`sniff_udp`, `command_hook`).

```bash
pip install "pktcap[cli]"        # installs duho; the command is `pktcap` or `python -m pktcap`
pktcap convert -i trace.pcap -o trace.jsonl
pktcap replay -i trace.pcap --to 127.0.0.1:9000 --no-delay
sudo pktcap capture --interface eth0 -o live.pcapng
```

Without the extra the command prints one line on stderr,
`pktcap: error: the command line needs the 'cli' extra: pip install "pktcap[cli]"`,
and exits 1. `pktcap.cli.main(argv=None) -> int` is the entry point: it
returns the status and does not call `sys.exit`.

## Every command

- **Options of the root**, before the command name: `--version` (prints
  `pktcap 0.1.3`), `-h`/`--help`, and the logging flags `-v`/`--verbose` and
  `-q`/`--quiet` (repeatable), `--loglevel [NAME:]LEVEL[,...]`. Each command
  accepts the same three after its own name. Logging is on stderr, under the
  logger `pktcap`.
- **`--filter`/`-f EXPR`** (`capture`, `replay`, `convert`): the library's
  capture filter, `key=value and key!=value` over `src`, `dst`, `host`,
  `sport`, `dport`, `port`, `proto`, `vlan`, `linktype`, any field of a layer
  as `LAYER.FIELD` (`ipv4.ttl=64`) and the keys of the plugins loaded;
  `pktcap plugins` lists them all. Omitted: every frame. A bad expression is
  status 2, before anything is read.
- **`--load NAME`** (every command; repeat it, or separate names by `,` `;`
  `:` or space; `none` for none): the plugins to load, each a dotted module name
  with a `pktcap_plugin(registry)` function or `MODULE.CALLABLE`, into a
  registry of the command's own, before the filter is compiled and before
  anything is opened. The first of the option, `PKTCAP_LOAD` and the `load` of
  the settings file is the list. A plugin that cannot be loaded is status 2 and
  one line naming it. **A tool call cannot name it**: a program serving the
  tool may have just read a capture's text, and the server's own variable
  decides.
- **Output and statuses.** What a command produces goes to standard output or
  to `--output`; its summary and every diagnostic go to standard error, because
  standard output may be a capture. A failure is one line, `pktcap: error:
  <text>`. Status **0** done (Ctrl-C during `capture` included), **1** the
  operation failed (a file that cannot be opened or written, a send that
  failed, no live capture here, no permission, a missing format extra, records
  refused for the file budget), **2** the invocation was wrong (the parser's
  own errors, a bad filter, an unknown format, a combination that cannot work,
  a capture that is not one or is damaged), **130** Ctrl-C in `convert` or
  `replay`, silently. Standard output closed by the reader is status 1, no line.
- **A capture is untrusted input** and the library's bounds hold through every
  command (the reader's frame ceiling, the reassembly limits, `--max-files`),
  and the commands keep no state of their own that a file could grow.

## The settings file

The root takes it, before the command's name (`pktcap -c FILE convert ...`; after
it is the parser's own error): `--config`/`-c FILE`, else `PKTCAP_CONFIG` (an
absolute path), else the user's own `pktcap/pktcap.ini` under `$XDG_CONFIG_HOME`
(else `~/.config`) on Linux, macOS and the BSDs and `%APPDATA%` on Windows, which
may be absent. **An empty path (`--config ""`, `PKTCAP_CONFIG=`) means no file**,
the user's own included. It is duho's layout, read by `duho.config` in the format
its name says (`.ini`/`.cfg`, `.toml`, `.json`, `.yaml`/`.yml`; TOML before Python
3.11 and YAML need duho's `config` and `yaml` extras; another name is refused):
top-level keys for the root's options (`verbose`), a table for each command with
the command's field names as keys; in INI the keys of `[DEFAULT]` are the top
level (examples in `_plugins/AGENTS.md`).

- **Order**, nearest first: the argument, the variable the field declares
  (`PKTCAP_LOAD` for `load`; a class's `_env_prefix_` names the rest), the file,
  the default; a higher layer replaces a lower for that option only, so lists
  do not add up. A top-level `load` is the list of every command whose table
  names none.
- **Refused**, status 2, in one line and never with text of a value: a key or
  table nobody has (`unknown key 'convert.nosuch'`, which names the key), a
  `config` key, a `[pktcap]` table (`load` goes at the top level), an invalid
  document, a file over 65,536 octets. A named file that does not exist is status 2 from `--config`
  and 1 from the variable.
- **Trust.** A list and a hook run code: `Loading._load_from_` and
  `Capture._hook_from_` name the layers each may come from. The file found by
  default must be yours or root's and not writable by everyone (POSIX); a file
  you name is read as it is: `sudo pktcap -c ~/.config/pktcap/pktcap.ini capture`.
- **A served tree** (`PKTCAP_MCP`) reads the server's own default file, checked
  as any default is, and neither `PKTCAP_CONFIG` nor a `config` a tool call names;
  a call names no `load` or `hook` either.

## Writing options

`convert` and `capture` write what they read with a `CaptureWriter`:

| Option | Meaning |
| --- | --- |
| `--output`/`-o TARGET` | a file; a file-name pattern with `--per-record`; `-` for standard output (default `-`) |
| `--format` | one of `pcap`, `pcapng`, `json`, `yaml`, `toml`, `ini`, `text` (one readable line a frame). Omitted: from the ending of `--output`; `json` for `-` |
| `--append` | add to a record file that exists instead of replacing it; a capture format cannot be appended to, nor can `--per-record` (status 2) |
| `--per-record` | one file per record, `--output` being the pattern (`{index}`, `{timestamp}`, `{format}`); needed for `toml` and `ini` |
| `--max-files N` | with `--per-record`, the most files created (default 1000); the rest are counted as refused and the status is 1 |
| `--datagrams` | write each frame's UDP datagram, IP fragments reassembled, and pass over frames without one. Omitted: write the frames. In a capture format a datagram is written under synthesised headers |

- With `--output -` and a capture format the octets go to standard output
  unchanged on every platform, and nothing else is written there. Capture
  octets are refused (status 2, naming `--output`) when standard output is a
  terminal. A pattern with `--per-record` cannot be `-`.
- The summary is `12 frames read, 10 written` and, only when not zero,
  `, 2 skipped`, `, 3 refused, 1000 files already (--max-files)`,
  `, 4 malformed`, `, 5 of an unsupported link type (105, 147)`. `-q` drops it
  unless records were refused.

## `pktcap convert`

`pktcap convert --input FILE|- [--output TARGET] [--format FMT] [--filter EXPR] [--per-record] [--max-files N] [--datagrams] [--limit N]`

Copies a pcap or pcapng capture into pcap, pcapng or records.

- `--input`/`-i`: the capture, or `-` for standard input, which need not seek
  (`tcpdump -w - | pktcap convert -i - --datagrams -o requests.jsonl`).
- `--limit N`: write at most N frames, then stop reading. Omitted: all.
- A capture cut or damaged part-way writes every record before the damage,
  then ends with status 2 and a line naming the file and how many were
  written. A file that is not a capture is status 2; one that cannot be opened
  is status 1.
- `toml` or `ini` (`--format`, or the ending of `--output`) without `--per-record` is status 2 naming it.

## `pktcap replay`

`pktcap replay --input FILE|- --to HOST:PORT [--filter EXPR] [--speed X | --no-delay] [--max-delay SECONDS] [--limit N] [--source-port N] [--broadcast] [--json]`

Sends the payload of each UDP datagram of the frames the filter selects, in
capture order and in time. **`--to` is the only destination there is**: the
addresses in the file are never sent to, and nothing but UDP payloads is ever
sent.

- `--input`/`-i`: the capture, or `-` for standard input.
- `--to`: `HOST:PORT`, an IPv6 address in brackets (`[2001:db8::1]:547`). A
  missing or invalid port is status 2; a name that does not resolve is
  status 1.
- `--speed X` divides each recorded wait by X (default 1.0, the recorded
  pace); `--no-delay` sends without waiting. They exclude each other (status
  2). `--max-delay SECONDS` caps one wait (default 5.0).
- `--limit N`: stop after N datagrams, partial ones counted. Omitted: all.
- `--source-port N`: send from that port. Omitted: any free one.
- `--broadcast`: allow a broadcast destination. Omitted: refused.
- A datagram the capture holds only in part (cut by the snap length) is not
  sent and is counted as partial.
- Prints, on standard output, `sent 12, partial 0`; with `--json`,
  `{"sent": 12, "partial": 0}`.
- A capture damaged part-way sends what came before it, then status 2 naming
  the file.

## `pktcap capture`

`pktcap capture [--interface NAME | --listen SPEC...] [--filter EXPR] [--output TARGET] [--format FMT] [--per-record] [--max-files N] [--datagrams] [--append] [--count N] [--duration SECONDS] [--hook COMMAND] [--hook-fail-fast] [--hook-timeout SECONDS]`

Captures and writes what it sees, never sending anything. From an interface it
is **Linux only** (`AF_PACKET`), and the process needs `CAP_NET_RAW` (root, or
`setcap cap_net_raw+ep` on the interpreter). From `--listen` it runs anywhere,
with no privilege.

- `--interface NAME`: a name, an address or a MAC. Omitted: every interface (or `_listen_`).
- `--listen SPEC` (repeatable, and excludes `--interface`, status 2): capture
  the datagrams that arrive at sockets the command binds, read with
  `netimps.parse_listen`; the grammar, the ports and the counts are in
  `_sources/AGENTS.md`.
- `--hook COMMAND`: run a program for each record written, with the record on
  standard input, or `MODULE:FUNCTION`; `--hook-timeout SECONDS` (default 10)
  and `--hook-fail-fast`; all in `_copy/AGENTS.md`. It comes from the command
  line alone (never a tool call or a capture) unless `Capture._hook_from_` says.
- `--count N`: stop once N records are written. Omitted: until stopped.
- `--duration SECONDS`/`-d`: stop after that long, within a second of it. Omitted:
  until stopped.
- Ctrl-C ends the capture with status 0 and the summary.
- Off Linux the line is `pktcap: error: live capture needs Linux (AF_PACKET);
  pipe a capture tool's output in instead: tcpdump -w - | pktcap convert --input -`
  (`pktcap` is the program's name) and the status 1. Without the capability
  the line names `CAP_NET_RAW`, status 1. No such interface is status 2.

## `pktcap plugins`

`pktcap plugins [--load LIST] [--layer NAME] [--json]`

Loads the plugins exactly as the other commands do and shows them: the settings
file the root read (`none` when it read none), where the list came from, each
plugin with what it registered, every filter key and layer. The output, the
options `--layer` and `--json` and the JSON object are in `_plugins/AGENTS.md`.

## Environment

- **`PKTCAP_LOAD`** is the `--load` option's variable and **`PKTCAP_CONFIG`**
  the root's (an absolute path). `XDG_CONFIG_HOME` (POSIX) and `APPDATA`
  (Windows) say where the user's own settings file is.
- **`PKTCAP_MCP=stdio`** serves the command line as tools over standard input
  and output (JSON-RPC, the MCP protocol) instead of running a command.
  **`convert`** is served as the tool `pktcap.convert` with the options above
  as its input (`input` is required; the rest have the defaults above), and
  **`plugins`** as `pktcap.plugins`, which only reads. The records come back as
  the tool's result; `format` `pcap` or `pcapng` with no `output` writes the
  octets to the server's output target (descriptor 3, or what
  **`PKTCAP_MCP_OUTPUT`** names: a descriptor number, a file or a pipe) and the
  result says how many went where; with no target the call fails. An `input` of
  `-` is refused.
  A tool call that names `load` or `append` is refused (status 2, naming
  `PKTCAP_LOAD` for the first). `capture` and `replay` are not served, and a
  subclass that serves `capture` is refused a `hook` in a call.
- `AGENT_HELP=1` makes `--help` print one JSON document describing every
  command; `NO_COLOR` and `FORCE_COLOR` set the colour of help and log.

## Subclassing

A library with a protocol of its own subclasses these classes and adds only what
is the protocol's. `from pktcap.cli import Loading, Selecting, Writing, Capture,
Convert, Replay, Plugins` binds each on first use, so `import pktcap.cli` needs
no `duho`; without it the name is an `ImportError` (`MissingExtraError`) naming
`pip install "pktcap[cli]"`. Class attributes ending in `_` and methods
beginning with `_` listed below are the **override points**; every other name
the base defines begins `_pk_`, and a subclass defines and uses none.

| Class | Options it declares | Class attributes |
| --- | --- | --- |
| `Loading(LoggingArgs, Cmd)` | `--load` (`load`) | `_plugins_ = ()`: dotted plugin names always loaded, first, source `always`; code's, never read from input. `_load_from_ = ("argument", "environment", "file")`: the layers `--load` may come from; `_env_prefix_ = None`: a prefix such as `"MYPROG_CAPTURE_"` gives every option of the class (inherited ones too) that names no variable `PREFIX` + its field name in upper case (`MYPROG_CAPTURE_FORMAT`), the logging options excepted, `--load` keeping `PKTCAP_LOAD`, and `Meta(env="")` keeping an option without one |
| `Selecting(Loading)` | `--filter`/`-f` | `_filter_ = None`: own clauses, ANDed with `--filter` |
| `Writing(Selecting)` | `--output`, `--format`, `--per-record`, `--max-files`, `--datagrams`, `--append` | `_fields_ = ()` file-name fields beyond `timestamp`, `index`, `format`; `_interruptible_ = False`; `_format_ = None` |
| `Convert(Writing)` | `--input`/`-i`, `--limit` | |
| `Capture(Writing)` | `--interface`, `--listen`, `--count`, `--duration`/`-d`, `--hook`, `--hook-fail-fast`, `--hook-timeout`; `_interruptible_ = True` | `_default_port_ = None` (`None`, an `int` or a tuple of them); `_listen_ = None`: what the command listens on, read as `--listen` is, when neither `--listen` nor `--interface` is given (`None`: every interface); `_hook_from_ = ("argument",)`: the layers `--hook` may come from, as `_load_from_` |
| `Replay(Selecting)` | `--input`/`-i`, `--to`, `--speed`, `--no-delay`, `--max-delay`, `--limit`, `--source-port`, `--broadcast`, `--json` | `_default_port_ = None` (an `int` or `None`) |
| `Plugins(Loading)` | `--layer`, `--json` | |

`Loading.served() -> bool` is true in a tool call. `Writing.__call__` is the one
loop and is not overridden: registry, `_select`, `_hook`, the writer, `_frames`,
`copy_frames`, `_report`. `_format_` is the format when neither `--format` nor a
known ending of `--output` names one (`None`: `json`); a protocol library that
wants a listing sets `"text"`. Methods, with when each is called:

| Override | Called | A subclass may assume |
| --- | --- | --- |
| `Selecting._select(self, registry) -> Callable[[DissectedFrame], bool]` | once, before the source is opened | the registry holds `_plugins_` and the user's; a bad expression is status 2; call `super()` to keep `_filter_` and `--filter` |
| `Writing._frames(self, dissector: FrameDissector) -> Iterator[DissectedFrame]` | once, after the filter and the writer exist | the loop closes the iterator (`close()` if it has one); `ValueError` is status 2, `OSError` status 1, `KeyboardInterrupt` ends the run only when `_interruptible_` |
| `Writing._names(self, frame) -> Mapping[str, object]` | for each frame the filter kept, before it is written, and by a hook | values for `_fields_`, and the hook's `PKTCAP_HOOK_*`; each passes the writer's file-name rule |
| `Writing._limit(self) -> Optional[int]` | once | the most items written; `Convert` gives `--limit`, `Capture` `--count` |
| `Writing._hook(self) -> Optional[Callable[[DissectedFrame], object]]` | once, before the source | called after a frame is written, never for one the filter dropped |
| `Writing._report(self, result: CopyResult, dissector: FrameDissector) -> int` | once, at the end, after Ctrl-C too | prints the summary on stderr; returns the status |
| `Capture._endpoints(self, dissector: FrameDissector) -> Tuple[UDPEndpoint, ...]` | once, when `--listen` is given or `_listen_` applies | `dissector` is the one `_frames` was given, so a protocol can be registered (`dissector.registry.register("udp", port, fn)`) on a port that was bound; the default is `netimps.bind_listen` of `--listen`, else `_listen_`, read with `_default_port_`; the capture owns what is returned (and closes it if the source refuses it); override for a family, broadcast or one socket per address |
| `Capture._stop(self) -> bool` | between datagrams, at least once a second, whatever the options | the default is the `--duration` deadline, false without one |
| `Replay._datagrams(self, registry) -> Iterator[CapturedDatagram]` | once | the filtered datagrams in capture order |
| `Replay._replay(self, datagrams, host: str, port: int) -> Any` | once | default `replay_to` with the options; its result is given to `_report` |
| `Replay._report(self, result: Any) -> Optional[int]` | once | default prints `sent N, partial M` |

**What a subclass must do that a thin wrapper would not:**

- **No command class has a configuration option**, so a foreign base with a
  `--config` of its own meets no clash. A program that subclasses a command
  names its settings file on **its own root**, and that file's table for the
  command (`[convert]`) sets the inherited options, `load` among them unless
  the subclass narrows `_load_from_`. A foreign base with a field of the same
  name wins silently if it comes first in the bases (`duho` keeps the first);
  redeclaring `--listen` drops the exclusion with `--interface`, which it must
  restate (`Meta(conflicts=...)`) if it wants it.
- A root that serves the subclass maps `MissingExtraError` (an `ImportError`)
  and `CaptureHookError` (an `OSError`) to status 1; `main`'s does.
- A subclass that serves `Capture` as a tool (`_mcp_ = True`) is refused a
  `hook` in a tool call by the class; do not remove that. A root that has a
  settings file or a variable for a field applies it to the inherited ones too.
- `_names` runs for hooks as well as file names, so it must not raise on a
  frame the filter let through; `_filter_` is how it is guaranteed its layer.

```python
from pktcap.cli import Capture, Convert


class Listing(Convert):
    """Convert, with a filter of its own and a readable default."""

    _parsername_ = "listing"
    _filter_ = "proto=udp"
    _format_ = "text"


class Watching(Capture):
    """Capture on ports of its own, with MYPROG_WATCHING_* variables."""

    _parsername_ = "watching"
    _listen_ = "*"  # listen with no option; --interface still wins
    _default_port_ = (6767, 6768)
    _env_prefix_ = "MYPROG_WATCHING_"

    def _endpoints(self, dissector):
        endpoints = super()._endpoints(dissector)
        for endpoint in endpoints:  # dissect: the protocol's own function
            port = endpoint.socket.getsockname()[1]
            dissector.registry.register("udp", port, dissect)
        return endpoints
```
