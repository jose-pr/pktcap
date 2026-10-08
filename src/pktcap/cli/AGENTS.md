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
  `pktcap 0.1.0`), `-h`/`--help`, and the logging flags `-v`/`--verbose` and
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
  `:` or space; `none` for none) and **`--config`/`-c FILE`** (the field
  `plugin_config`; `none` for no file): the plugins to load, each a dotted module name with a
  `pktcap_plugin(registry)` function or `MODULE.CALLABLE`. They are loaded
  into a registry of the command's own, before the filter is compiled and
  before anything is opened. The first of the option, the variable
  `PKTCAP_LOAD` and the `load` key of the configuration file is the list; where
  the file is and what it must be are in `_plugins/AGENTS.md`. A file you name
  is read as it is, so a capture run as root names the user's file:
  `sudo pktcap capture --config ~/.config/pktcap/pktcap.ini`. A plugin that
  cannot be loaded, or a malformed file, is status 2 and one line naming it;
  a named file that does not exist is status 1. **A tool call cannot name
  either option**: they are refused, since a program serving the tool may have
  just read a capture's text, and the server's own variable and file decide.
  **A root's own settings file or variable cannot supply them either**: such a
  value is status 2 naming the layer (`--load`, `PKTCAP_LOAD` or pktcap's own
  file are the sources).
- **Output and statuses.** What a command produces goes to standard output or
  to `--output`; its one-line summary and every diagnostic go to standard
  error, because standard output may be a capture. Every failure is one line,
  `pktcap: error: <text>`. Status **0** done (Ctrl-C during `capture`
  included), **1** the operation failed (a file that cannot be opened or
  written, a send that failed, no live capture here, no permission, a missing
  format extra, a writer that refused records for its file budget), **2** the
  invocation was wrong (the parser's own errors, a bad filter, an unknown
  format, a combination that cannot work, a capture that is not one or is
  damaged), **130** Ctrl-C in `convert` or `replay`. Standard output closed by
  the reader is status 1 with no line.
- **A capture is untrusted input** and the library's bounds hold through every
  command: a frame larger than the reader's ceiling, the reassembly limits and
  `--max-files` apply as they do to a program, and the commands keep no state
  of their own that a file could grow.

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
- `--format toml` or `ini` without `--per-record` is status 2 saying why.

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

- `--interface NAME`: a name, an address or a MAC. Omitted: every interface.
- `--listen SPEC` (repeatable, and excludes `--interface`, status 2): capture
  the datagrams that arrive at sockets the command binds, read with
  `netimps.parse_listen` before anything is opened: `HOST:PORT`, `[V6]:PORT`,
  `*:PORT` or `:PORT`, an adapter name or a MAC, several joined by commas. A
  value with no port gets the command's `_default_port_`, and with none is
  refused (status 2, netimps' message). A taken port is status 1, one line
  `cannot listen on SPEC: ...`. `listening on HOST:PORT` is logged at INFO for
  each socket, shown unless `-q`, the way to learn a port 0. What it sees and does not (a made-up IP
  header, no other host's traffic) and that it holds the port are in
  `_sources/AGENTS.md`. A datagram that arrives on an interface a limited
  socket does not serve is counted in the summary as `N not admitted`; one
  over 65,535 octets as `N over the size limit`.
- `--hook COMMAND`: run a program for each record written, with the record on
  standard input in the format the writer writes (JSON for a capture format or
  `text`) and the values `_names` gives as `PKTCAP_HOOK_<FIELD>`; how a program
  is found, run and ended is `command_hook`'s (`_copy/AGENTS.md`). **Or
  `MODULE:FUNCTION`**, imported as written with nothing added to `sys.path` and
  called with each `DissectedFrame`: `--hook-timeout` does not bound a
  function, and its failures are logged at the rate a program's are. On Windows
  `C:hook.exe` is a program. The command comes from the command line alone
  (never a tool call or a capture); a value a root's settings file or variable
  put in the field is status 2 naming the layer, unless the class lists it in
  `Capture._hook_from_`. `--hook-timeout SECONDS` (default 10) kills the
  program and what it started; a failure is counted (`N hook failures` in the
  summary) and logged, and `--hook-fail-fast` ends the capture at the first one
  with status 1. A hook that cannot be found is status 2 before anything is bound.
- `--count N`: stop once N records are written. Omitted: until stopped.
- `--duration SECONDS`/`-d`: stop after that long, within a second of it. Omitted:
  until stopped.
- Ctrl-C ends the capture with status 0 and the summary.
- Off Linux the line is `pktcap: error: live capture needs Linux (AF_PACKET);
  pipe a capture tool's output in instead: tcpdump -w - | pktcap convert --input -`
  and the status 1. Without the capability the line names `CAP_NET_RAW`,
  status 1. An interface that matches nothing is status 2.

## `pktcap plugins`

`pktcap plugins [--load LIST] [--config FILE] [--layer NAME] [--json]`

Loads the plugins exactly as the other commands do and shows them. Standard
output is:

```text
configuration: PATH (absent)
plugins: 2 from SOURCE
  NAME: udp 67, udp 68; layer dhcp
keys: dport, dst, host, linktype, ...
layers: dhcp, ethernet, ipv4, ...
```

- `configuration` is the file that applies, `none` when there is none, and
  ` (absent)` when it does not exist. `plugins` says how many were loaded and
  where the list came from (`argument`, `PKTCAP_LOAD`, the file's path), or
  `plugins: none`; each plugin has a line with the selectors it registered a
  dissector under and the layers it declared. `keys` are the bare filter
  keys: the nine built-in ones and each registered key that one layer has.
  `layers` are the names a filter may put before a dot.
- `--layer NAME`: print only that layer's keys, one per line
  (`ipv4.ttl`, `demo.opcode`), which are `LAYER.FIELD` and `LAYER.KEY` of a
  filter. A name that is no layer is status 2 listing the layers.
- `--json`: one object, `{"configuration": PATH-or-null, "plugins": [{"name",
  "source", "selectors", "layers"}], "keys": [every filter key that compiles]}`.

## Environment

- **`PKTCAP_LOAD`** and **`PKTCAP_CONFIG`** are what `--load` and
  `--config` fall back to, in that order and then the user's own file: the
  plugins to load, and the configuration file (an absolute path, or `none`).
  `XDG_CONFIG_HOME` (POSIX) and `APPDATA` (Windows) say where the user's own
  file is.
- **`PKTCAP_MCP=stdio`** serves the command line as tools over standard input
  and output (JSON-RPC, the MCP protocol) instead of running a command.
  **`convert`** is served as the tool `pktcap.convert` with the options above
  as its input (`input` is required; the rest have the defaults above), and
  **`plugins`** as `pktcap.plugins`, which only reads. The records come back as
  the tool's result; a capture format cannot be returned as text, so `format`
  `pcap` or `pcapng` needs an `output` file, and an `input` of `-` is refused.
  A tool call that names `plugins`, `plugin_config` or `append` is refused
  (status 2, naming `PKTCAP_LOAD` for the first two). `capture` runs until stopped and binds ports or needs a privilege, and
  `replay` puts datagrams on a network: neither is served, and a subclass that
  serves `capture` is refused a `hook` in a tool call.
- `AGENT_HELP=1` makes `--help` print one JSON document describing every
  command; `NO_COLOR` and `FORCE_COLOR` decide the colour of the help and the
  log.

## Subclassing

A library with a protocol of its own subclasses these classes and adds only what
is the protocol's. `from pktcap.cli import Loading, Selecting, Writing, Capture,
Convert, Replay, Plugins` binds each on first use, so `import pktcap.cli` needs
no `duho`; without it the name is an `ImportError` (`MissingExtraError`)
naming `pip install "pktcap[cli]"`. Class attributes ending in `_` and methods
beginning with `_` listed below are the **override points**; nothing else
beginning with `_` is promised.

| Class | Options it declares | Class attributes |
| --- | --- | --- |
| `Loading(LoggingArgs, Cmd)` | `--load` (`plugins`), `--config`/`-c` (`plugin_config`) | `_plugins_ = ()`: dotted plugin names always loaded, first, source `always`; code's, never read from input |
| `Selecting(Loading)` | `--filter`/`-f` | `_filter_ = None`: own clauses, ANDed with `--filter` |
| `Writing(Selecting)` | `--output`, `--format`, `--per-record`, `--max-files`, `--datagrams`, `--append` | `_fields_ = ()` file-name fields beyond `timestamp`, `index`, `format`; `_interruptible_ = False`; `_format_ = None` |
| `Convert(Writing)` | `--input`/`-i`, `--limit` | |
| `Capture(Writing)` | `--interface`, `--listen`, `--count`, `--duration`/`-d`, `--hook`, `--hook-fail-fast`, `--hook-timeout`; `_interruptible_ = True` | `_default_port_ = None` (`None`, an `int` or a tuple of them); `_hook_from_ = ("argument",)`: the layers `--hook` may come from, of `"argument"`, `"environment"`, `"file"` |
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
| `Capture._endpoints(self) -> Tuple[UDPEndpoint, ...]` | once, when `--listen` is given | the default is `netimps.bind_listen` of `--listen` read with `_default_port_`; the capture owns what is returned (and closes it if the source refuses it); override for a family, broadcast or one socket per address |
| `Capture._stop(self) -> bool` | between datagrams, at least once a second, whatever the options | the default is the `--duration` deadline, false without one |
| `Replay._destination` is private; `Replay._datagrams(self, registry) -> Iterator[CapturedDatagram]` | once | the filtered datagrams in capture order |
| `Replay._replay(self, datagrams, host: str, port: int) -> Any` | once | default `replay_to` with the options; its result is given to `_report` |
| `Replay._report(self, result: Any) -> Optional[int]` | once | default prints `sent N, partial M` |

**What a subclass must do that a thin wrapper would not:**

- A foreign base with a field of the same name wins silently if it comes first
  in the bases (`duho` keeps the first). With a `--config` of its own the
  parser fails to build (`conflicting option string`) until the subclass
  redeclares `plugin_config` under a flag of its own (`("--pktcap-config",)`);
  redeclaring `--listen` drops the exclusion with `--interface`, which it must
  restate (`Meta(conflicts=...)`) if it wants it.
- A root that serves the subclass maps `MissingExtraError` (an `ImportError`)
  and `CaptureHookError` (an `OSError`) to status 1; `main`'s does.
- A subclass that serves `Capture` as a tool (`_mcp_ = True`) is refused a
  `hook` in a tool call by the class; do not remove that. A root that has a
  settings file or a variable for a field applies it to the inherited ones too;
  `_hook_from_` is how a class says which of those it takes a hook from, and
  the plugin list never comes from them.
- `_names` runs for hooks as well as file names, so it must not raise on a
  frame the filter let through; `_filter_` is how it is guaranteed its layer.

```python
from pktcap.cli import Convert


class Listing(Convert):
    """Convert, with a filter of its own and a readable default."""

    _parsername_ = "listing"
    _filter_ = "proto=udp"
    _format_ = "text"
```
