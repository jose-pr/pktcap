# `pktcap` command line — reference

Header-file-style reference for the `pktcap` command: its commands, every
option, what it prints and the statuses it ends with, so it can be used
without running `--help`. It ships inside the package and is self-contained;
the library's header is `pktcap/AGENTS.md`. Development documentation lives
with the source at <https://github.com/jose-pr/pktcap>.

`pktcap.cli` is the command line's package and is **not library API**: it is
absent from `pktcap.__all__`, nothing here is importable by contract, and
every command is a call into the library that a program can make itself
(`copy_frames`, `replay_to`, `sniff_frames`).

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
- **`--filter`/`-f EXPR`** (all three commands): the library's capture filter,
  `key=value and key!=value` over `src`, `dst`, `host`, `sport`, `dport`,
  `port`, `proto`, `vlan`, `linktype`. Omitted: every frame. A bad expression
  is status 2, before anything is read.
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
| `--format` | one of `pcap`, `pcapng`, `json`, `yaml`, `toml`, `ini`. Omitted: from the ending of `--output`; `json` for `-` |
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

`pktcap capture [--interface NAME] [--filter EXPR] [--output TARGET] [--format FMT] [--per-record] [--max-files N] [--datagrams] [--count N] [--duration SECONDS]`

Captures live and writes what it sees, never sending anything. **Linux only**
(`AF_PACKET`), and the process needs `CAP_NET_RAW` (root, or
`setcap cap_net_raw+ep` on the interpreter).

- `--interface NAME`: a name, an address or a MAC. Omitted: every interface.
- `--count N`/`-c`: stop once N records are written. Omitted: until stopped.
- `--duration SECONDS`/`-d`: stop after that long, within a second of it. Omitted:
  until stopped.
- Ctrl-C ends the capture with status 0 and the summary.
- Off Linux the line is `pktcap: error: live capture needs Linux (AF_PACKET);
  pipe a capture tool's output in instead: tcpdump -w - | pktcap convert --input -`
  and the status 1. Without the capability the line names `CAP_NET_RAW`,
  status 1. An interface that matches nothing is status 2.

## Environment

- **`PKTCAP_MCP=stdio`** serves the command line as tools over standard input
  and output (JSON-RPC, the MCP protocol) instead of running a command. Only
  **`convert`** is served, as the tool `pktcap.convert` with the options above
  as its input (`input` is required; the rest have the defaults above). The
  records come back as the tool's result; a capture format cannot be returned
  as text, so `format` `pcap` or `pcapng` needs an `output` file, and an
  `input` of `-` is refused. `capture` runs until stopped and needs a
  privilege, and `replay` puts datagrams on a network: neither is served.
- `AGENT_HELP=1` makes `--help` print one JSON document describing every
  command; `NO_COLOR` and `FORCE_COLOR` decide the colour of the help and the
  log. No option reads an environment variable of its own.
