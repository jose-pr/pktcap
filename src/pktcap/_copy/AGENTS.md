# `pktcap` copying and hooks — public API header

Header-file-style reference for `copy_frames`, which writes a source of
dissected frames into a `CaptureWriter`, and for `command_hook`, a program run
for each frame it writes. It ships inside the package and is self-contained;
the top header is `pktcap/AGENTS.md`. Development documentation lives with the
source at <https://github.com/jose-pr/pktcap>.

This directory (`pktcap/_copy/`) is private and not an import path: every name
below is imported from `pktcap`.

## Copying frames into a writer

**`copy_frames(frames, writer, *, select=None, datagrams=False, limit=None, names=None, each=None) -> CopyResult`**
— write the frames a predicate accepts to a writer, in order.

- `frames` is any iterable of `DissectedFrame`: `read_dissected(path)` for a
  capture, `sniff_frames()` or `sniff_udp()` for a live source. `writer` is a
  `CaptureWriter` the caller made and still owns: it is neither opened nor
  closed here, and a second call adds to it.
- `select` is a predicate over a frame, such as
  `compile_capture_filter(text, frame_filter)`; `None` accepts every frame.
- `datagrams=True` writes each frame's UDP datagram (reassembled) in place of
  the frame, and passes over a frame that has none.
- `limit` stops the copy once that many items are written; the source is not
  read past it, so a live source is not waited on for one more. `0` reads
  nothing. An item the writer turned away does not count.
- `names` is called with each frame `select` kept, before it is written, and
  gives a mapping: the writer's `names`, the values of its `fields` for a file
  name pattern. It is given the frame even when `datagrams` is set, and is
  called again for the same frame by a hook that was given the same function,
  so it should be cheap and give the same answer.
- `each` is called with the frame after its item is written, in order. It is
  **not** called for a frame `select` dropped, one with no datagram under
  `datagrams`, or one the writer turned away for its file budget; it is called
  for the frame that reaches `limit`. Any callable will do, so a Python hook
  is a function of one `DissectedFrame`. An exception from it ends the copy
  and propagates; the item stays written.
- Raises `TypeError` for a `writer` that is not a `CaptureWriter`, a `select`,
  `names` or `each` that is not callable, a `limit` that is not an `int`,
  `names` giving something that is not a mapping, or an item that is not a
  `DissectedFrame`; `ValueError` for a `limit` below zero. The arguments are
  checked before anything is read. `OSError` from the writer ends the copy;
  what was written stays written and `writer.written` counts it.

**`CopyResult(read, written, skipped, refused)`** — a named tuple of counts for
one call: `read` items taken from the source, `written` items the writer
wrote, `skipped` items `select` refused or that had no datagram, and
`refused` items the writer turned away for its `max_files` budget during this
call (the writer's own `refused` is for its whole life).

## Running a program for each frame

**`command_hook(command, *, format="json", timeout=10.0, fail_fast=False, names=None, datagrams=False) -> Callable[[DissectedFrame], None]`**
— a hook for `copy_frames(each=...)` that runs a program for each frame it is
given.

- **The program is found once, when the hook is made**, as an absolute path: a
  name with a directory part (`./hook`, `sub/hook`, `/usr/bin/hook`) is that
  file taken from the working directory then, a bare name is looked up on
  `PATH`. `ValueError` for a command that does not exist, is not a file, is
  not executable (POSIX), is empty or holds a NUL, and **for a `.bat` or
  `.cmd` file on Windows**, which `cmd.exe` runs by reading its command line
  again: name a program. `TypeError` for a command that is not text.
- **How it runs:** no shell, no argument, its own process group (POSIX
  session), and a copy of the environment at each run with the additions
  below. Its standard input is the record of the frame in `format` (one of
  `RECORD_FORMATS`; `frame_record`, or `datagram_record` of the frame's
  datagram when `datagrams=True`, which raises `ValueError` for a frame with
  none). Its standard output and error are read and dropped, never shown.
- **What a capture can reach:** the record on standard input, and the
  values `names(frame)` gives, as `PKTCAP_HOOK_<FIELD>` (the field name
  upper-cased) beside `PKTCAP_HOOK_FORMAT`, the format's name. A value passes
  the file-name rule of `CaptureWriter`: no separator, no control character,
  at most 64 characters, a longer one cut to 55 and `-` and 8 digits of its
  digest. **A field name is the caller's code**: letters, digits and
  underscores, not `format`, not two that differ only in case; anything else
  is a `ValueError` when the hook runs and nothing is started. A sender
  therefore chooses no argument, no variable name and nothing a shell reads.
- **The time limit:** past `timeout` seconds (positive and finite;
  `ValueError` otherwise, `TypeError` for a non-number) the program and every
  process it started are killed (`killpg` on POSIX, `taskkill /T` on
  Windows).
- **A failure** is a non-zero exit status or a kill for the time limit. It is
  counted in the `failures` attribute of the returned callable, and logged on
  the logger `pktcap._copy._hook` at `ERROR` with the status and a bounded
  (400 characters), escaped (printable ASCII) tail of the program's error
  output: the first one, then at most one a minute with the running count, so
  a sender that makes the hook fail does not choose the size of the log. Output
  sizes, never contents, are logged at `DEBUG`. With `fail_fast=True` the
  first failure raises `CaptureHookError`, which ends a copy.
- **Not bounded:** how much the program writes to its own output before the
  time limit. It is the user's program.
- Raises `UnsupportedFormatError` for a `format` that is no record format and
  `MissingExtraError` when its extra is not installed, at the call.

**`CaptureHookError(message, *, status=None, timed_out=False)`** — a
`PktcapError` and an `OSError`, raised by a hook with `fail_fast`. `status` is
the program's exit status, `None` when it was killed; `timed_out` says it ran
past its time limit. The message names the program and ends with the escaped
tail.
