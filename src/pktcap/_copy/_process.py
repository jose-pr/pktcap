"""Running a hook's program once, bounded in time (internal).

The program reads the record from a temporary file and writes its standard
error to another; its standard output goes nowhere. Nothing waits for a pipe
to reach its end, so a process the program left behind that holds its streams
neither delays the run nor makes it a failure: the run is the program's own
exit within the time limit. Past the limit the program and what it started are
ended (a job object on Windows, the process group on POSIX). Measured
2026-10-09, Windows 11 and Fedora under WSL2: an orphaned grandchild is ended
by the job and by the group, and a descendant that calls ``setsid`` leaves the
group.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
from typing import IO, Any, Mapping, NamedTuple, Optional, Tuple

from .._plugins._config import process_environment
from ._find import brief

if sys.platform == "win32":
    from ._job import CREATE_SUSPENDED, Job

__all__ = ["Outcome", "run_program", "taskkill_path"]

#: Seconds to wait for an ended program to be reaped.
_REAP_SECONDS = 5.0
#: Octets of the end of standard error that are read: a character is at most
#: four, and a log line or an error carries 400 characters.
_TAIL_BYTES = 4 * 400


class Outcome(NamedTuple):
    """How one run ended.

    ``status`` is the program's exit status, ``None`` when it was killed or
    never started. ``timed_out`` says it ran past the limit. ``error`` is the
    reason it could not be started, or ``None``. ``tail`` is the end of its
    standard error, decoded, and ``written`` how many octets it wrote there.
    """

    status: Optional[int]
    timed_out: bool
    error: Optional[str]
    tail: str
    written: int


def taskkill_path() -> str:
    """``taskkill.exe`` under the Windows directory the environment names, the
    key being found whatever its case."""
    root = r"C:\Windows"
    for key, value in process_environment().items():
        if key.upper() == "SYSTEMROOT":
            root = value
    return os.path.join(root, "System32", "taskkill.exe")


def _taskkill(pid: int) -> None:
    try:
        subprocess.run(
            [taskkill_path(), "/F", "/T", "/PID", str(pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_REAP_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


class _Running:
    """A started program and what ends it with everything it started."""

    def __init__(
        self, process: "subprocess.Popen[bytes]", job: Optional[Any] = None
    ) -> None:
        self.process = process
        self._job = job

    def kill(self) -> None:
        """End the program and what it started."""
        if sys.platform == "win32":
            if self._job is not None:
                self._job.terminate()
            else:
                _taskkill(self.process.pid)
        else:
            try:
                # The program leads its own session, so its group is the tree.
                os.killpg(self.process.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            self.process.kill()
        except OSError:
            pass

    def release(self) -> None:
        if self._job is not None:
            self._job.close()


def _start(
    path: str, stdin: IO[bytes], errors: IO[bytes], env: Mapping[str, str]
) -> _Running:
    # sys.platform is tested here, not through a variable, so a type checker
    # narrows each branch to the platform that has the option.
    if sys.platform == "win32":
        job: Optional[Job]
        try:
            job = Job()
        except OSError:
            job = None
        flags = subprocess.CREATE_NEW_PROCESS_GROUP
        if job is not None:
            flags |= CREATE_SUSPENDED
        try:
            process = subprocess.Popen(
                [path],
                stdin=stdin,
                stdout=subprocess.DEVNULL,
                stderr=errors,
                env=dict(env),
                creationflags=flags,
            )
        except BaseException:
            if job is not None:
                job.close()
            raise
        if job is not None:
            try:
                joined = job.adopt(process)
            except BaseException:
                process.kill()
                process.wait()
                job.close()
                raise
            if not joined:  # running outside the job: taskkill is the way
                job.close()
                job = None
        return _Running(process, job)
    process = subprocess.Popen(
        [path],
        stdin=stdin,
        stdout=subprocess.DEVNULL,
        stderr=errors,
        env=dict(env),
        start_new_session=True,
    )
    return _Running(process)


def _read_tail(errors: IO[bytes]) -> Tuple[str, int]:
    size = errors.seek(0, os.SEEK_END)
    errors.seek(max(0, size - _TAIL_BYTES))
    return errors.read(_TAIL_BYTES).decode("utf-8", "replace"), size


def run_program(
    path: str, payload: bytes, env: Mapping[str, str], timeout: float
) -> Outcome:
    """Run ``path`` with ``payload`` on standard input and no argument, never
    through a shell, for at most ``timeout`` seconds.

    Standard error is decoded as UTF-8 with ``errors="replace"``, whatever the
    platform's encoding is. A program that cannot be started is an
    :class:`Outcome` with ``error``, not an exception.
    """
    with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as errors:
        stdin.write(payload)
        stdin.flush()
        stdin.seek(0)
        try:
            running = _start(path, stdin, errors, env)
        except OSError as exc:
            return Outcome(None, False, brief(str(exc)), "", 0)
        timed_out = False
        try:
            try:
                status: Optional[int] = running.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out, status = True, None
                running.kill()
                try:
                    running.process.wait(timeout=_REAP_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
            except BaseException:
                running.kill()
                running.process.wait()
                raise
        finally:
            running.release()
        tail, written = _read_tail(errors)
    return Outcome(status, timed_out, None, tail, written)
