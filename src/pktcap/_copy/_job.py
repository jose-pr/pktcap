"""A Windows job object: the program a hook runs and every process it starts
(internal).

``taskkill /T`` follows the parent links of processes that are alive, so a
process whose parent has left is not found. A job keeps its members whoever
their parent is, and ``TerminateJobObject`` ends them all. The program is
started suspended and joins the job before it runs its first instruction, so
nothing it starts can be outside.

The program is let run by resuming its first thread, found through a Toolhelp
snapshot: every call here is documented. Measured 2026-10-12 on Windows 11
ARM64 (Python 3.9 and 3.14): 400 starts of a suspended program, each had one
thread, none was missed or left suspended, and the snapshot costs about 60 ms
a start because it lists every thread of the machine.
"""

from __future__ import annotations

import subprocess
import sys
from typing import List

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    __all__ = ["CREATE_SUSPENDED", "Job", "resume"]

    CREATE_SUSPENDED = 0x00000004
    _SET_QUOTA = 0x0100
    _TERMINATE = 0x0001
    _TH32CS_SNAPTHREAD = 0x00000004
    _THREAD_SUSPEND_RESUME = 0x0002
    _INVALID_HANDLE = wintypes.HANDLE(-1).value
    _NO_COUNT = 0xFFFFFFFF  # ResumeThread's answer when it failed

    class _ThreadEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)]
    _kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)]
    _kernel32.OpenThread.restype = wintypes.HANDLE
    _kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.ResumeThread.restype = wintypes.DWORD
    _kernel32.ResumeThread.argtypes = [wintypes.HANDLE]

    def _thread_ids(pid: int) -> List[int]:
        """The ids of the threads of process ``pid``, from a snapshot."""
        snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot is None or snapshot == _INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        found: List[int] = []
        try:
            entry = _ThreadEntry()
            entry.dwSize = ctypes.sizeof(entry)
            more = _kernel32.Thread32First(snapshot, ctypes.byref(entry))
            while more:
                if entry.th32OwnerProcessID == pid:
                    found.append(entry.th32ThreadID)
                entry.dwSize = ctypes.sizeof(entry)
                more = _kernel32.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            _kernel32.CloseHandle(snapshot)
        return found

    def resume(pid: int) -> None:
        """Let the program ``pid``, created suspended, run: its first suspended
        thread is resumed. An ``OSError`` when no thread of it was suspended or
        one could not be opened or resumed, which leaves the program as it was."""
        for thread_id in _thread_ids(pid):
            handle = _kernel32.OpenThread(_THREAD_SUSPEND_RESUME, False, thread_id)
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                before = _kernel32.ResumeThread(handle)
                if before == _NO_COUNT:
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                _kernel32.CloseHandle(handle)
            if before > 0:
                return
        raise OSError("the program could not be resumed: it has no suspended thread")

    class Job:
        """A job object with no limit: it only keeps track of its members."""

        def __init__(self) -> None:
            handle = _kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            self._handle = handle

        def adopt(self, process: "subprocess.Popen[bytes]") -> bool:
            """Put the suspended ``process`` in the job and let it run. False
            when it could not join (it runs anyway, outside); an ``OSError``
            when it could not be resumed, which leaves it suspended."""
            opened = _kernel32.OpenProcess(_SET_QUOTA | _TERMINATE, False, process.pid)
            if not opened:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                joined = bool(_kernel32.AssignProcessToJobObject(self._handle, opened))
                resume(process.pid)
                return joined
            finally:
                _kernel32.CloseHandle(opened)

        def terminate(self) -> None:
            """End every process in the job."""
            _kernel32.TerminateJobObject(self._handle, 1)

        def close(self) -> None:
            """Release the job; its members keep running."""
            handle, self._handle = self._handle, None
            if handle:
                _kernel32.CloseHandle(handle)
