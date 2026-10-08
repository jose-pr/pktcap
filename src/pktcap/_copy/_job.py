"""A Windows job object: the program a hook runs and every process it starts
(internal).

``taskkill /T`` follows the parent links of processes that are alive, so a
process whose parent has left is not found. A job keeps its members whoever
their parent is, and ``TerminateJobObject`` ends them all. The program is
started suspended and joins the job before it runs its first instruction, so
nothing it starts can be outside.
"""

from __future__ import annotations

import subprocess
import sys

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    __all__ = ["CREATE_SUSPENDED", "Job"]

    CREATE_SUSPENDED = 0x00000004
    _SET_QUOTA = 0x0100
    _TERMINATE = 0x0001
    _SUSPEND_RESUME = 0x0800

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    _ntdll.NtResumeProcess.restype = ctypes.c_long

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
            rights = _SET_QUOTA | _TERMINATE | _SUSPEND_RESUME
            opened = _kernel32.OpenProcess(rights, False, process.pid)
            if not opened:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                joined = bool(_kernel32.AssignProcessToJobObject(self._handle, opened))
                status = _ntdll.NtResumeProcess(opened)
                if status != 0:
                    raise OSError(
                        "the program could not be resumed (%#x)" % (status & 0xFFFFFFFF)
                    )
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
