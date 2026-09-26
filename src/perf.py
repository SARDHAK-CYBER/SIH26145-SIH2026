"""
Process-level performance opt-ins for a long-running sensor/service.

Windows 11 puts processes it considers "background" (hidden windows, services started from a
launcher, anything without foreground UI) into EcoQoS / efficiency mode: after ~3 s of sustained
CPU load the process is clamped to efficiency-core-class speed. Measured on this project's
dev machine (i7-14650HX): a pure-Python counting loop ran 20.6 M iter/s for 3 s and then 2.2 M
iter/s -- an 8x cliff -- and the native capture thread went from 1.0 M pps to 0.15 M pps at the
same instant. Opting the process out of execution-speed power throttling removes the cliff
completely (20 M iter/s steady).

This is a per-process API (SetProcessInformation / SetPriorityClass), not a system setting;
it only affects this process.
"""
from __future__ import annotations

import os
import sys

_done = False


def boost_process(high_priority: bool = True) -> dict:
    """Idempotent. Returns what was applied."""
    global _done
    applied: dict = {"platform": sys.platform}
    if _done or os.environ.get("STEALTHTAP_NO_BOOST") == "1":
        return applied
    _done = True
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.GetCurrentProcess.restype = wintypes.HANDLE
            k.SetProcessInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            k.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]

            class _PTS(ctypes.Structure):
                _fields_ = [("Version", wintypes.ULONG), ("ControlMask", wintypes.ULONG), ("StateMask", wintypes.ULONG)]

            h = k.GetCurrentProcess()
            # ProcessPowerThrottling=4; EXECUTION_SPEED(0x1) controlled, state 0 = never throttle
            st = _PTS(1, 0x1, 0)
            applied["ecoqos_disabled"] = bool(k.SetProcessInformation(h, 4, ctypes.byref(st), ctypes.sizeof(st)))
            if high_priority:
                applied["priority_high"] = bool(k.SetPriorityClass(h, 0x80))   # HIGH_PRIORITY_CLASS
        except Exception as exc:  # never fatal
            applied["error"] = str(exc)
    else:
        if high_priority:
            try:
                os.nice(-5)
                applied["nice"] = -5
            except (PermissionError, OSError, AttributeError):
                pass
    return applied
