"""
Import scapy without a 2-minute stall on Windows hosts running Npcap in
"Administrators only" mode.

The problem: scapy forces `conf.use_pcap = True` on Windows and, at IMPORT time,
loads wpcap.dll and enumerates adapters (`load_winpcapy`). With Npcap installed
"restricted to Administrators" (the installer's default-off but common choice)
the first adapter enumeration from a NON-elevated process makes Npcap raise a UAC
prompt for NpcapHelper and wait for it -- a fixed ~122 s -- before failing.
Measured here: `import scapy.layers.l2` took 122 s; every pytest run, API start
and CLI tool paid it, whether or not it captured anything.

The fix: only the process that actually captures needs Npcap. Everything else
(API workers, tests, pcap parsing, packet dissection) only needs scapy's
protocol layers, so this hook turns scapy's import-time Npcap probe into a
no-op for them. Live capture itself no longer goes through scapy at all: the
native engine (native/stealthtap_core/src/capture.rs) loads wpcap.dll directly
and is used by exactly one long-lived (elevated) sensor process.

Enabled automatically when: Windows + Npcap AdminOnly=1 + process not elevated.
Force off with STEALTHTAP_SCAPY_PROBE=1 (e.g. the scapy capture fallback).
"""
from __future__ import annotations

import importlib.abc
import importlib.util
import os
import sys

_INSTALLED = False


def _needs_guard() -> bool:
    if os.name != "nt" or os.environ.get("STEALTHTAP_SCAPY_PROBE") == "1":
        return False
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return False
    except Exception:
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as k:
            return int(winreg.QueryValueEx(k, "AdminOnly")[0]) == 1
    except OSError:
        return False


class _Hook(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name != "scapy.arch.libpcap":
            return None
        try:
            sys.meta_path.remove(self)
        except ValueError:
            pass
        spec = importlib.util.find_spec(name)
        if spec is None or spec.loader is None:
            return spec
        loader = spec.loader
        orig_exec = loader.exec_module

        def exec_module(module):
            orig_exec(module)
            module.load_winpcapy_original = getattr(module, "load_winpcapy", None)
            module.load_winpcapy = lambda *a, **k: None      # skip the Npcap adapter probe
        loader.exec_module = exec_module
        return spec


def install() -> bool:
    """Idempotent. Must run before scapy is first imported. Returns True if the guard is active."""
    global _INSTALLED
    if _INSTALLED:
        return True
    if "scapy.arch.libpcap" in sys.modules or not _needs_guard():
        return False
    sys.meta_path.insert(0, _Hook())
    _INSTALLED = True
    return True
