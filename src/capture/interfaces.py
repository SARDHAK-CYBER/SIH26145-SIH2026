"""
Network-interface enumeration for the "pick an interface" step (the
Wireshark-style capture picker).

Cross-platform: uses psutil for addresses / link state / speed, and
merges scapy's view (npf device names, human descriptions) when present.
Never raises -- a backend that can't enumerate just contributes nothing.
"""
from __future__ import annotations

import platform
import socket
from dataclasses import dataclass, asdict, field
from typing import Any


@dataclass
class InterfaceInfo:
    name: str                       # OS interface name (what you pass to --iface)
    description: str = ""            # human-readable NIC description
    mac: str = ""
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    is_up: bool = False
    is_loopback: bool = False
    speed_mbps: int = 0
    mtu: int = 0
    capture_name: str = ""           # the name the active capture backend wants
    kernel_capture: bool = False     # True if AF_PACKET kernel ring is usable for this iface

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _psutil_interfaces() -> dict[str, InterfaceInfo]:
    out: dict[str, InterfaceInfo] = {}
    try:
        import psutil
    except Exception:
        return out

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addrs.items():
        info = InterfaceInfo(name=name)
        st = stats.get(name)
        if st is not None:
            info.is_up = bool(st.isup)
            info.speed_mbps = int(getattr(st, "speed", 0) or 0)
            info.mtu = int(getattr(st, "mtu", 0) or 0)
        for a in addr_list:
            fam = getattr(a, "family", None)
            if fam == socket.AF_INET:
                info.ipv4.append(a.address)
            elif fam == socket.AF_INET6:
                info.ipv6.append(a.address.split("%")[0])
            elif str(fam).endswith("AF_LINK") or str(fam).endswith("AF_PACKET"):
                info.mac = a.address
        info.is_loopback = name.lower().startswith(("lo", "loopback")) or "127.0.0.1" in info.ipv4
        out[name] = info
    return out


def _windows_guid_map() -> dict[str, str]:
    """friendly-name -> \\Device\\NPF_{GUID}, straight from the registry
    via winreg (stdlib). No scapy, no PowerShell subprocess -- importing
    scapy.arch.windows / calling get_windows_if_list() can block for
    minutes on some hosts while it shells out to Get-NetAdapter."""
    out: dict[str, str] = {}
    try:
        import winreg
    except Exception:
        return out
    key_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root:
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                if not guid.startswith("{"):
                    continue
                try:
                    with winreg.OpenKey(root, guid + r"\Connection") as conn:
                        name, _ = winreg.QueryValueEx(conn, "Name")
                        out[name] = f"\\Device\\NPF_{guid}"
                except OSError:
                    continue
    except OSError:
        pass
    return out


def _scapy_overlay(infos: dict[str, InterfaceInfo]) -> None:
    """Fill capture_name (the string libpcap/Npcap wants)."""
    if platform.system() == "Windows":
        guid_map = _windows_guid_map()
        for name, info in infos.items():
            info.capture_name = guid_map.get(name, name)
    else:
        for name, info in infos.items():
            info.capture_name = name


def _mark_kernel_capture(infos: dict[str, InterfaceInfo]) -> None:
    """AF_PACKET (kernel ring) is Linux-only and needs CAP_NET_RAW."""
    if platform.system() != "Linux":
        return
    import os
    can_raw = os.geteuid() == 0 or _has_cap_net_raw()
    for info in infos.values():
        info.kernel_capture = can_raw and not info.is_loopback


def _has_cap_net_raw() -> bool:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)  # type: ignore[attr-defined]
        s.close()
        return True
    except Exception:
        return False


_CACHE: dict = {"t": 0.0, "rows": None}
_CACHE_TTL_S = 8.0


def list_interfaces(include_down: bool = True, include_loopback: bool = False) -> list[InterfaceInfo]:
    import time as _t
    now = _t.monotonic()
    if _CACHE["rows"] is None or (now - _CACHE["t"]) > _CACHE_TTL_S:
        infos = _psutil_interfaces()
        _scapy_overlay(infos)
        _mark_kernel_capture(infos)
        _CACHE["rows"] = list(infos.values())
        _CACHE["t"] = now
    all_rows = _CACHE["rows"]
    return _filter_sort(all_rows, include_down, include_loopback)


def _filter_sort(rows, include_down, include_loopback):
    result = []
    for info in rows:
        if not include_loopback and info.is_loopback:
            continue
        if not include_down and not info.is_up:
            continue
        result.append(info)
    # Up interfaces first, then by speed desc, then name.
    result.sort(key=lambda i: (not i.is_up, -i.speed_mbps, i.name.lower()))
    return result


def resolve_capture_name(iface: str) -> str:
    """Map a user-supplied interface name to what the backend needs
    (e.g. Windows \\Device\\NPF_{GUID})."""
    for info in list_interfaces(include_down=True, include_loopback=True):
        if iface in (info.name, info.capture_name, info.description):
            return info.capture_name or info.name
    return iface


if __name__ == "__main__":
    import json
    print(json.dumps([i.as_dict() for i in list_interfaces(include_loopback=True)], indent=2))
