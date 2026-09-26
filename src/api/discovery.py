"""
Active device discovery of the LOCAL subnet -- complements the passive host inventory (which only knows
devices that happened to send a packet the sensor could see).

Deliberately narrow, because scanning networks you do not own is not okay:
  * host discovery only -- NO port scans: an unprivileged ARP-cache sweep (UDP datagram to the discard port to force ARP,
    then the OS neighbour table) or, when the sensor is elevated, `nmap -sn`;
  * the target range must sit inside a subnet this machine is actually attached to, be private
    (RFC1918 / link-local) and hold at most MAX_ADDRESSES addresses; a larger interface subnet is
    narrowed to the /24 around this host unless a smaller CIDR is given;
  * rate-limited (`--max-rate`), one sweep at a time.

    POST /network/discover   {interface?, cidr?}     -> {job_id}
    GET  /network/discover/{job_id}                  -> {status, cidr, hosts:[{ip, mac, vendor, hostname, latency_ms}]}
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/network", tags=["discovery"])

# Python's is_private also covers documentation/benchmark/CGNAT-adjacent ranges: allow exactly RFC1918 + link-local.
_SWEEPABLE = [ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]
MAX_ADDRESSES = 1024
MAX_RATE = int(os.environ.get("STEALTHTAP_DISCOVERY_MAX_RATE", "100"))     # probes/s
_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()


class DiscoverRequest(BaseModel):
    interface: Optional[str] = None
    cidr: Optional[str] = None


def _elevated() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _nmap() -> Optional[str]:
    p = shutil.which("nmap")
    if p:
        return p
    for c in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe", "/usr/bin/nmap"):
        if os.path.exists(c):
            return c
    return None


def local_subnets() -> list[tuple[str, ipaddress.IPv4Network, ipaddress.IPv4Address]]:
    """(interface, network, our address) for every up, non-loopback IPv4 interface."""
    import psutil
    out = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        for a in addrs:
            if a.family.name != "AF_INET" or not a.netmask:
                continue
            ip = ipaddress.IPv4Address(a.address)
            if ip.is_loopback or ip.is_link_local:
                continue
            out.append((name, ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False), ip))
    return out


def resolve_target(interface: Optional[str], cidr: Optional[str]) -> tuple[str, ipaddress.IPv4Network]:
    subs = [s for s in local_subnets() if interface is None or s[0] == interface]
    if not subs:
        raise HTTPException(422, "no usable local IPv4 subnet (is the interface up?)")
    if cidr:
        try:
            want = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            raise HTTPException(422, f"bad CIDR {cidr!r}")
        for name, net, _ip in subs:
            if want.subnet_of(net):
                target, iface = want, name
                break
        else:
            raise HTTPException(403, "the range must lie inside a subnet this machine is attached to")
    else:
        name, net, ip = subs[0]
        iface = name
        target = net if net.num_addresses <= 256 else ipaddress.IPv4Network(f"{ip}/24", strict=False)
    if not any(target.subnet_of(r) for r in _SWEEPABLE):
        raise HTTPException(403, "only private (RFC1918 / link-local) ranges may be swept")
    if target.num_addresses > MAX_ADDRESSES:
        raise HTTPException(422, f"range has {target.num_addresses} addresses; the limit is {MAX_ADDRESSES} — give a smaller CIDR")
    return iface, target


def _oui_table() -> dict[str, str]:
    exe = _nmap()
    tbl: dict[str, str] = {}
    if exe:
        f = os.path.join(os.path.dirname(exe), "nmap-mac-prefixes")
        if os.path.exists(f):
            for line in open(f, encoding="utf-8", errors="ignore"):
                if line[:1] != "#" and len(line) > 7:
                    tbl[line[:6].lower()] = line[7:].strip()
    return tbl


def _neighbors(target: ipaddress.IPv4Network) -> dict[str, str]:
    """{ip: mac} from the OS neighbour (ARP) table, restricted to `target`. No privileges needed."""
    out: dict[str, str] = {}
    if os.name == "nt":
        cp = subprocess.run(["powershell", "-NoProfile", "-Command",
                             "Get-NetNeighbor -AddressFamily IPv4 | Where-Object {$_.State -in 'Reachable','Stale','Delay','Probe','Permanent'} "
                             "| ForEach-Object { $_.IPAddress + ' ' + $_.LinkLayerAddress }"],
                            capture_output=True, text=True, timeout=30)
        pairs = [ln.split() for ln in cp.stdout.splitlines() if ln.strip()]
    else:
        cp = subprocess.run(["ip", "-4", "neigh"], capture_output=True, text=True, timeout=30)
        pairs = []
        for ln in cp.stdout.splitlines():
            t = ln.split()
            if "lladdr" in t and t[-1] not in ("FAILED", "INCOMPLETE"):
                pairs.append([t[0], t[t.index("lladdr") + 1]])
    for pr in pairs:
        if len(pr) < 2:
            continue
        try:
            ip = ipaddress.IPv4Address(pr[0])
        except ValueError:
            continue
        mac = pr[1].replace("-", ":").lower()
        if ip in target and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") and not mac.startswith("01:00:5e"):
            out[str(ip)] = mac
    return out


def _arp_sweep(target: ipaddress.IPv4Network) -> list[dict]:
    """Unprivileged, accurate LAN discovery: make the OS resolve every address in the range (a UDP datagram to the discard
    port forces an ARP request; no raw sockets, no firewall dependence -- a host answers ARP even when it drops every
    port), then read the neighbour table. Only on-link hosts that actually answered ARP appear."""
    import socket
    gap = 1.0 / max(1, MAX_RATE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for ip in target.hosts():
            try:
                sock.sendto(bytes(1), (str(ip), 9))
            except OSError:
                pass
            time.sleep(gap)
    finally:
        sock.close()
    time.sleep(2.5)                                    # let late ARP replies land
    oui = _oui_table()
    rows = []
    for ip, mac in _neighbors(target).items():
        rows.append({"ip": ip, "mac": mac, "vendor": oui.get(mac.replace(":", "")[:6]), "hostname": None, "latency_ms": None})
    return rows


def _run(job_id: str, iface: str, target: ipaddress.IPv4Network) -> None:
    job = _JOBS[job_id]
    try:
        if _elevated() and _nmap():
            cp = subprocess.run([_nmap(), "-sn", "-n", "--max-rate", str(MAX_RATE), "-oX", "-", str(target)],
                                capture_output=True, text=True, timeout=600)
            root = ET.fromstring(cp.stdout)
            hosts = []
            for h in root.findall("host"):
                st = h.find("status")
                if st is None or st.get("state") != "up":
                    continue
                row = {"ip": "", "mac": None, "vendor": None, "hostname": None, "latency_ms": None}
                for a in h.findall("address"):
                    if a.get("addrtype") == "ipv4":
                        row["ip"] = a.get("addr")
                    elif a.get("addrtype") == "mac":
                        row["mac"], row["vendor"] = (a.get("addr") or "").lower(), a.get("vendor")
                t = h.find("times")
                if t is not None and t.get("srtt"):
                    row["latency_ms"] = round(int(t.get("srtt")) / 1000, 2)
                hosts.append(row)
            mode = "nmap ARP/ping sweep (elevated)"
        else:
            hosts = _arp_sweep(target)
            mode = "ARP-cache sweep (unprivileged)"
        hosts.sort(key=lambda r: tuple(int(x) for x in r["ip"].split(".")))
        job.update(status="done", hosts=hosts, finished=time.time(), mode=mode)
    except Exception as exc:
        job.update(status="error", error=f"{type(exc).__name__}: {exc}")


@router.post("/discover", status_code=202)
def discover(req: DiscoverRequest):
    iface, target = resolve_target(req.interface, req.cidr)
    with _LOCK:
        if any(j["status"] == "running" for j in _JOBS.values()):
            raise HTTPException(409, "a discovery sweep is already running")
        for jid in [j for j, v in _JOBS.items() if time.time() - v["created"] > 3600]:
            _JOBS.pop(jid, None)
        job_id = uuid.uuid4().hex
        _JOBS[job_id] = {"status": "running", "created": time.time(), "cidr": str(target), "interface": iface, "hosts": []}
    threading.Thread(target=_run, args=(job_id, iface, target), daemon=True, name="discovery").start()
    return {"job_id": job_id, "cidr": str(target), "interface": iface, "addresses": target.num_addresses}


@router.get("/discover/{job_id}")
def discover_result(job_id: str):
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown or expired job")
    return {"job_id": job_id, **{k: v for k, v in job.items() if k != "created"}}
