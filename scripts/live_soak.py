"""
Real-traffic live soak test.

Runs the LiveAgent on a REAL interface, generates REAL network load (parallel
HTTPS downloads from public speed-test endpoints, DNS lookups, many short TLS
connections) and cross-checks the capture against the NIC's own counters, so
capture loss anywhere in the stack (driver ring, pcap buffer, queue, assembler)
shows up as a number instead of a feeling.

    python scripts/live_soak.py --iface Wi-Fi --seconds 120 --streams 4
    python scripts/live_soak.py --iface Wi-Fi --seconds 600 --streams 8 --out docs/reports/soak.json

Reports, sampled every second: pps / Mbit/s seen by the agent, queue depth,
drops, active flows, detection latency percentiles, process CPU and RSS, and at
the end  agent_packets / nic_packets  (should be ~1.0 on a host-only capture).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("SCAPY_USE_PCAPDNET", "1")

import psutil  # noqa: E402

from src.capture.live_agent import LiveAgent  # noqa: E402

DL_URLS = [
    "https://speed.cloudflare.com/__down?bytes=200000000",
    "https://proof.ovh.net/files/100Mb.dat",
    "https://speed.hetzner.de/100MB.bin",
]
SITES = ["www.wikipedia.org", "github.com", "www.bbc.com", "www.reddit.com", "news.ycombinator.com",
         "www.python.org", "www.mozilla.org", "www.cloudflare.com", "www.apple.com", "www.microsoft.com"]


def nic_counters(iface: str):
    """(rx+tx packets, rx+tx bytes) from the OS for this interface."""
    if os.name == "nt":
        ps = (f"$s=Get-NetAdapterStatistics -Name '{iface}'; "
              "'{0} {1}' -f ($s.ReceivedUnicastPackets+$s.SentUnicastPackets+$s.ReceivedMulticastPackets+"
              "$s.SentMulticastPackets+$s.ReceivedBroadcastPackets+$s.SentBroadcastPackets),"
              "($s.ReceivedBytes+$s.SentBytes)")
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True).stdout.split()
        return int(out[0]), int(out[1])
    with open("/proc/net/dev") as f:
        for line in f:
            if line.strip().startswith(iface + ":"):
                p = line.split(":")[1].split()
                return int(p[1]) + int(p[9]), int(p[0]) + int(p[8])
    return 0, 0


class Traffic:
    """Real internet load. Every worker loops until stop()."""

    def __init__(self, streams: int):
        self.streams = streams
        self.stop_ev = threading.Event()
        self.threads: list[threading.Thread] = []
        self.bytes = 0
        self.errors = 0

    def _dl(self, i: int):
        import httpx
        url = DL_URLS[i % len(DL_URLS)]
        while not self.stop_ev.is_set():
            try:
                with httpx.stream("GET", url, timeout=20, follow_redirects=True) as r:
                    for chunk in r.iter_bytes(65536):
                        self.bytes += len(chunk)
                        if self.stop_ev.is_set():
                            break
            except Exception:
                self.errors += 1
                time.sleep(1)

    def _web(self):
        import httpx
        import socket
        n = 0
        while not self.stop_ev.is_set():
            host = SITES[n % len(SITES)]
            n += 1
            try:
                socket.getaddrinfo(host, 443)
                httpx.get(f"https://{host}/", timeout=8, follow_redirects=True)
            except Exception:
                self.errors += 1
            time.sleep(0.2)

    def start(self):
        for i in range(self.streams):
            t = threading.Thread(target=self._dl, args=(i,), daemon=True)
            t.start(); self.threads.append(t)
        t = threading.Thread(target=self._web, daemon=True)
        t.start(); self.threads.append(t)

    def stop(self):
        self.stop_ev.set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--streams", type=int, default=4)
    ap.add_argument("--bpf", default="ip or ip6")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--no-traffic", action="store_true")
    ap.add_argument("--traffic-only", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    if a.traffic_only:            # child process: generate load until killed
        t = Traffic(a.streams); t.start()
        while True:
            time.sleep(1)

    agent = LiveAgent(a.iface, a.bpf, num_workers=a.workers)
    me = psutil.Process()
    p0, b0 = nic_counters(a.iface)
    agent.start()
    tr = Traffic(0)
    child = None
    if not a.no_traffic:
        # separate process: load generation must not steal the agent's CPU/GIL
        child = subprocess.Popen([sys.executable, __file__, "--iface", a.iface, "--streams", str(a.streams),
                                  "--traffic-only"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()
    rows = []
    print(f"{'t':>4} {'pps':>9} {'Mbit/s':>8} {'q':>7} {'udrop':>7} {'kdrop':>7} {'flows':>7} {'p95ms':>8} {'cpu%':>6} {'rssMB':>7} {'alerts':>6}")
    me.cpu_percent(None)
    try:
        while time.time() - t0 < a.seconds:
            time.sleep(1.0)
            s = agent.status()
            tp = s.get("throughput") or {}
            lat = s.get("detection_latency") or {}
            cpu = me.cpu_percent(None)
            rss = me.memory_info().rss / 1e6
            row = {"t": round(time.time() - t0), "pps": tp.get("pps"), "mbps": tp.get("mbps"),
                   "q": s["queue_depth"], "udrop": s["dropped"], "kdrop": tp.get("kernel_drop_total"),
                   "flows": s["active_flows"], "p95": lat.get("p95_ms"), "cpu": cpu, "rss": round(rss),
                   "alerts": s["alerts"]}
            rows.append(row)
            if row["t"] % 2 == 0:
                print(f"{row['t']:>4} {row['pps'] or 0:>9.0f} {row['mbps'] or 0:>8.2f} {row['q']:>7} {row['udrop']:>7} "
                      f"{str(row['kdrop']):>7} {row['flows']:>7} {str(row['p95']):>8} {cpu:>6.0f} {rss:>7.0f} {row['alerts']:>6}")
    finally:
        if child is not None:
            child.kill()
        time.sleep(1.0)
        s_end = agent.status()
        agent.stop()
    p1, b1 = nic_counters(a.iface)
    asm_pk = s_end["assembler"]["packets"]
    nic_pk = p1 - p0
    summary = {
        "iface": a.iface, "seconds": a.seconds, "streams": a.streams,
        "agent_packets": asm_pk, "nic_packets": nic_pk,
        "capture_ratio": round(asm_pk / nic_pk, 4) if nic_pk else None,
        "nic_bytes": b1 - b0,         "peak_pps": max((r["pps"] or 0) for r in rows) if rows else 0,
        "peak_mbps": max((r["mbps"] or 0) for r in rows) if rows else 0,
        "user_drops": s_end["dropped"], "kernel_drops": (s_end.get("throughput") or {}).get("kernel_drop_total"),
        "alerts": s_end["alerts"], "detection_latency": s_end.get("detection_latency"),
        "max_rss_mb": max(r["rss"] for r in rows) if rows else 0,
        "rss_first_last_mb": [rows[0]["rss"], rows[-1]["rss"]] if rows else None,
    }
    print(json.dumps(summary, indent=2))
    if a.out:
        Path(a.out).write_text(json.dumps({"summary": summary, "samples": rows}, indent=1))


if __name__ == "__main__":
    main()
