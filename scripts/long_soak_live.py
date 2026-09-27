"""
Long live-link soak through a running sensor, with real traffic, unattended:

    python scripts/long_soak_live.py --sensor http://127.0.0.1:8100 --iface Wi-Fi --hours 2.5 [--drive-streams 1]

Starts a capture on the interface (optionally with a modest real-traffic generator on top of whatever the network carries),
samples every 30 s (packets seen, kernel/user drops, active flows, alerts, detection latency, the sensor process's RSS/CPU/handles,
NIC counters) into docs/reports/live_soak_<name>.jsonl, saves each NEW alert (with evidence) for triage, restarts the capture if it
stops, records any time the sensor stops answering, and at the end writes docs/reports/live_soak_<name>.json:
capture ratio against the NIC's own counters, total drops, memory start/end and least-squares slope after warm-up (a leak shows as
a positive slope), worst detection latency, alerts by class, sensor outages.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent


def call(base, path, body=None, timeout=15):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="GET" if body is None else "POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def nic_packets(iface: str) -> int:
    ps = (f"$s=Get-NetAdapterStatistics -Name '{iface}'; ($s.ReceivedUnicastPackets+$s.SentUnicastPackets+$s.ReceivedMulticastPackets+"
          "$s.SentMulticastPackets+$s.ReceivedBroadcastPackets+$s.SentBroadcastPackets)")
    try:
        return int(subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=30).stdout.strip())
    except Exception:
        return 0


def sensor_proc(port: int):
    for c in psutil.net_connections():
        if c.laddr and c.laddr.port == port and c.status == "LISTEN":
            try:
                return psutil.Process(c.pid)
            except psutil.Error:
                return None
    return None


def slope_mb_per_hour(samples: list[tuple[float, float]]) -> float:
    if len(samples) < 4:
        return 0.0
    n = len(samples)
    mx = sum(t for t, _ in samples) / n
    my = sum(v for _, v in samples) / n
    den = sum((t - mx) ** 2 for t, _ in samples) or 1.0
    return sum((t - mx) * (v - my) for t, v in samples) / den * 3600.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sensor", default="http://127.0.0.1:8100")
    ap.add_argument("--iface", default="Wi-Fi")
    ap.add_argument("--hours", type=float, default=2.5)
    ap.add_argument("--name", default="wifi")
    ap.add_argument("--drive-streams", type=int, default=0, help="also run scripts/live_soak.py --traffic-only with this many streams")
    ap.add_argument("--interval", type=float, default=30.0)
    a = ap.parse_args()
    base, port = a.sensor.rstrip("/"), int(a.sensor.rsplit(":", 1)[1])
    out = ROOT / "docs" / "reports"
    jl, sm, alerts_f = out / f"live_soak_{a.name}.jsonl", out / f"live_soak_{a.name}.json", out / f"live_soak_{a.name}_alerts.jsonl"
    jl.write_text("")
    alerts_f.write_text("")

    def start():
        try:
            call(base, "/capture/stop", {})
        except Exception:
            pass
        call(base, "/capture/start", {"interface": a.iface, "bpf": "ip or ip6 or arp"})

    start()
    child = None
    if a.drive_streams:
        child = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "live_soak.py"), "--iface", a.iface, "--streams", str(a.drive_streams),
                                  "--traffic-only"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    t0, nic0 = time.time(), nic_packets(a.iface)
    base_recv = call(base, "/capture/status")["capture"]["recv"]
    seen_alerts: set[str] = set()
    rss, lat_max, outages, restarts, by_class = [], 0.0, [], 0, {}
    last_ok, down_since = time.time(), None
    print(f"soak started {time.strftime('%H:%M:%S')} for {a.hours} h", flush=True)
    while time.time() - t0 < a.hours * 3600:
        time.sleep(a.interval)
        row = {"t": round(time.time() - t0)}
        try:
            st = call(base, "/capture/status")
            if down_since:
                outages.append({"from": down_since, "seconds": round(time.time() - down_since)})
                down_since = None
            if not st.get("running"):
                restarts += 1
                start()
                base_recv = 0
                st = call(base, "/capture/status")
            c = st["capture"]
            row.update(recv=c["recv"], kernel_drop=c["kernel_drop"], if_drop=c.get("if_drop", 0), records_dropped=c["records_dropped"],
                       user_drops=st.get("dropped"), flows=c["active_flows"], hosts=c["hosts"], alerts=st["alerts"],
                       mbps=(st.get("throughput") or {}).get("mbps"), pps=(st.get("throughput") or {}).get("pps"),
                       p95_ms=(st.get("detection_latency") or {}).get("p95_ms"), pending=c["pending_records"])
            lat_max = max(lat_max, (st.get("detection_latency") or {}).get("max_ms") or 0.0)
            for al in call(base, "/capture/alerts?limit=200"):
                if al["alert_id"] not in seen_alerts:
                    seen_alerts.add(al["alert_id"])
                    by_class[al["threat_class"]] = by_class.get(al["threat_class"], 0) + 1
                    with alerts_f.open("a") as f:
                        f.write(json.dumps(al) + "\n")
        except Exception as exc:
            if not down_since:
                down_since = time.time()
            row["error"] = f"{type(exc).__name__}: {exc}"[:120]
        p = sensor_proc(port)
        if p is not None:
            try:
                mi = p.memory_info()
                row.update(rss_mb=round(mi.rss / 1e6, 1), cpu=p.cpu_percent(None), threads=p.num_threads())
                rss.append((time.time() - t0, mi.rss / 1e6))
            except psutil.Error:
                pass
        with jl.open("a") as f:
            f.write(json.dumps(row) + "\n")
    if child:
        child.kill()
    st = call(base, "/capture/status")
    nic1 = nic_packets(a.iface)
    dur = time.time() - t0
    warm = [(t, v) for t, v in rss if t > 900] or rss
    summary = {
        "iface": a.iface, "hours": round(dur / 3600, 2), "driver_streams": a.drive_streams,
        "packets_sensor": st["capture"]["recv"] - base_recv, "packets_nic": nic1 - nic0,
        "capture_ratio": round((st["capture"]["recv"] - base_recv) / max(1, nic1 - nic0), 4),
        "kernel_drop": st["capture"]["kernel_drop"], "records_dropped": st["capture"]["records_dropped"], "user_drops": st.get("dropped"),
        "capture_restarts": restarts, "sensor_outages": outages,
        "rss_start_mb": round(rss[0][1], 1) if rss else None, "rss_end_mb": round(rss[-1][1], 1) if rss else None,
        "rss_max_mb": round(max(v for _, v in rss), 1) if rss else None, "rss_slope_mb_per_hour_after_15min": round(slope_mb_per_hour(warm), 2),
        "detection_latency_max_ms": lat_max, "alerts_total": len(seen_alerts), "alerts_by_class": by_class,
        "alerts_per_hour": round(len(seen_alerts) / (dur / 3600), 2),
    }
    sm.write_text(json.dumps(summary, indent=1))
    try:
        call(base, "/capture/stop", {})
    except Exception:
        pass
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
