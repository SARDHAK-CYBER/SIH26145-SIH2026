"""
Real-NIC validation through a running (elevated) sensor -- waits for it, then measures.

    python scripts/live_validate.py --sensor http://127.0.0.1:8107 --iface Wi-Fi --seconds 60 [--wait 900]

* waits (up to --wait s) until the sensor answers /health, i.e. until the UAC approval happened and it started
* starts a capture on the interface, drives real internet traffic from a separate process (parallel downloads + page loads)
* compares packets seen by the engine with the NIC's own counters, reports drops, rate, hosts, IPv6, shards and per-protocol
  decoder counters, false-positive-relevant alerts (with the periodic test-traffic classes labelled), and the coverage verdict
* writes docs/reports/live_nic_validation.json
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

ROOT = Path(__file__).resolve().parent.parent


def get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def post(url, body=None, timeout=120):
    req = urllib.request.Request(url, data=json.dumps(body or {}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def nic_packets(iface: str) -> int:
    if os.name == "nt":
        ps = (f"$s=Get-NetAdapterStatistics -Name '{iface}'; "
              "($s.ReceivedUnicastPackets+$s.SentUnicastPackets+$s.ReceivedMulticastPackets+$s.SentMulticastPackets+"
              "$s.ReceivedBroadcastPackets+$s.SentBroadcastPackets)")
        return int(subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True).stdout.strip())
    with open("/proc/net/dev") as f:
        for line in f:
            if line.strip().startswith(iface + ":"):
                p = line.split(":")[1].split()
                return int(p[1]) + int(p[9])
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sensor", required=True)
    ap.add_argument("--iface", default="Wi-Fi")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--streams", type=int, default=4)
    ap.add_argument("--wait", type=int, default=900)
    a = ap.parse_args()
    base = a.sensor.rstrip("/")

    t0 = time.time()
    while True:
        try:
            get(base + "/health", 3)
            break
        except Exception:
            if time.time() - t0 > a.wait:
                print("sensor never came up (was the UAC prompt approved?)", file=sys.stderr)
                return 2
            time.sleep(3)
    print(f"sensor up after {time.time() - t0:.0f}s: {get(base + '/capture/capabilities')}")

    try:
        post(base + "/capture/stop")
    except Exception:
        pass
    post(base + "/capture/start", {"interface": a.iface, "bpf": "ip or ip6 or arp"})
    time.sleep(3)
    child = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "live_soak.py"), "--iface", a.iface, "--streams", str(a.streams),
                              "--traffic-only"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    n0, r0 = nic_packets(a.iface), get(base + "/capture/status")["capture"]["recv"]
    t1 = time.time()
    peak = 0.0
    while time.time() - t1 < a.seconds:
        time.sleep(2)
        peak = max(peak, get(base + "/capture/status").get("throughput", {}).get("mbps") or 0)
    n1, st = nic_packets(a.iface), get(base + "/capture/status")
    child.kill()
    cap = st["capture"]
    agent_pk, nic_pk = cap["recv"] - r0, n1 - n0
    hosts = get(base + "/capture/hosts?limit=2000")
    v6 = [h for h in hosts if ":" in h["ip"]]
    prot = {p["name"]: p["packets"] for p in get(base + "/capture/protocols")}
    summ = get(base + "/capture/summary")
    cov = get(base + "/capture/coverage")
    alerts = get(base + "/capture/alerts?limit=500")
    by = {}
    for x in alerts:
        by[x["threat_class"]] = by.get(x["threat_class"], 0) + 1
    ml_alerts = [x for x in alerts if x.get("detection_mode") != "rule"]
    out = {
        "sensor": base, "iface": a.iface, "seconds": a.seconds, "shards": cap.get("shards"), "native": st.get("native"),
        "agent_packets": agent_pk, "nic_packets": nic_pk, "capture_ratio": round(agent_pk / nic_pk, 4) if nic_pk else None,
        "kernel_drops": cap["kernel_drop"], "records_dropped": cap["records_dropped"], "user_drops": st.get("dropped"),
        "peak_mbps": round(peak, 1), "hosts_seen": len(hosts), "ipv6_hosts": len(v6),
        "ipv6_global_hosts": [h["ip"] for h in v6 if not h["ip"].startswith(("fe80", "ff"))][:5],
        "protocol_packets": prot,
        "decoders": {k: cap.get(k) for k in ("dns", "ssl", "http", "kerberos", "s7comm", "iec104", "cip", "bacnet", "opcua", "profinet", "modbus", "dnp3")},
        "alerts_by_class": by, "ml_alerts": len(ml_alerts), "coverage": cov,
        "latency": st.get("detection_latency"),
    }
    Path(ROOT / "docs" / "reports" / "live_nic_validation.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))
    try:
        post(base + "/capture/stop")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
