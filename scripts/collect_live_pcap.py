"""
Record REAL live traffic from a running (elevated) sensor into a classic pcap, for offline evaluation.

    python scripts/collect_live_pcap.py --sensor http://127.0.0.1:8108 --iface Wi-Fi --minutes 20 --out data/benign_live/wifi.pcap

The sensor keeps only a bounded packet ring, so this polls `/capture/packets?after=<last id>` and pulls every new packet by
id through `/capture/export.pcap`, keeping a running high-water mark (no duplicates, gaps are counted and reported).
Nothing is synthesised. The output contains real payloads from this network: keep it local (data/benign_live is git-ignored).
Traffic is whatever the machine and its users generate; add `--drive` to also fetch a few real web pages/downloads.
"""
from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def call(base, path, body=None, key=None, timeout=60, raw=False):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **({"X-API-Key": key} if key else {})},
                                 method="GET" if body is None else "POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if raw else json.loads(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sensor", required=True)
    ap.add_argument("--iface", default="Wi-Fi")
    ap.add_argument("--minutes", type=float, default=20)
    ap.add_argument("--out", default="data/benign_live/wifi.pcap")
    ap.add_argument("--key", default=None)
    ap.add_argument("--drive", action="store_true", help="also run scripts/live_soak.py --traffic-only for real page loads/downloads")
    a = ap.parse_args()
    base, out = a.sensor.rstrip("/"), Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    try:
        call(base, "/capture/stop", {}, a.key)
    except Exception:
        pass
    call(base, "/capture/start", {"interface": a.iface, "bpf": "ip or ip6"}, a.key)
    child = None
    if a.drive:
        child = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "live_soak.py"), "--iface", a.iface, "--streams", "2", "--traffic-only"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    last, n, gaps, t_end = 0, 0, 0, time.time() + a.minutes * 60
    with out.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        while time.time() < t_end:
            rows = call(base, f"/capture/packets?after={last}&limit=2000", key=a.key)
            rows = rows if isinstance(rows, list) else rows.get("rows", [])
            if rows:
                ids = [r["id"] for r in rows]
                if last and ids[0] > last + 1:
                    gaps += ids[0] - last - 1
                blob = call(base, "/capture/export.pcap?ids=" + ",".join(map(str, ids)) + "&limit=2000", key=a.key, raw=True, timeout=120)
                f.write(blob[24:])                      # drop the per-file header, keep the packet records
                n += len(ids)
                last = ids[-1]
            f.flush()
            if len(rows) < 2000:
                time.sleep(1.0)
    if child:
        child.kill()
    call(base, "/capture/stop", {}, a.key)
    print(json.dumps({"packets": n, "ring_gaps": gaps, "file": str(out), "bytes": out.stat().st_size}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
