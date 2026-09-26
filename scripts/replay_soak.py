"""
Hardness test: push REAL captures through the full live pipeline (native capture thread ->
assembler -> 13 engines + ML -> alerts) as fast as it will go, for as long as asked.

    python scripts/replay_soak.py "C:/.../mirai.pcap" --seconds 120            # loop one file
    python scripts/replay_soak.py dir_of_pcaps/ --seconds 600                  # every file, forever
    python scripts/replay_soak.py x.pcap --speed 1.0 --seconds 60              # original timing

Reports per second: pps / Mbit/s, pending records, active flows, alerts, RSS and CPU; and at the
end: packets processed, sustained pps/Gbit/s, alert counts by class, memory growth (a leak shows
as RSS climbing over identical loops), and any records dropped.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psutil  # noqa: E402

import src  # noqa: E402,F401
from src.capture.live_agent import LiveAgent  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--per-file", type=int, default=30, help="seconds each file loops before the next (directory mode)")
    ap.add_argument("--speed", type=float, default=0.0)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    p = Path(a.path)
    files = sorted(f for f in p.glob("*.pcap")) if p.is_dir() else [p]
    files = [f for f in files if f.stat().st_size > 0]
    me = psutil.Process()
    rows = []
    totals = {"packets": 0, "bytes": 0}
    classes: dict[str, int] = {}
    t_begin = time.time()
    agent = None
    fi = 0
    me.cpu_percent(None)
    print(f"{'t':>4} {'file':<22} {'pps':>9} {'Mbit/s':>8} {'pend':>8} {'flows':>8} {'alerts':>7} {'cpu%':>6} {'rssMB':>7}")
    while time.time() - t_begin < a.seconds:
        f = files[fi % len(files)]
        fi += 1
        agent = LiveAgent("pcap-replay", None, num_workers=a.workers)
        agent.start_replay(str(f), loops=0, speed=a.speed)      # loop the file until we stop it
        cap = agent._ncap
        t_file = time.time()
        while agent._loop_thread.is_alive() and time.time() - t_file < a.per_file:
            time.sleep(1.0)
            s = agent.status()
            tp = s.get("throughput") or {}
            row = {"t": round(time.time() - t_begin), "file": f.name, "pps": tp.get("pps") or 0, "mbps": tp.get("mbps") or 0,
                   "pend": s["capture"]["pending_records"], "flows": s["active_flows"], "alerts": s["alerts"],
                   "cpu": me.cpu_percent(None), "rss": round(me.memory_info().rss / 1e6)}
            rows.append(row)
            print(f"{row['t']:>4} {f.name[:22]:<22} {row['pps']:>9.0f} {row['mbps']:>8.1f} {row['pend']:>8} {row['flows']:>8} "
                  f"{row['alerts']:>7} {row['cpu']:>6.0f} {row['rss']:>7}")
            if time.time() - t_begin >= a.seconds:
                break
        st = cap.stats()
        totals["packets"] += st["recv"]
        totals["bytes"] += st["bytes"]
        for k, v in agent.summary()["alerts_by_class"].items():
            classes[k] = classes.get(k, 0) + v
        rec_drop = st["records_dropped"]
        agent.stop()
    dt = time.time() - t_begin
    out = {"seconds": round(dt, 1), "files": len(files), "packets": totals["packets"], "bytes": totals["bytes"],
           "avg_pps": round(totals["packets"] / dt), "avg_gbit_s": round(totals["bytes"] * 8 / dt / 1e9, 3),
           "peak_pps": max((r["pps"] for r in rows), default=0), "alerts_by_class": classes,
           "max_rss_mb": max((r["rss"] for r in rows), default=0), "records_dropped_last": rec_drop}
    print(json.dumps(out, indent=2))
    if a.out:
        Path(a.out).write_text(json.dumps({"summary": out, "samples": rows}, indent=1))


if __name__ == "__main__":
    main()
