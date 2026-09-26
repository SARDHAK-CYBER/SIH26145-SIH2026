"""
Accuracy of the LIVE pipeline on real labelled captures.

Every capture in a folder is replayed ONCE (no loops -- looping makes any flow look periodic)
through the native capture engine and all engines/models, exactly as a NIC would feed them,
and the alerts are compared with the file-level label:

    * files named like the benign set (normal*, benign*) are expected CLEAN
    * every other file is an attack capture and is expected to raise >= 1 alert

    python scripts/live_replay_eval.py "C:/.../pcap folder" [--exclude mirai.pcap] [--out docs/reports/live_replay_eval.json]

Reports per-file alerts (by class), detection recall on attack files, benign-file cleanliness,
alerts per 1,000 benign flows, packets/s and detection latency. mirai (94 MB) is included unless excluded.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import src  # noqa: E402,F401
from src.capture.live_agent import LiveAgent  # noqa: E402

BENIGN_PREFIXES = ("normal", "benign")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--exclude", nargs="*", default=[])
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    files = sorted(p for p in Path(a.folder).glob("*.pcap") if p.name not in a.exclude)
    seen_sizes: dict[int, str] = {}
    rows = []
    for f in files:
        dup = seen_sizes.get(f.stat().st_size)          # the corpus contains byte-identical duplicates
        seen_sizes.setdefault(f.stat().st_size, f.name)
        agent = LiveAgent("pcap-replay", None)
        t0 = time.time()
        agent.start_replay(str(f), loops=1, speed=0.0)
        agent._loop_thread.join()
        dt = time.time() - t0
        st = agent.status()
        cap = st["capture"]
        summ = agent.summary()
        lat = st["detection_latency"]
        benign = f.name.lower().startswith(BENIGN_PREFIXES)
        rows.append({
            "file": f.name, "mb": round(f.stat().st_size / 1e6, 1), "benign": benign, "duplicate_of": dup,
            "packets": cap["recv"], "flows": cap["flows_seen"], "seconds": round(dt, 2),
            "pps": round(cap["recv"] / dt) if dt else 0,
            "alerts": st["alerts"], "by_class": summ["alerts_by_class"], "p95_latency_ms": lat.get("p95_ms"),
        })
        agent.stop()
        r = rows[-1]
        print(f"{r['file']:<28} {r['mb']:>6.1f}MB pk={r['packets']:>8} fl={r['flows']:>7} {r['seconds']:>6.1f}s "
              f"{r['pps']:>8} pps  alerts={r['alerts']:>4} {r['by_class']}", flush=True)

    uniq = [r for r in rows if not r["duplicate_of"]]
    attacks = [r for r in uniq if not r["benign"]]
    benigns = [r for r in uniq if r["benign"]]
    hit = [r for r in attacks if r["alerts"] > 0]
    out = {
        "attack_files": len(attacks), "attack_detected": len(hit),
        "recall": round(len(hit) / len(attacks), 3) if attacks else None,
        "missed": [r["file"] for r in attacks if r["alerts"] == 0],
        "benign_files": len(benigns), "benign_clean": sum(1 for r in benigns if r["alerts"] == 0),
        "benign_alerts": {r["file"]: r["by_class"] for r in benigns if r["alerts"]},
        "benign_alerts_per_1000_flows": (round(1000 * sum(r["alerts"] for r in benigns) / max(1, sum(r["flows"] for r in benigns)), 2)),
        "note": "file-level ground truth, duplicates removed, single pass per file",
    }
    print(json.dumps(out, indent=2))
    if a.out:
        Path(a.out).write_text(json.dumps({"summary": out, "files": rows}, indent=1))


if __name__ == "__main__":
    main()
