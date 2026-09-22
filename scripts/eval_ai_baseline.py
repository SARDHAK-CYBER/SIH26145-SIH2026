#!/usr/bin/env python3
"""
Prototype: UNSUPERVISED learned-baseline detector, evaluated on the same
labelled real captures as scripts/eval_real_traffic.py.

Trains an Isolation Forest ONLY on benign traffic (normal.pcap) -- it never
sees an attack -- then scores every other capture. Two feature sets:

    two_way  -- flow features using both directions (orig + resp bytes)
    one_way  -- ONLY what a one-directional tap would see: no responder-side
                bytes/ratios. Per-source fan-out is kept (needs only the
                forward direction).

A capture is flagged if the fraction of its flows scored anomalous exceeds
FILE_FLAG_FRACTION. The per-flow threshold is the 99.5th percentile of
scores on HELD-OUT benign flows (last 30% of normal.pcap by time), so it
is fixed before any attack file is looked at. normal2.pcap is a second,
untouched benign capture used as the false-positive test.

Everything here is a prototype on a tiny, single-environment benign set:
treat the numbers as a direction indicator, not a product claim.
"""
from __future__ import annotations

import argparse
import json
import math
import pickle
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TRAIN_FILE = "normal.pcap"
BENIGN_TEST = "normal2.pcap"
UNLABELLED = {"check-output.pcapng"}
FILE_FLAG_FRACTION = 0.05
FLOW_QUANTILE = 0.995
WINDOW_S = 60.0


def feats(conn: list[dict], one_way: bool) -> np.ndarray:
    """Per-flow feature matrix. Fan-out features are per (source, 60 s window)
    and use only forward-direction information."""
    conn = sorted(conn, key=lambda r: r["ts"])
    win_ports: dict[tuple, set] = defaultdict(set)
    win_hosts: dict[tuple, set] = defaultdict(set)
    win_flows: dict[tuple, int] = defaultdict(int)
    for r in conn:
        k = (r["id.orig_h"], int(r["ts"] // WINDOW_S))
        win_ports[k].add(r["id.resp_p"])
        win_hosts[k].add(r["id.resp_h"])
        win_flows[k] += 1
    rows = []
    for r in conn:
        k = (r["id.orig_h"], int(r["ts"] // WINDOW_S))
        ob = float(r["orig_bytes"])
        rb = float(r["resp_bytes"])
        dur = float(r["duration"])
        base = [
            math.log1p(ob), math.log1p(dur),
            1.0 if r["proto"] == "tcp" else 0.0,
            math.log1p(r["id.resp_p"]),
            1.0 if r["id.orig_p"] >= 32768 else 0.0,
            math.log1p(len(win_ports[k])), math.log1p(len(win_hosts[k])), math.log1p(win_flows[k]),
            math.log1p(ob / max(dur, 1e-3)),
        ]
        if not one_way:
            base += [math.log1p(rb), math.log1p(ob) - math.log1p(rb), math.log1p(rb / max(dur, 1e-3))]
        rows.append(base)
    return np.asarray(rows, dtype=np.float64), conn


def load_flows(path: Path, cache: Path) -> list[dict]:
    cache.mkdir(parents=True, exist_ok=True)
    c = cache / f"{path.name}.pkl"
    if c.exists():
        return pickle.loads(c.read_bytes())
    from pcap_parser import parse_pcap
    # same cap as eval_real_traffic.py --big-file-cap so both use identical flows
    conn = parse_pcap(str(path), max_packets=100000 if path.stat().st_size > 30e6 else None)["conn"]
    c.write_bytes(pickle.dumps(conn))
    return conn


def main() -> None:
    from sklearn.ensemble import IsolationForest

    ap = argparse.ArgumentParser()
    ap.add_argument("pcap_dir")
    ap.add_argument("--out", default="eval_results")
    args = ap.parse_args()
    out = ROOT / args.out
    cache = out / "flows_cache"

    files = sorted(p for p in Path(args.pcap_dir).iterdir() if p.suffix in (".pcap", ".pcapng"))
    seen, uniq = set(), []
    import hashlib
    for p in files:
        h = hashlib.sha256(p.read_bytes() if p.stat().st_size < 30e6 else p.name.encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        uniq.append(p)

    flows = {p.name: load_flows(p, cache) for p in uniq}
    train_all = sorted(flows[TRAIN_FILE], key=lambda r: r["ts"])
    cut = int(len(train_all) * 0.7)
    train, calib = train_all[:cut], train_all[cut:]

    result = {}
    lines = ["# Unsupervised learned-baseline (train on benign only)\n",
             f"Train: first 70% of {TRAIN_FILE} ({len(train)} flows). Threshold: {FLOW_QUANTILE:.1%} quantile on the "
             f"held-out 30% ({len(calib)} flows). File flagged if >{FILE_FLAG_FRACTION:.0%} of flows anomalous.\n"]
    for variant, one_way in (("two_way", False), ("one_way", True)):
        Xtr, _ = feats(train, one_way)
        mu, sd = Xtr.mean(0), Xtr.std(0) + 1e-9
        model = IsolationForest(n_estimators=300, random_state=0, n_jobs=-1).fit((Xtr - mu) / sd)
        Xc, _ = feats(calib, one_way)
        thr = np.quantile(-model.score_samples((Xc - mu) / sd), FLOW_QUANTILE)
        lines.append(f"\n## {variant}\n")
        lines.append("| file | label | flows | anomalous flows | fraction | flagged |")
        lines.append("|---|---|---:|---:|---:|---|")
        tp = fn = fp = tn = 0
        per = {}
        for p in uniq:
            n = p.name
            if n == TRAIN_FILE or n in UNLABELLED:
                continue
            X, _ = feats(flows[n], one_way)
            if len(X) == 0:
                continue
            s = -model.score_samples((X - mu) / sd)
            frac = float((s > thr).mean())
            flagged = frac > FILE_FLAG_FRACTION
            benign = n == BENIGN_TEST
            if benign:
                fp += flagged
                tn += (not flagged)
            else:
                tp += flagged
                fn += (not flagged)
            per[n] = {"flows": len(X), "fraction": frac, "flagged": flagged}
            lines.append(f"| {n} | {'BENIGN' if benign else 'attack'} | {len(X)} | {int((s > thr).sum())} | {frac:.1%} | {'YES' if flagged else 'no'} |")
        rec = tp / (tp + fn) if tp + fn else 0
        lines.append(f"\n**{variant}: attacks flagged {tp}/{tp + fn} ({rec:.0%}); benign flagged {fp}/{fp + tn}**\n")
        result[variant] = {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "recall": rec, "per_file": per}

    (out / "eval_ai_baseline.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "eval_ai_baseline.json").write_text(json.dumps(result, indent=2))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
