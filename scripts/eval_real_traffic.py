#!/usr/bin/env python3
"""
Evaluate StealthTap's detection layers on LABELLED REAL captures.

Runs every capture in a directory through the same parser + engines +
ONNX models the API uses, then scores three configurations from the SAME
alert list (so they are directly comparable):

    rule    -- alerts whose detection_mode == "rule"       (ENG-01..13 heuristics)
    ai      -- alerts whose detection_mode is xgboost / isolation_forest
    hybrid  -- everything (what the product actually ships)

Ground truth is FILE-LEVEL (this dataset has no per-flow labels): each
capture is either a known attack session or benign background traffic.
Flow-level false-positive rate is therefore only measured on the benign
files, where every flow is known to be benign.

    python scripts/eval_real_traffic.py "C:/path/to/pcaps" --out eval_results

Limits (also printed in the report): no Zeek/Suricata here -- this is the
in-process scapy parser and Python engines; stateful engines run against
an in-memory Redis stand-in so their cross-flow counters are exercised.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BENIGN = {"normal.pcap", "normal2.pcap"}
UNLABELLED = {"check-output.pcapng"}   # provenance unknown -> reported, never scored

CONFIGS = {
    "rule": lambda a: a["detection_mode"] == "rule",
    "ai": lambda a: a["detection_mode"] in ("xgboost", "isolation_forest"),
    "hybrid": lambda a: True,
}


from src.memstore import MemoryStore as FakeRedis  # the same store the desktop app ships


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_file(path: Path, model_server, max_packets):
    from pcap_parser import parse_pcap
    from src.api.pcap_analysis import _run_engines, _payload_events

    t0 = time.time()
    parsed = parse_pcap(str(path), max_packets=max_packets)
    # same payload-level decoders the API's upload path runs (plain-text service attacks + OT protocols)
    for k, v in _payload_events(path.read_bytes()).items():
        parsed.setdefault(k, []).extend(v)
    parse_s = time.time() - t0
    t0 = time.time()
    alerts, coverage = asyncio.new_event_loop().run_until_complete(
        _run_engines(parsed, model_server, FakeRedis())
    )
    return {
        "file": path.name,
        "flows": len(parsed["conn"]), "dns": len(parsed["dns"]), "ssl": len(parsed["ssl"]),
        "parse_s": round(parse_s, 2), "detect_s": round(time.time() - t0, 2),
        "alerts": alerts,
        "coverage": coverage,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap_dir")
    ap.add_argument("--out", default="eval_results")
    ap.add_argument("--max-packets", type=int, default=None)
    ap.add_argument("--big-file-cap", type=int, default=None,
                    help="only read this many packets from captures larger than 30 MB")
    ap.add_argument("--only", default=None, help="run a single file name (debug)")
    ap.add_argument("--reuse", action="store_true", help="reuse cached per-file results")
    args = ap.parse_args()

    out = ROOT / args.out
    (out / "per_file").mkdir(parents=True, exist_ok=True)

    try:
        from src.inference.model_server import HybridModelServer
        model_server = HybridModelServer()
    except Exception as exc:
        print(f"[eval] ML unavailable ({exc}) -- AI/hybrid columns will be empty")
        model_server = None

    files = sorted(p for p in Path(args.pcap_dir).iterdir() if p.suffix in (".pcap", ".pcapng"))
    if args.only:
        files = [p for p in files if p.name == args.only]

    seen: dict[str, str] = {}
    results = []
    for p in files:
        digest = sha256(p)
        if digest in seen:
            print(f"[skip] {p.name}: byte-identical duplicate of {seen[digest]}")
            continue
        seen[digest] = p.name
        cache = out / "per_file" / f"{p.name}.json"
        if args.reuse and cache.exists():
            r = json.loads(cache.read_text())
        else:
            cap = args.max_packets
            if cap is None and args.big_file_cap and p.stat().st_size > 30e6:
                cap = args.big_file_cap   # keep one giant capture from dominating the run
            print(f"[run ] {p.name} ({p.stat().st_size / 1e6:.1f} MB)"
                  f"{f' -- first {cap:,} packets only' if cap else ''} ...", flush=True)
            r = run_file(p, model_server, cap)
            r["sha256"] = digest
            r["packet_cap"] = cap
            cache.write_text(json.dumps(r))
        n = len(r["alerts"])
        print(f"       flows={r['flows']:>7} alerts={n:>5} parse={r['parse_s']}s detect={r['detect_s']}s "
              f"classes={dict(Counter(a['threat_class'] for a in r['alerts']))}", flush=True)
        results.append(r)

    report(results, out)


def report(results: list[dict], out: Path) -> None:
    labelled = [r for r in results if r["file"] not in UNLABELLED]
    attack = [r for r in labelled if r["file"] not in BENIGN]
    benign = [r for r in labelled if r["file"] in BENIGN]

    summary = {"n_attack_files": len(attack), "n_benign_files": len(benign), "configs": {}}
    lines = []
    lines.append(f"# Real-traffic evaluation ({len(attack)} attack captures, {len(benign)} benign captures, deduplicated)\n")
    lines.append("Ground truth is file-level. 'Detected' = the config raised >=1 alert on the capture.\n")

    lines.append("## Per-file alerts\n")
    lines.append("| file | label | flows | rule | ai | hybrid | classes |")
    lines.append("|---|---|---:|---:|---:|---:|---|")
    for r in results:
        lab = "unlabelled" if r["file"] in UNLABELLED else ("BENIGN" if r["file"] in BENIGN else "attack")
        c = {k: sum(1 for a in r["alerts"] if f(a)) for k, f in CONFIGS.items()}
        cls = ", ".join(f"{k}:{v}" for k, v in Counter(a["threat_class"] for a in r["alerts"]).most_common(4))
        lines.append(f"| {r['file']} | {lab} | {r['flows']} | {c['rule']} | {c['ai']} | {c['hybrid']} | {cls} |")

    lines.append("\n## File-level accuracy\n")
    lines.append("| config | attacks detected (recall) | 95% CI | benign clean (specificity) | precision | F1 |")
    lines.append("|---|---:|---|---:|---:|---:|")
    for name, f in CONFIGS.items():
        tp = sum(1 for r in attack if any(f(a) for a in r["alerts"]))
        fn = len(attack) - tp
        fp = sum(1 for r in benign if any(f(a) for a in r["alerts"]))
        tn = len(benign) - fp
        rec = tp / len(attack) if attack else 0.0
        spec = tn / len(benign) if benign else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        lo, hi = wilson(tp, len(attack))
        summary["configs"][name] = {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
                                    "recall": rec, "recall_ci": [lo, hi], "specificity": spec,
                                    "precision": prec, "f1": f1}
        lines.append(f"| {name} | {tp}/{len(attack)} = {rec:.0%} | {lo:.0%}-{hi:.0%} | {tn}/{len(benign)} = {spec:.0%} | {prec:.0%} | {f1:.2f} |")

    lines.append("\n## Flow-level false positives on BENIGN captures (every flow here is known-benign)\n")
    lines.append("| config | benign flows | flows alerted | false-positive rate | alerts per 1,000 flows |")
    lines.append("|---|---:|---:|---:|---:|")
    total_flows = sum(r["flows"] for r in benign)
    for name, f in CONFIGS.items():
        alerted = len({a["alert_id"] for r in benign for a in r["alerts"] if f(a)})
        n_alerts = sum(1 for r in benign for a in r["alerts"] if f(a))
        rate = alerted / total_flows if total_flows else 0.0
        lo, hi = wilson(alerted, total_flows)
        summary["configs"][name].update({"benign_flows": total_flows, "benign_flows_alerted": alerted,
                                         "flow_fpr": rate, "flow_fpr_ci": [lo, hi]})
        lines.append(f"| {name} | {total_flows} | {alerted} | {rate:.3%} ({lo:.3%}-{hi:.3%}) | {1000 * n_alerts / max(total_flows, 1):.2f} |")

    lines.append("\n## Which engine fired on attack captures\n")
    eng = Counter()
    for r in attack:
        for k, v in r["coverage"].items():
            if v.get("alerts_fired"):
                eng[k] += 1
    lines.append(", ".join(f"{k}: {v}/{len(attack)} files" for k, v in eng.most_common()) or "none")

    (out / "eval_real_traffic.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "eval_real_traffic.json").write_text(json.dumps(summary, indent=2))
    print("\n" + "\n".join(lines))


if __name__ == "__main__":
    main()
