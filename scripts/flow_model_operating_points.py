"""
Operating points of the SHIPPED `flow` model on real flows: false-positive rate on real benign captures vs. detection on real
attack captures, at a range of confidence thresholds.

    python scripts/flow_model_operating_points.py --benign "C:/.../normal2.pcap" data/benign_live/wifi.pcap \
        --benign-drop normal.pcap=54920 --attack-dir "C:/.../pcap folder" --out docs/reports/flow_model_operating_points.json

Flows are assembled exactly as the live path does (native LiveFlowAssembler) and scored with the production model server.
`--benign-drop file=port` removes the flows of a known scan hiding inside a "benign" file (normal.pcap contains a real nmap scan
from source port 54920). Use this to choose ML_FLOW_STANDALONE_CONFIDENCE for a network -- the default (never standalone) is
deliberately conservative; see docs/PRD.md section 14.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import src  # noqa: E402,F401
import stealthtap_core as core  # noqa: E402
from src.capture.rawpcap import iter_raw_pcap  # noqa: E402
from src.inference.model_server import HybridModelServer  # noqa: E402

THRESHOLDS = (0.6, 0.8, 0.9, 0.95, 0.98, 0.99, 0.995, 0.999)


def flows(path: Path, drop_port: int | None = None) -> list[dict]:
    it = iter_raw_pcap(str(path))
    if it is None:
        return []
    asm = core.LiveFlowAssembler(60.0)
    for ts, raw in it:
        asm.process(ts, raw)
    out = []
    for _t, r in asm.flush():
        if drop_port and r["id.orig_p"] == drop_port:
            continue
        out.append({"duration_s": r["duration"], "orig_bytes": r["orig_bytes"], "resp_bytes": r["resp_bytes"],
                    "proto": r["proto"].upper(), "orig_pkts": r.get("orig_pkts", 0), "resp_pkts": r.get("resp_pkts", 0)})
    return out


def wilson_upper(k: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 1.0
    p = k / n
    d = 1 + z * z / n
    return (p + z * z / (2 * n) + z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", nargs="+", required=True)
    ap.add_argument("--benign-drop", nargs="*", default=[], help="file.pcap=SRC_PORT")
    ap.add_argument("--attack-dir", required=True)
    ap.add_argument("--out", default="docs/reports/flow_model_operating_points.json")
    a = ap.parse_args()
    ms = HybridModelServer(skip_untrusted_iforest=True)
    drops = {k: int(v) for k, v in (x.split("=") for x in a.benign_drop)}

    def score(fl):
        if not fl:
            return np.array([])
        return np.array([x["threat_score"] if x else 0.0 for x in ms.score_flows_batch(fl, "flow")])

    ben = {}
    for f in a.benign:
        p = Path(f)
        ben[p.name] = score(flows(p, drops.get(p.name)))
    att = {p.name: score(flows(p)) for p in sorted(Path(a.attack_dir).glob("*.pcap"))
           if p.name not in drops and not p.name.startswith(("normal", "benign"))}
    all_b = np.concatenate([v for v in ben.values() if len(v)])
    all_a = np.concatenate([v for v in att.values() if len(v)])
    ddos = np.array([])
    csv = Path(__file__).resolve().parent.parent / "models" / "flow_training_data.csv"
    if csv.exists():
        import pandas as pd
        d = pd.read_csv(csv)
        d = d[d.label == "malicious"].sample(min(3000, int((d.label == "malicious").sum())), random_state=1)
        ddos = score(d[["duration_s", "orig_bytes", "resp_bytes", "proto"]].to_dict("records"))
    rows = []
    for t in THRESHOLDS:
        k = int((all_b >= t).sum())
        rows.append({"threshold": t, "benign_flows": int(len(all_b)), "benign_flagged": k,
                     "benign_fpr": round(k / len(all_b), 5), "benign_fpr_95_upper": round(float(wilson_upper(k, len(all_b))), 5),
                     "attack_capture_flow_recall": round(float((all_a >= t).mean()), 5) if len(all_a) else None,
                     "ddos_training_distribution_recall": round(float((ddos >= t).mean()), 5) if len(ddos) else None})
    per_file = {k: {"flows": int(len(v)), "flagged_at_0.98": int((v >= 0.98).sum())} for k, v in {**ben, **att}.items()}
    out = {"benign_sources": {k: int(len(v)) for k, v in ben.items()}, "attack_flows": int(len(all_a)), "operating_points": rows, "per_file": per_file,
           "note": "attack-capture flows are labelled by FILE (background flows inside an attack capture count as attack flows), so recall there is a floor"}
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(f"{'thr':>6} {'benign FPR':>11} {'95% upper':>10} {'attack-file flow recall':>24} {'DDoS-shape recall':>18}")
    for r in rows:
        print(f"{r['threshold']:>6} {r['benign_fpr']:>11.4f} {r['benign_fpr_95_upper']:>10.4f} {r['attack_capture_flow_recall']:>24.4f} {r['ddos_training_distribution_recall'] or 0:>18.4f}")


if __name__ == "__main__":
    main()
