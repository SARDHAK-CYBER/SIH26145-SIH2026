"""
Can the 4-feature `flow` model be made usable standalone by training on a LARGE real benign set?

Earlier hard-negative experiments used 484 benign flows. This one uses a real live capture (thousands of flows from a real Wi-Fi
network, recorded with scripts/collect_live_pcap.py), split by TIME so the model never sees the held-out benign minutes:

    python scripts/retrain_flow_real_benign.py --wifi data/benign_live/eval/benign_wifi_20min.pcap \
        --corpus "C:/.../pcap folder" --out docs/reports/flow_retrain_real_benign.json

Train benign  = first half (by flow start) of the live capture + normal.pcap (minus its embedded nmap scan)
Held-out benign = second half of the live capture + normal2.pcap
Attack side   = models/flow_training_data.csv (DDoS captures), split BY SOURCE CAPTURE (held-out captures unseen)
Also reported: a CROSS-NETWORK check on real captures from other networks (--cross, e.g. data/public_samples) that no model saw.

Without --write nothing is written. With --write the shipped flow model is replaced (see write_model): trained on ALL data
(DDoS captures + every real benign flow, benign weight 5), exported to ONNX, manifest + feature importances updated, and the
real benign rows appended to models/flow_training_data.csv so the training is reproducible.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import src  # noqa: E402,F401
import stealthtap_core as core  # noqa: E402
from src.capture.rawpcap import iter_raw_pcap  # noqa: E402
from src.features.feature_extraction import build_feature_vector  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
THRESHOLDS = (0.6, 0.9, 0.95, 0.98, 0.99, 0.995)


def flows(path: Path, drop_port: int | None = None) -> pd.DataFrame:
    asm = core.LiveFlowAssembler(60.0)
    for ts, raw in iter_raw_pcap(str(path)):
        asm.process(ts, raw)
    rows = []
    for _t, r in asm.flush():
        if drop_port and r["id.orig_p"] == drop_port:
            continue
        rows.append({"ts": r["ts"], "duration_s": r["duration"], "orig_bytes": r["orig_bytes"], "resp_bytes": r["resp_bytes"], "proto": r["proto"].upper()})
    return pd.DataFrame(rows)


def feats(df: pd.DataFrame) -> np.ndarray:
    return np.vstack([build_feature_vector({"duration_s": d, "orig_bytes": o, "resp_bytes": r, "proto": p}, "flow")
                      for d, o, r, p in zip(df.duration_s, df.orig_bytes, df.resp_bytes, df.proto)]).astype(np.float32)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wifi", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", default="docs/reports/flow_retrain_real_benign.json")
    ap.add_argument("--cross", default=None, help="folder of pcaps from OTHER networks, never used for training (cross-network FPR)")
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()
    import xgboost as xgb
    from sklearn.model_selection import GroupShuffleSplit

    wifi = flows(Path(a.wifi)).sort_values("ts").reset_index(drop=True)
    half = len(wifi) // 2
    corpus = Path(a.corpus)
    ben_tr = pd.concat([wifi.iloc[:half], flows(corpus / "normal.pcap", 54920)], ignore_index=True)
    ben_te = pd.concat([wifi.iloc[half:], flows(corpus / "normal2.pcap")], ignore_index=True)
    orig = pd.read_csv(ROOT / "models" / "flow_training_data.csv")
    orig = orig[~orig.source_file.str.startswith("live_wifi/")].reset_index(drop=True)   # idempotent: never train on rows a previous --write appended
    orig["y"] = (orig.label == "malicious").astype(int)
    tr_i, te_i = next(GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=7).split(orig, groups=orig.source_file))
    otr, ote = orig.iloc[tr_i], orig.iloc[te_i]
    print(f"benign train {len(ben_tr)} / held-out {len(ben_te)} flows; DDoS train {int(otr.y.sum())} / held-out captures {int(ote.y.sum())} rows "
          f"({sorted(set(ote.source_file))})")

    Xte_a = feats(ote[ote.y == 1])
    Xte_b = feats(ben_te)

    def fit(weight: float | None):
        X, y, w = feats(otr), otr.y.values.astype(float), np.ones(len(otr))
        if weight is not None:
            X = np.vstack([X, feats(ben_tr)])
            y = np.concatenate([y, np.zeros(len(ben_tr))])
            w = np.concatenate([w, np.full(len(ben_tr), weight)])
        m = xgb.XGBClassifier(n_estimators=250, max_depth=6, learning_rate=0.1, subsample=0.9, eval_metric="logloss", n_jobs=4)
        m.fit(X, y, sample_weight=w)
        return m

    cross = pd.DataFrame()
    if a.cross:
        parts = []
        for f in sorted(list(Path(a.cross).rglob("*.pcap")) + list(Path(a.cross).rglob("*.cap"))):
            if iter_raw_pcap(str(f)) is not None:
                parts.append(flows(f))
        cross = pd.concat([p for p in parts if len(p)], ignore_index=True) if parts else pd.DataFrame()
        print(f"cross-network real flows (other networks, never trained on): {len(cross)}")
    Xcross = feats(cross) if len(cross) else None

    rows = []
    for name, wt in (("baseline (attack data + its few benign rows)", None), ("+ real benign x1", 1.0), ("+ real benign x5", 5.0),
                     ("+ real benign x20", 20.0), ("+ real benign x50", 50.0)):
        m = fit(wt)
        pa, pb = m.predict_proba(Xte_a)[:, 1], m.predict_proba(Xte_b)[:, 1]
        if wt == 5.0:
            heldout = (pa, pb)
        pts = [{"threshold": t, "held_out_benign_fpr": round(float((pb >= t).mean()), 5), "held_out_ddos_capture_recall": round(float((pa >= t).mean()), 5)}
               for t in THRESHOLDS]
        if Xcross is not None:
            pc = m.predict_proba(Xcross)[:, 1]
            for p, thr in zip(pts, THRESHOLDS):
                p["cross_network_fpr"] = round(float((pc >= thr).mean()), 5)
        rows.append({"config": name, "points": pts})
        print(f"\n{name}")
        for p in pts:
            print(f"  thr {p['threshold']:<6} benign FPR {p['held_out_benign_fpr']:.4f}   held-out DDoS-capture recall {p['held_out_ddos_capture_recall']:.4f}"
                  + (f"   cross-network FPR {p['cross_network_fpr']:.4f}" if "cross_network_fpr" in p else ""))
    Path(a.out).write_text(json.dumps({"benign_train_flows": len(ben_tr), "benign_heldout_flows": len(ben_te),
                                       "cross_network_flows": int(len(cross)), "results": rows}, indent=1))
    if a.write:
        write_model(orig, pd.concat([wifi, flows(corpus / "normal.pcap", 54920), flows(corpus / "normal2.pcap")], ignore_index=True), xgb, heldout)


def write_model(orig: pd.DataFrame, benign: pd.DataFrame, xgb, heldout) -> None:
    """Train on everything, export ONNX, update manifest + importances, append the real benign rows to the training CSV."""
    import datetime
    from onnxmltools import convert_xgboost
    from onnxmltools.convert.common.data_types import FloatTensorType

    X = np.vstack([feats(orig), feats(benign)])
    y = np.concatenate([orig.y.values.astype(float), np.zeros(len(benign))])
    w = np.concatenate([np.ones(len(orig)), np.full(len(benign), 5.0)])
    m = xgb.XGBClassifier(n_estimators=250, max_depth=6, learning_rate=0.1, subsample=0.9, eval_metric="logloss", n_jobs=4)
    m.fit(X, y, sample_weight=w)
    onx = convert_xgboost(m, initial_types=[("input", FloatTensorType([None, X.shape[1]]))])
    (ROOT / "models" / "flow_xgboost_v1.onnx").write_bytes(onx.SerializeToString())

    from src.features.feature_extraction import _FAMILY_BUILDERS
    names = _FAMILY_BUILDERS["flow"][0]()
    imp = {n: round(float(v), 5) for n, v in zip(names, m.feature_importances_)}
    fi = ROOT / "models" / "flow_feature_importance.json"
    old = json.loads(fi.read_text()) if fi.exists() else {}
    fi.write_text(json.dumps(imp if not isinstance(old, list) else [{"feature": n, "importance": v} for n, v in
                                                                      sorted(imp.items(), key=lambda kv: -kv[1])], indent=1))
    man = json.loads((ROOT / "models" / "MANIFEST.json").read_text())
    for e in man:
        if e.get("family") == "flow":
            e["trained_at"] = datetime.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
            e["model_version"] = "v1"
            e["training_data"] = {"source_file": "flow_training_data.csv", "row_count": int(len(orig) + len(benign)),
                                  "note": "DDoS captures + real benign flows from a live Wi-Fi capture (weight 5); see docs/PRD.md section 14"}
            pa, pb = heldout                                   # metrics of the SPLIT model on data it never saw (threshold 0.6)
            tp, fn, fp, tn = int((pa >= 0.6).sum()), int((pa < 0.6).sum()), int((pb >= 0.6).sum()), int((pb < 0.6).sum())
            prec, rec = tp / max(1, tp + fp), tp / max(1, tp + fn)
            from sklearn.metrics import roc_auc_score
            e["xgboost_metrics"] = {
                "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(2 * prec * rec / max(1e-9, prec + rec), 4),
                "roc_auc": round(float(roc_auc_score(np.r_[np.ones(len(pa)), np.zeros(len(pb))], np.r_[pa, pb])), 4),
                "confusion_matrix": {"true_negative": tn, "false_positive": fp, "false_negative": fn, "true_positive": tp},
                "evaluated_on": "held-out DDoS captures (unseen files) + held-out real benign flows (later minutes of the live capture, normal2.pcap)"}
    (ROOT / "models" / "MANIFEST.json").write_text(json.dumps(man, indent=2))
    add = benign[["duration_s", "orig_bytes", "resp_bytes", "proto"]].copy()
    add["label"] = "benign"
    add["source_file"] = "live_wifi/benign_wifi_20min+normal+normal2"
    csv = ROOT / "models" / "flow_training_data.csv"
    keep = pd.read_csv(csv)
    keep = keep[~keep.source_file.str.startswith("live_wifi/")]                       # replace, never duplicate, earlier real-benign rows
    pd.concat([keep, add], ignore_index=True).to_csv(csv, index=False)
    print(f"wrote models/flow_xgboost_v1.onnx (+manifest, importances, {len(add)} benign rows written to the training CSV (replacing earlier ones))")


if __name__ == "__main__":
    main()
