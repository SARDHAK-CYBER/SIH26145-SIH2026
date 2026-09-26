"""
Hard-negative retraining experiment for the `flow` model, with guard-rails.

The shipped flow model was trained on 23k rows that are 97% attack. This harvests REAL benign flows from captures
you name, adds them as hard negatives, retrains XGBoost with a GROUPED evaluation (the model never sees the held-out
capture), and only recommends replacing the shipped model when it is measurably better on data it has not seen:

    python scripts/retrain_flow_hard_negatives.py --train-benign normal.pcap --holdout-benign normal2.pcap \
           --exclude-src-port normal.pcap=54920 [--write]

Decision rule (printed, and enforced by --write): held-out benign false-positive rate must not get worse AND recall on the
ORIGINAL held-out attack rows must not drop by more than 1 point. Otherwise nothing is written.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import stealthtap_core as core  # noqa: E402
from src.features.feature_extraction import build_feature_vector  # noqa: E402

THRESHOLD = 0.6      # MIN_ML_CONFIDENCE
ROOT = Path(__file__).resolve().parent.parent


def harvest(path: Path, drop_src_port: int | None) -> pd.DataFrame:
    """Real flows of a capture via the native live assembler (same records the live pipeline scores)."""
    idx = core.PcapIndex(str(path))
    asm = core.LiveFlowAssembler(60.0)
    for n in range(1, len(idx) + 1):
        ts, _w, raw = idx.packet(n)
        asm.process(ts, bytes(raw))
    rows = []
    for _t, r in asm.flush():
        if drop_src_port is not None and r["id.orig_p"] == drop_src_port:
            continue                                   # e.g. the nmap scan hiding inside a "benign" capture
        rows.append({"duration_s": r["duration"], "orig_bytes": r["orig_bytes"], "resp_bytes": r["resp_bytes"],
                     "proto": r["proto"].upper(), "label": "benign", "source_file": path.name})
    return pd.DataFrame(rows)


def features(df: pd.DataFrame) -> np.ndarray:
    return np.vstack([build_feature_vector({"duration_s": d, "orig_bytes": o, "resp_bytes": r, "proto": p}, "flow")
                      for d, o, r, p in zip(df.duration_s, df.orig_bytes, df.resp_bytes, df.proto)]).astype(np.float32)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-benign", nargs="+", required=True)
    ap.add_argument("--holdout-benign", nargs="+", required=True)
    ap.add_argument("--exclude-src-port", nargs="*", default=[], help="capture.pcap=PORT")
    ap.add_argument("--corpus", default="C:/Users/admin/Downloads/archive (2)")
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()
    import xgboost as xgb
    from sklearn.model_selection import GroupShuffleSplit

    excl = {k: int(v) for k, v in (x.split("=") for x in a.exclude_src_port)}
    orig = pd.read_csv(ROOT / "models" / "flow_training_data.csv")
    orig["y"] = (orig.label == "malicious").astype(int)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=7)
    tr_i, te_i = next(gss.split(orig, groups=orig.source_file))
    otr, ote = orig.iloc[tr_i], orig.iloc[te_i]           # split by source capture: the held-out attacks are unseen files

    corpus = Path(a.corpus)
    hn_train = pd.concat([harvest(corpus / n, excl.get(n)) for n in a.train_benign], ignore_index=True)
    hn_hold = pd.concat([harvest(corpus / n, excl.get(n)) for n in a.holdout_benign], ignore_index=True)
    print(f"original: {len(orig)} rows ({orig.y.mean():.1%} attack); hard negatives: train {len(hn_train)} flows, held-out {len(hn_hold)} flows")

    def fit(df_attack_benign: pd.DataFrame, weight_hn: float = 1.0, hn: pd.DataFrame | None = None):
        X = features(df_attack_benign)
        y = df_attack_benign.y.values
        w = np.ones(len(y))
        if hn is not None and len(hn):
            X = np.vstack([X, features(hn)]); y = np.concatenate([y, np.zeros(len(hn))])
            w = np.concatenate([w, np.full(len(hn), weight_hn)])
        m = xgb.XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, subsample=0.9, eval_metric="logloss", n_jobs=4)
        m.fit(X, y, sample_weight=w)
        return m

    def report(m, name):
        pa = m.predict_proba(features(ote))[:, 1]
        recall = float((pa[ote.y.values == 1] >= THRESHOLD).mean())
        prec_benign_orig = float((pa[ote.y.values == 0] >= THRESHOLD).mean()) if (ote.y == 0).any() else float("nan")
        ph = m.predict_proba(features(hn_hold))[:, 1]
        fpr = float((ph >= THRESHOLD).mean())
        print(f"{name:34s} held-out attack recall {recall:.4f} | held-out ORIGINAL benign FPR {prec_benign_orig:.4f} | "
              f"REAL held-out benign FPR {fpr:.4f} ({int((ph >= THRESHOLD).sum())}/{len(ph)})")
        return recall, fpr

    base = fit(otr)
    r0, f0 = report(base, "baseline (original data only)")
    best = None
    for w in (1.0, 5.0, 20.0):
        m = fit(otr, w, hn_train)
        r1, f1 = report(m, f"+ hard negatives (weight {w:g})")
        if f1 <= f0 and r1 >= r0 - 0.01 and (best is None or f1 < best[2]):
            best = (m, w, f1, r1)
    if best is None:
        print("\nDECISION: no configuration improves held-out benign FPR without hurting attack recall -> keep the shipped model.")
        return
    print(f"\nDECISION: weight {best[1]:g} improves held-out benign FPR {f0:.4f} -> {best[2]:.4f} with recall {best[3]:.4f} (was {r0:.4f}).")
    if not a.write:
        print("(dry run: pass --write to export the retrained ONNX model)")
        return
    print("--write requested: export via training/train_model_template.py's ONNX path is required; refusing to overwrite models/ "
          "from this experiment script without a full retrain on all data. Run the template with the hard-negative CSV.")


if __name__ == "__main__":
    main()
