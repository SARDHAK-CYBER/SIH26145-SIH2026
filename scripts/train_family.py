#!/usr/bin/env python3
"""
Train one protocol family's hybrid model pair (XGBoost + Isolation Forest)
and export both to ONNX, plus feature importances and a MANIFEST.json
entry the running model server can validate.

    python scripts/train_family.py flow   models/flow_training_data.csv
    python scripts/train_family.py modbus models/modbus_training_data.csv
    python scripts/train_family.py dns    path/to/dga_domains.csv --domain-col domain --label-col label --malicious-value dga

Requires:  pip install -r requirements.txt -r requirements-train.txt

Train/serve parity: feature vectors are built with the SAME
src.features.feature_extraction.build_feature_vector the live engines use.
Never hand-roll feature order here.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.features.feature_extraction import build_feature_vector, FEATURE_SCHEMA_VERSION  # noqa: E402

RANDOM_STATE = 42
MODEL_VERSION = "v1"
OUT_DIR = ROOT / "models"


# --------------------------------------------------------------------------
# Per-family: dataset row -> the flow dict feature_extraction expects
# --------------------------------------------------------------------------
def row_to_flow(row: pd.Series, family: str, args) -> dict:
    if family == "flow":
        return {
            "duration_s": float(row.get("duration_s", 0) or 0),
            "orig_bytes": float(row.get("orig_bytes", 0) or 0),
            "resp_bytes": float(row.get("resp_bytes", 0) or 0),
            "proto": str(row.get("proto", "TCP") or "TCP"),
        }
    if family == "modbus":
        return {
            "modbus_func": str(row.get("modbus_func", "") or ""),
            "register_address": float(row.get("register_address", 0) or 0),
            "register_sweep_count": float(row.get("register_sweep_count", 1) or 1),
        }
    if family == "dns":
        return {"dns_query": str(row.get(args.domain_col, "")).lower()}
    if family == "tls":
        return {"ja4": str(row.get("ja4", "")), "sni": str(row.get("sni", ""))}
    raise ValueError(f"no row_to_flow mapping for family '{family}'")


def load_labeled(csv_path: str, family: str, args) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(csv_path)
    df = df.dropna(how="all")
    label_col = args.label_col if family in ("dns", "tls") else "label"
    if label_col not in df.columns:
        raise SystemExit(f"label column '{label_col}' not in {csv_path} (columns: {list(df.columns)})")
    mal_value = args.malicious_value
    y = (df[label_col].astype(str).str.lower() == mal_value.lower()).astype(int).to_numpy()
    if y.sum() == 0 or y.sum() == len(y):
        raise SystemExit(f"label column has only one class after mapping '{mal_value}' -> malicious")
    X = np.vstack([build_feature_vector(row_to_flow(r, family, args), family) for _, r in df.iterrows()])
    print(f"[data] {len(df)} rows | malicious={int(y.sum())} ({y.mean():.1%}) | feature dim={X.shape[1]}")
    return X.astype(np.float32), y


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("family", choices=["flow", "dns", "tls", "modbus"])
    p.add_argument("csv")
    p.add_argument("--domain-col", default="domain")
    p.add_argument("--label-col", default="label")
    p.add_argument("--malicious-value", default="malicious",
                   help="value in the label column that means 'attack' (default: malicious; use 'dga' for DGA datasets)")
    p.add_argument("--contamination", type=float, default=0.02,
                   help="IsolationForest contamination = expected outlier fraction of the BENIGN set (default 0.02)")
    args = p.parse_args()

    import xgboost as xgb
    from sklearn.ensemble import IsolationForest
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (precision_score, recall_score, f1_score,
                                 roc_auc_score, confusion_matrix)
    from onnxmltools import convert_xgboost
    from onnxmltools.convert.common.data_types import FloatTensorType as OMTFloat
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType as SKLFloat

    fam = args.family
    X, y = load_labeled(args.csv, fam, args)
    n_features = X.shape[1]

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE)
    print(f"[split] train={len(X_tr)} test={len(X_te)}")

    # --- XGBoost: supervised ---
    scale_pos = float((y_tr == 0).sum()) / max(1, int((y_tr == 1).sum()))
    xgb_clf = xgb.XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.9,
        colsample_bytree=0.9, eval_metric="logloss", random_state=RANDOM_STATE,
        n_jobs=4, scale_pos_weight=scale_pos,
    )
    t0 = time.time()
    xgb_clf.fit(X_tr, y_tr)
    print(f"[xgboost] trained in {time.time()-t0:.1f}s (scale_pos_weight={scale_pos:.2f})")

    # --- Isolation Forest: unsupervised, benign-only training ---
    # contamination = expected fraction of the BENIGN training set that is
    # actually noise/outliers, NOT the dataset's malicious rate. Keep it
    # small; a large value makes the model flag a big slice of normal
    # traffic (observed: contamination=0.2 -> 252/572 benign flows alerted).
    benign = X_tr[y_tr == 0]
    contamination = float(args.contamination)
    iforest = IsolationForest(n_estimators=200, contamination=contamination,
                              random_state=RANDOM_STATE, n_jobs=4)
    iforest.fit(benign)
    print(f"[iforest] trained on {len(benign)} benign rows (contamination={contamination:.3f})")

    # --- Evaluate on the same held-out test set ---
    def _metrics(y_true, y_pred, y_score):
        return {
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_true, y_score)), 4),
            "confusion_matrix": {
                k: int(v) for k, v in zip(
                    ("true_negative", "false_positive", "false_negative", "true_positive"),
                    confusion_matrix(y_true, y_pred).ravel())
            },
        }

    xgb_proba = xgb_clf.predict_proba(X_te)[:, 1]
    xgb_metrics = _metrics(y_te, (xgb_proba >= 0.5).astype(int), xgb_proba)
    if_score = -iforest.score_samples(X_te)                    # higher = more anomalous
    if_pred = (iforest.predict(X_te) == -1).astype(int)
    if_metrics = _metrics(y_te, if_pred, if_score)
    print(f"[xgboost]  {xgb_metrics}")
    print(f"[iforest]  {if_metrics}")

    # --- ONNX export ---
    OUT_DIR.mkdir(exist_ok=True)
    xgb_path = OUT_DIR / f"{fam}_xgboost_{MODEL_VERSION}.onnx"
    if_path = OUT_DIR / f"{fam}_isolation_forest_{MODEL_VERSION}.onnx"
    xgb_onnx = convert_xgboost(xgb_clf, initial_types=[("input", OMTFloat([None, n_features]))])
    xgb_path.write_bytes(xgb_onnx.SerializeToString())
    if_onnx = convert_sklearn(iforest, initial_types=[("input", SKLFloat([None, n_features]))],
                              target_opset={"": 17, "ai.onnx.ml": 3})
    if_path.write_bytes(if_onnx.SerializeToString())
    print(f"[export] {xgb_path.name}, {if_path.name}")

    # --- feature importances (explainability -> Alert.top_contributing_features) ---
    from src.features.feature_extraction import _FAMILY_BUILDERS
    names = _FAMILY_BUILDERS[fam][0]()
    importances = sorted(
        ({"feature": n, "importance": round(float(v), 5)}
         for n, v in zip(names, xgb_clf.feature_importances_)),
        key=lambda d: d["importance"], reverse=True,
    )
    (OUT_DIR / f"{fam}_feature_importance.json").write_text(json.dumps(importances[:10], indent=2))
    print(f"[export] {fam}_feature_importance.json (top: {[i['feature'] for i in importances[:3]]})")

    # --- MANIFEST.json (list-of-entries format, matches the existing dns entry) ---
    manifest_path = OUT_DIR / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else []
    if not isinstance(manifest, list):
        manifest = [manifest]
    manifest = [e for e in manifest if e.get("family") != fam]
    manifest.append({
        "family": fam,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "model_version": MODEL_VERSION,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S%z") or time.strftime("%Y-%m-%d"),
        "training_data": {"source_file": Path(args.csv).name, "row_count": int(len(y))},
        "test_split": {"fraction": 0.20, "row_count": int(len(y_te))},
        "xgboost_metrics": xgb_metrics,
        "isolation_forest_metrics": if_metrics,
        "artifacts": [xgb_path.name, if_path.name],
    })
    manifest.sort(key=lambda e: e.get("family", ""))
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"[export] MANIFEST.json updated for '{fam}'")
    print("\n[done] restart the api / streaming-engine to pick up the new model.")


if __name__ == "__main__":
    main()
