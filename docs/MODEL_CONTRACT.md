# StealthTap Model Contract v1.0.0

This is the interface your locally-trained models must satisfy to plug into the live pipeline with zero rework. If you change anything on this page, bump `FEATURE_SCHEMA_VERSION` in `feature_extraction.py` and retrain — a model trained against v1.0.0 features is not valid input for v1.1.0 code, even if the shapes happen to match by coincidence.

## 1. Feature vectors (the actual contract)

Four protocol families, each with a fixed field order. **Always build vectors through `feature_extraction.build_feature_vector(flow, family)` — never hand-roll the order in a training notebook.** That function is the single source of truth; import it in your local training scripts exactly as the live engines do.

| Family | Vector length | Covers |
|---|---|---|
| `flow` | 9 | IT: volumetric DDoS, exfiltration, general connection stats |
| `dns` | 262 | DGA domains, DNS tunnelling |
| `tls` | 3 | Encrypted malware (JA4-based, metadata only) |
| `modbus` | 3 | OT/ICS unauthorized control commands |

Note what's *not* here: fan-out (reconnaissance) and inter-arrival periodicity (C2 beaconing) are inherently multi-flow, windowed features — they stay computed in the streaming engines' stateful aggregators, not in this stateless module. If you want to train a model on those, you'll need to export windowed aggregates (e.g. rolling distinct-destination counts, FFT peak ratios) as their own feature vectors — happy to build that extraction path once you're ready for it.

## 2. Model artifacts: format and where they go

Per the project's existing security posture (no pickle, ever — see `relay.py`'s docstring and the Dockerfile's ONNX/SafeTensors-only stance), both models ship as **ONNX**:

- **XGBoost → ONNX.** Train with `xgboost.XGBClassifier`, convert with `onnxmltools.convert_xgboost` (or export native `.json`/`.ubj` first, then convert). XGBoost's native JSON booster format is also non-pickle and acceptable if you need a fallback, but ONNX is preferred so serving code only needs one runtime (`onnxruntime`) for everything.
- **Isolation Forest → ONNX.** Train with `sklearn.ensemble.IsolationForest`, convert with `skl2onnx.convert_sklearn` — same pattern already proven working for the DGA classifier (`skl2onnx.convert_sklearn(clf, initial_types=[("input", FloatTensorType([None, n_features]))], target_opset=17)`).

Drop the finished `.onnx` files into a `models/` directory using this naming convention so the serving code can find them automatically:

```
models/
  flow_xgboost_v1.onnx
  flow_isolation_forest_v1.onnx
  dns_xgboost_v1.onnx
  dns_isolation_forest_v1.onnx
  tls_xgboost_v1.onnx
  tls_isolation_forest_v1.onnx
  modbus_xgboost_v1.onnx
  modbus_isolation_forest_v1.onnx
  MANIFEST.json   ← see below
```

`MANIFEST.json` records what each artifact actually is, so the model server can validate compatibility before loading anything:

```json
{
  "feature_schema_version": "1.0.0",
  "models": {
    "flow_xgboost_v1.onnx": {
      "family": "flow", "algorithm": "xgboost",
      "trained_on": "<dataset name/version>", "trained_date": "YYYY-MM-DD",
      "metrics": { "precision": 0.0, "recall": 0.0, "f1": 0.0, "roc_auc": 0.0 }
    }
  }
}
```

## 3. Hybrid scoring: how two models become one explainable threat score

Per family, both models run on the same feature vector:

- **XGBoost** → supervised probability that this flow matches a known-bad pattern. Good at catching what it's been trained on.
- **Isolation Forest** → unsupervised anomaly score (how far this flow sits from normal traffic). Good at catching *novel* attack variants the supervised model has never seen — this is the actual reason to run both rather than just the stronger of the two.

Combine as:

```
threat_score = max(xgboost_proba, normalized_isolation_forest_score)
detection_mode = "xgboost" if xgboost_proba >= if_score else "isolation_forest"
```

Taking the max (rather than averaging) is deliberate: an averaged score lets a confident XGBoost detection get diluted by a neutral anomaly score, and vice versa. Either model firing strongly should be enough to raise an alert; agreement between them should raise *confidence*, not gate detection. Report which model fired in the alert's `detection_mode` field — that's part of what makes the score explainable rather than a single opaque number.

## 4. Explainability fields (feeds the Alert schema)

Every ML-sourced alert should populate:
- `model_scores`: `{"xgboost": 0.94, "isolation_forest": 0.81}` — both raw scores, not just the winner
- `top_contributing_features`: top 3-5 features by XGBoost's built-in `feature_importances_` (or SHAP values if you have budget for it locally — genuinely worth it, `shap.TreeExplainer` is fast for tree models and gives per-prediction attribution, not just global importance)
- `detection_mode`: which model's score won, per the rule above

## 5. Evaluation methodology — what "verified" actually means here

Report **all** of these, not a subset that looks best:

1. **Standard stratified train/val/test split** (70/15/15). This is your baseline number.
2. **A holdout generalization test** — for DGA, this means training on most malware families and testing only on families never seen in training (I started exactly this pattern in `train_dga_model.py` before handing off — reuse it). For flow/TLS/OT models, the equivalent is a *temporal* holdout: train on traffic from one time period, test on a later period, so the model isn't just memorizing today's attacker infrastructure. **Report both numbers, not just whichever is higher.** The holdout number is the honest one — it's what a jury question like "how does this generalize to attacks you haven't seen" is actually asking.
3. **Precision, Recall, F1, ROC-AUC** — per the jury's stated evaluation criteria, computed on the *holdout* set, not the training set.
4. **Confusion matrix** — always report this alongside the summary metrics. A 99% accuracy number on an imbalanced dataset can hide a model that never once catches the minority class.
5. **Detection latency** — measured end-to-end once the live pipeline is running: timestamp of packet arrival vs. timestamp of alert emission. This can't be computed offline on a CSV; it needs the actual streaming pipeline running against generated traffic (iperf3/Ostinato/hping3), which is workstream #6 in the priority list.
6. **Sustained flows/sec** — same: needs the live pipeline under load, not a training-time number.

Items 5 and 6 are why the streaming path (workstream #2) has to get fixed before those jury metrics can be honestly reported — there's no way to claim a real detection-latency number without something actually running end-to-end.
