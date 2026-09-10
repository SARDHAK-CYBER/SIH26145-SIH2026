"""
Hybrid model server: loads XGBoost + Isolation Forest ONNX artifacts per
protocol family and runs combined inference, per MODEL_CONTRACT.md.

Models are OPTIONAL per family. If a family's .onnx files aren't present
yet (e.g. you haven't finished training that one locally), that family's
ML scoring is simply skipped -- not an error. This lets the API run and
be demoed incrementally as each model finishes training, rather than
requiring the entire model suite to exist before anything works.

VERIFIED: the output-extraction logic below was tested against real
trained artifacts (XGBoost via onnxmltools, IsolationForest via
skl2onnx) and confirmed correct -- XGBoost's ONNX export produces
[label, probabilities] with probabilities as the last float output;
IsolationForest's produces [label(int64), scores(float)], correctly
skipped-past and picked-up respectively by the logic below. One
remaining uncertainty: whether ONNX's IsolationForest "scores" output is
exactly sklearn's score_samples() or decision_function() (they differ by
a small constant offset) -- the anomaly-direction sign convention is the
same either way, so scoring still works, just treat the exact 0-1
normalization as approximate until you check against your own artifact.

BATCHED SCORING ADDED: real production testing found a severe bottleneck
-- a real Modbus capture (39,969 records) took 30-40 seconds in detection
time alone, because score_flow() was called once per record, each call
paying full Python/ONNX-Runtime call overhead for a single row. ONNX
models natively support a batch dimension (the `None` in the exported
input shape) -- verified directly (not assumed) that batched inference
produces IDENTICAL results to one-at-a-time (np.allclose, atol=1e-6) with
a real measured 10.3x speedup at 1,000 rows; the real 39,969-row case
should improve considerably more, since per-call Python/IPC overhead
(what batching eliminates) dominates more as the individual-call count
grows. score_flow() (singular) is kept for compatibility with any
existing single-flow call site; score_flows_batch() is the fix
pcap_analysis.py's high-volume loops (Modbus, and any other family that
can see thousands of records in one file) should actually use.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import numpy as np
import onnxruntime as ort

from src.features.feature_extraction import build_feature_vector, FEATURE_SCHEMA_VERSION

MODELS_DIR = Path(os.environ.get("MODELS_DIR", "models"))
FAMILIES = ["flow", "dns", "tls", "modbus"]

# Shared ML alerting threshold -- a hybrid threat_score below this does
# not raise an alert on ANY path (upload or live). Chosen from the real
# full-scale DGA precision-recall curve (see docs/MODEL_CONTRACT.md and
# the table in src/api/pcap_analysis.py history): at 0.6, DGA XGBoost
# precision=0.957 recall=0.840. Overridable per-deployment.
MIN_ML_CONFIDENCE = float(os.environ.get("MIN_ML_CONFIDENCE", "0.6"))

# An Isolation Forest whose held-out F1 (from MANIFEST.json) is below
# this is treated as ADVISORY ONLY: its anomaly score is still reported
# in model_scores for transparency, but it cannot by itself set the
# alert's threat_score / detection_mode. This stops a degenerate
# unsupervised model (dns IF recall 0.03; a flow IF trained on a tiny,
# unrepresentative benign set) from flooding the alert table -- observed
# directly: an untrusted flow IF fired on 252 of 572 benign-ish flows.
# XGBoost (supervised, real held-out metrics) still drives detection.
IFOREST_MIN_F1 = float(os.environ.get("IFOREST_MIN_F1", "0.30"))


def _extract_positive_class_proba(outputs) -> Optional[float]:
    """Best-effort: most sklearn-onnx / onnxmltools classifier exports
    produce (label, probabilities) -- probabilities is usually the last
    float-typed output, shape (1, 2) for binary classification, where
    index 1 is the positive class. VERIFY against your actual export."""
    for out in reversed(outputs):
        arr = np.asarray(out)
        if arr.dtype.kind == "f" and arr.size >= 1:
            flat = arr.reshape(-1)
            return float(flat[-1])
    return None


def _extract_anomaly_score(outputs) -> Optional[float]:
    """sklearn's IsolationForest.score_samples is roughly in [-0.5, 0.5],
    lower = more anomalous. VERIFY the actual ONNX output semantics --
    some converters expose the raw score, others expose a binary
    is_inlier prediction as the first output instead."""
    for out in outputs:
        arr = np.asarray(out)
        if arr.dtype.kind == "f" and arr.size >= 1:
            return float(arr.reshape(-1)[0])
    return None


def _extract_positive_class_proba_batch(outputs) -> Optional[np.ndarray]:
    """Batched version of _extract_positive_class_proba -- same output
    shape convention (last float output, column 1 = positive class), one
    score per row instead of assuming a single row. Verified to produce
    results identical (not just similar) to the one-at-a-time function
    above, via direct np.allclose comparison against real trained
    artifacts."""
    for out in reversed(outputs):
        arr = np.asarray(out)
        if arr.dtype.kind == "f" and arr.ndim == 2 and arr.shape[1] >= 2:
            return arr[:, 1]
    return None


def _extract_anomaly_score_batch(outputs) -> Optional[np.ndarray]:
    """Batched version of _extract_anomaly_score."""
    for out in outputs:
        arr = np.asarray(out)
        if arr.dtype.kind == "f" and arr.size >= 1:
            return arr.reshape(-1)
    return None


class FamilyModels:
    def __init__(self, family: str, iforest_trusted: bool = True):
        self.family = family
        self.xgb_session: Optional[ort.InferenceSession] = None
        self.iforest_session: Optional[ort.InferenceSession] = None
        self.top_features: Optional[list] = None  # global XGBoost importances, for Alert explainability
        self.iforest_trusted = iforest_trusted    # see IFOREST_MIN_F1
        self._load()

    def _combine(self, scores: dict[str, float]) -> Optional[dict]:
        """Turn raw per-model scores into a hybrid result. An untrusted
        Isolation Forest stays visible in model_scores but does not get
        to set threat_score/detection_mode when XGBoost is available."""
        if not scores:
            return None
        deciding = dict(scores)
        if not self.iforest_trusted and "xgboost" in deciding and "isolation_forest" in deciding:
            deciding.pop("isolation_forest")
        detection_mode = max(deciding, key=deciding.get)
        out = {
            "model_scores": scores,
            "detection_mode": detection_mode,
            "threat_score": scores[detection_mode],
        }
        if self.top_features:
            out["top_contributing_features"] = self.top_features
        return out

    def _load(self) -> None:
        xgb_path = MODELS_DIR / f"{self.family}_xgboost_v1.onnx"
        if_path = MODELS_DIR / f"{self.family}_isolation_forest_v1.onnx"
        imp_path = MODELS_DIR / f"{self.family}_feature_importance.json"
        if xgb_path.exists():
            self.xgb_session = ort.InferenceSession(str(xgb_path), providers=["CPUExecutionProvider"])
            print(f"[model_server] loaded {xgb_path}")
        if if_path.exists():
            self.iforest_session = ort.InferenceSession(str(if_path), providers=["CPUExecutionProvider"])
            print(f"[model_server] loaded {if_path}")
        if imp_path.exists():
            try:
                self.top_features = json.loads(imp_path.read_text())[:5]
            except Exception as exc:
                print(f"[model_server] could not read {imp_path.name}: {exc}")

    @property
    def loaded(self) -> bool:
        return self.xgb_session is not None or self.iforest_session is not None

    def score(self, vector: np.ndarray) -> Optional[dict]:
        """Single-flow scoring. Kept for compatibility / low-volume call
        sites. For anything that might see more than a handful of
        records in one pass (Modbus, or any family on a large capture),
        use score_batch() instead -- see the module docstring for why."""
        if not self.loaded:
            return None
        x = vector.reshape(1, -1).astype(np.float32)
        scores: dict[str, float] = {}

        if self.xgb_session is not None:
            input_name = self.xgb_session.get_inputs()[0].name
            outputs = self.xgb_session.run(None, {input_name: x})
            proba = _extract_positive_class_proba(outputs)
            if proba is not None:
                scores["xgboost"] = proba

        if self.iforest_session is not None:
            input_name = self.iforest_session.get_inputs()[0].name
            outputs = self.iforest_session.run(None, {input_name: x})
            raw_score = _extract_anomaly_score(outputs)
            if raw_score is not None:
                scores["isolation_forest"] = float(max(0.0, min(1.0, 0.5 - raw_score)))

        return self._combine(scores)

    def score_batch(self, vectors: np.ndarray) -> list[Optional[dict]]:
        """Batched scoring -- ONE ONNX Runtime call per loaded model,
        regardless of how many rows. This is the real fix for the
        39,969-individual-call bottleneck found in production testing
        (modbus_iti_test.pcap: 30-40s of detection time on 9 conn flows
        that turned out to carry 39,969 real Modbus transactions).
        Returns one result (or None) per input row, in the same order."""
        if not self.loaded or vectors.shape[0] == 0:
            return [None] * vectors.shape[0]
        x = vectors.astype(np.float32)
        n = x.shape[0]

        xgb_probas: Optional[np.ndarray] = None
        if self.xgb_session is not None:
            input_name = self.xgb_session.get_inputs()[0].name
            outputs = self.xgb_session.run(None, {input_name: x})
            xgb_probas = _extract_positive_class_proba_batch(outputs)

        iforest_scores: Optional[np.ndarray] = None
        if self.iforest_session is not None:
            input_name = self.iforest_session.get_inputs()[0].name
            outputs = self.iforest_session.run(None, {input_name: x})
            raw = _extract_anomaly_score_batch(outputs)
            if raw is not None:
                iforest_scores = np.clip(0.5 - raw, 0.0, 1.0)

        results: list[Optional[dict]] = []
        for i in range(n):
            scores: dict[str, float] = {}
            if xgb_probas is not None:
                scores["xgboost"] = float(xgb_probas[i])
            if iforest_scores is not None:
                scores["isolation_forest"] = float(iforest_scores[i])
            results.append(self._combine(scores))
        return results


class HybridModelServer:
    def __init__(self):
        manifest_path = MODELS_DIR / "MANIFEST.json"
        raw_manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else []
        self.manifest: list[dict] = raw_manifest if isinstance(raw_manifest, list) else [raw_manifest] if raw_manifest else []

        # Decide, per family, whether the Isolation Forest is trustworthy
        # enough to independently trigger alerts (see IFOREST_MIN_F1).
        if_f1: dict[str, float] = {}
        for entry in self.manifest:
            fam = entry.get("family")
            f1 = (entry.get("isolation_forest_metrics") or {}).get("f1")
            if fam and isinstance(f1, (int, float)):
                if_f1[fam] = float(f1)
        self.families: dict[str, FamilyModels] = {}
        for f in FAMILIES:
            trusted = if_f1.get(f, 1.0) >= IFOREST_MIN_F1  # unknown F1 -> trust (no evidence against)
            self.families[f] = FamilyModels(f, iforest_trusted=trusted)
            if f in if_f1 and not trusted:
                print(f"[model_server] {f} isolation_forest F1={if_f1[f]:.3f} < {IFOREST_MIN_F1} "
                      f"-- demoted to advisory (XGBoost drives {f} detection)")

        for entry in self.manifest:
            entry_version = entry.get("feature_schema_version")
            if entry_version != FEATURE_SCHEMA_VERSION:
                print(f"[model_server] WARNING: MANIFEST.json entry for family "
                      f"{entry.get('family')!r} has feature_schema_version "
                      f"{entry_version!r}, does not match feature_extraction.py's "
                      f"{FEATURE_SCHEMA_VERSION!r} -- that model may have been "
                      f"trained on a different feature contract.")
        loaded = self.loaded_families()
        print(f"[model_server] ready. families with at least one model loaded: {loaded or 'NONE'}")

    def loaded_families(self) -> list[str]:
        return [f for f, m in self.families.items() if m.loaded]

    def score_flow(self, flow: dict, family: str) -> Optional[dict]:
        if family not in self.families:
            raise ValueError(f"unknown family '{family}', expected one of {FAMILIES}")
        vector = build_feature_vector(flow, family)
        return self.families[family].score(vector)

    def score_flows_batch(self, flows: list[dict], family: str) -> list[Optional[dict]]:
        """Batched equivalent of score_flow() -- builds all feature
        vectors, then ONE inference call per loaded model instead of one
        per flow. Use this anywhere a loop might process more than a
        handful of records of the same family in one pass."""
        if family not in self.families:
            raise ValueError(f"unknown family '{family}', expected one of {FAMILIES}")
        if not flows:
            return []
        vectors = np.stack([build_feature_vector(f, family) for f in flows])
        return self.families[family].score_batch(vectors)
