"""
ENG-03 -- DGA domains and DNS tunnelling.

Two branches:

  1. DNS tunnelling -- rule-based: unusual record types (TXT/NULL/CNAME)
     carrying long, high-entropy labels. Deterministic, no model needed.

  2. DGA domains -- hybrid:
       * If a trained `dns` model is available (HybridModelServer with
         dns_xgboost_v1.onnx / dns_isolation_forest_v1.onnx loaded), score
         the query through the SAME feature_extraction path the model was
         trained on, and fire when the hybrid score clears the shared
         MIN_ML_CONFIDENCE threshold. detection_mode reflects which model
         won (xgboost / isolation_forest).
       * If no model is loaded, fall back to a DETERMINISTIC lexical
         heuristic (Shannon entropy + digit ratio + longest consonant run
         + length). This replaces the previous branch, which ran an
         *untrained, randomly-initialised* CNN and therefore produced
         non-deterministic output -- see docs/PRD.md's "DGA (CNN branch)"
         gap. There is no torch dependency here any more.

The model_server is injected by the caller (upload path, live path). It's
duck-typed: anything with `.score_flow(flow, "dns")` returning
{"threat_score","detection_mode","model_scores"} or None works. Passing
None simply forces the heuristic fallback.
"""
from __future__ import annotations

from typing import Optional

from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector
from src.features.feature_extraction import (
    VOWELS,
    shannon_entropy,
    _max_consecutive_consonants,
)

# Shared ML threshold -- imported lazily inside score() to avoid pulling
# onnxruntime into every process that merely imports this engine.
TUNNELING_RECORD_TYPES = {"TXT", "NULL", "CNAME"}

# Deterministic lexical-heuristic parameters for the no-model fallback.
# The weighted score below is calibrated so classic DGA labels (no
# vowels, long consonant runs, hex-ish digit mixing, high entropy) clear
# HEURISTIC_FIRE_SCORE while ordinary domains (google, cloudfront,
# microsoftonline, googletagmanager) score near zero.
HEURISTIC_MIN_LENGTH = 12          # applies to the FULL query, gate before scoring
HEURISTIC_FIRE_SCORE = 0.55        # combined 0-1 lexical score needed to alert
_H_ENTROPY_FLOOR = 3.0
_H_ENTROPY_SPAN = 1.5
_H_VOWEL_CEIL = 0.30               # vowel ratio at/above this contributes nothing
_H_RUN_FLOOR = 3
_H_RUN_SPAN = 4
_H_DIGIT_FULL = 0.40              # digit ratio at/above this maxes the digit term
_W_ENTROPY, _W_VOWEL, _W_RUN, _W_DIGIT = 0.40, 0.30, 0.20, 0.10


def _candidate_labels(query: str) -> list[str]:
    """Every label that could carry a DGA string -- i.e. all labels
    except the final TLD. 'x7kqz.evil.com' -> ['x7kqz', 'evil'];
    'kqx3vwz.com' -> ['kqx3vwz']; a bare token -> [token]. The DGA branch
    scores each and takes the max, so it doesn't matter whether the
    random part is the SLD or a subdomain."""
    q = (query or "").strip().rstrip(".").lower()
    parts = [p for p in q.split(".") if p]
    if len(parts) <= 1:
        return parts
    return parts[:-1]


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _lexical_dga_score(label: str) -> tuple[float, dict]:
    """Deterministic 0-1 'looks like a DGA' score (weighted sum of four
    normalised lexical signals) plus its evidence."""
    if not label:
        return 0.0, {}
    entropy = shannon_entropy(label)
    alpha = [c for c in label if c.isalpha()]
    vowel_ratio = (sum(c in VOWELS for c in alpha) / len(alpha)) if alpha else 0.0
    digit_ratio = sum(c.isdigit() for c in label) / len(label)
    consonant_run = _max_consecutive_consonants(label)

    e_term = _clamp01((entropy - _H_ENTROPY_FLOOR) / _H_ENTROPY_SPAN)
    v_term = _clamp01((_H_VOWEL_CEIL - vowel_ratio) / _H_VOWEL_CEIL)
    r_term = _clamp01((consonant_run - _H_RUN_FLOOR) / _H_RUN_SPAN)
    d_term = _clamp01(digit_ratio / _H_DIGIT_FULL)

    score = (_W_ENTROPY * e_term + _W_VOWEL * v_term
             + _W_RUN * r_term + _W_DIGIT * d_term)
    if len(label) >= 18:
        score += 0.05

    signals = {
        "entropy_bits": round(entropy, 3),
        "vowel_ratio": round(vowel_ratio, 3),
        "digit_ratio": round(digit_ratio, 3),
        "max_consonant_run": consonant_run,
        "label_length": len(label),
        "label": label,
    }
    return _clamp01(score), signals


# Local-scope name resolution that is NOT DNS and must never be scored as
# DGA: mDNS (224.0.0.251:5353 / ff02::fb), LLMNR (5355), and the special
# TLDs the IETF reserves for local / service-discovery use. On a live LAN
# these dominate and every one looks "high entropy" to a DGA model
# (`_googlecast._tcp.local`, `_spotify-connect._tcp.local`, ...).
_LOCAL_RESOLUTION_PORTS = {5353, 5355}
_LOCAL_RESOLUTION_IPS = {"224.0.0.251", "224.0.0.252", "ff02::fb", "ff02::1:3"}
_LOCAL_SUFFIXES = (".local", ".local.", ".arpa", ".arpa.", ".home.arpa",
                   ".lan", ".internal", ".localdomain")


def _is_local_resolution(flow: dict, query: str) -> bool:
    if int(flow.get("dst_port", 0) or 0) in _LOCAL_RESOLUTION_PORTS:
        return True
    if str(flow.get("dst_ip", "")) in _LOCAL_RESOLUTION_IPS:
        return True
    q = query.lower().rstrip(".")
    if any(q.endswith(s.rstrip(".")) for s in _LOCAL_SUFFIXES):
        return True
    if q.startswith("_") or "._" in q:      # DNS-SD service records
        return True
    if "." not in q:                         # single-label -> not a real FQDN
        return True
    return False


class DGADetector(Detector):
    name = "ENG-03"

    def __init__(self, model_server=None):
        # Duck-typed HybridModelServer or None. No torch, no lazy CNN.
        self.model_server = model_server

    async def score(self, flow: dict) -> Optional[Alert]:
        query = flow.get("dns_query", "")
        record_type = flow.get("dns_qtype", "")
        if not query:
            return None
        if _is_local_resolution(flow, query):
            return None

        entropy = shannon_entropy(query)
        q_len = len(query)

        # 1. DNS tunnelling -- rule-based
        if record_type in TUNNELING_RECORD_TYPES and (q_len > 40 or entropy > 4.2):
            return self._build_alert(
                flow, query, record_type, confidence=96.0, is_tunneling=True,
                detection_mode="rule",
                evidence={"dns_query": query, "record_type": record_type,
                          "entropy": round(entropy, 2), "query_length": q_len},
            )

        if q_len <= HEURISTIC_MIN_LENGTH:
            return None

        # 2a. DGA -- trained model path
        if self.model_server is not None:
            try:
                from src.inference.model_server import MIN_ML_CONFIDENCE
                result = self.model_server.score_flow(flow, "dns")
            except Exception:
                result = None
            if result and result.get("threat_score", 0.0) >= MIN_ML_CONFIDENCE:
                score = float(result["threat_score"])
                return self._build_alert(
                    flow, query, record_type,
                    confidence=round(score * 100, 2), is_tunneling=False,
                    detection_mode=result["detection_mode"],
                    model_scores=result["model_scores"],
                    evidence={"dns_query": query, "record_type": record_type,
                              "entropy": round(entropy, 2), "raw_scores": result["model_scores"]},
                )
            # A loaded model that scored below threshold is a deliberate
            # negative -- don't second-guess it with the heuristic.
            if result is not None:
                return None

        # 2b. DGA -- deterministic lexical fallback (no model loaded)
        lex_score, signals = 0.0, {}
        for label in _candidate_labels(query):
            s, sig = _lexical_dga_score(label)
            if s > lex_score:
                lex_score, signals = s, sig
        if lex_score >= HEURISTIC_FIRE_SCORE:
            return self._build_alert(
                flow, query, record_type,
                confidence=round(60.0 + lex_score * 35.0, 2), is_tunneling=False,
                detection_mode="rule",
                evidence={"dns_query": query, "record_type": record_type,
                          "lexical_dga_score": round(lex_score, 3),
                          "heuristic_signals": signals,
                          "note": "deterministic lexical heuristic -- no trained dns model loaded"},
            )
        return None

    def _build_alert(self, flow: dict, query: str, record_type: str, *, confidence: float,
                     is_tunneling: bool, detection_mode: str = "rule",
                     model_scores: Optional[dict] = None, evidence: Optional[dict] = None) -> Alert:
        threat_class = "DNS_TUNNELING" if is_tunneling else "DGA_DOMAIN"
        t_id, t_name = (("T1572", "Protocol Tunneling") if is_tunneling
                        else ("T1568.002", "Domain Generation Algorithms"))
        return Alert(
            alert_id=flow.get("flow_uid", "unknown"),
            timestamp=float(flow.get("ts", 0.0)),
            severity="CRITICAL" if is_tunneling else "HIGH",
            confidence_score=max(0.0, min(100.0, confidence)),
            threat_class=threat_class,
            flow_identifier=FlowIdentifier(
                src_ip=flow.get("src_ip", "0.0.0.0"), src_port=int(flow.get("src_port", 0) or 0),
                dst_ip=flow.get("dst_ip", "0.0.0.0"), dst_port=53, protocol="UDP",
            ),
            mitre_attack=MitreAttack(tactic="Command and Control", technique_id=t_id, technique_name=t_name),
            evidence=evidence or {"dns_query": query, "record_type": record_type},
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
            detection_mode=detection_mode,
            model_scores=model_scores,
        )
