"""
Canonical feature extraction for StealthTap's hybrid AI-DPI pipeline.

CRITICAL DESIGN PRINCIPLE: this module is imported BOTH by offline
training scripts (running on your local machine, on real datasets) AND by
the live streaming/batch detection engines. That's deliberate. The single
most common reason a model that scores well offline performs badly in
production is "train/serve skew" -- training computes a feature slightly
differently than the live system does, and the model quietly learns
patterns that don't exist at inference time. Import this module from both
places. Never reimplement these functions separately in a training
notebook.

Covers four protocol families, spanning both IT and OT:
  - flow:   general TCP/UDP/ICMP connection metadata (conn.log-derived)
  - dns:    DNS query features (DGA / tunnelling)
  - tls:    TLS/QUIC metadata only -- JA3/JA4, never decrypted payload
  - modbus: OT/ICS function-code and register features

Each `*_feature_names()` function returns the field order a model expects.
That order is the actual contract -- if you change it, every trained
model artifact becomes invalid and must be retrained. Bump
FEATURE_SCHEMA_VERSION whenever any feature list changes, and record which
version a given model artifact was trained against.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer

FEATURE_SCHEMA_VERSION = "1.0.0"

VOWELS = set("aeiou")

# Same hasher configuration used in the DGA training script -- must stay
# identical between training and serving, which is exactly why it lives
# here instead of being redefined in two places.
_DNS_HASHER = HashingVectorizer(
    analyzer="char_wb", ngram_range=(2, 4),
    n_features=256, alternate_sign=False, norm=None,
)

# Dangerous Modbus function codes an OT engine should treat as high-risk
# by default. Keep in sync with eng07_ot_anomaly.py.
DANGEROUS_MODBUS_FUNCTIONS = [
    "WRITE_SINGLE_REGISTER", "WRITE_MULTIPLE_REGISTERS",
    "WRITE_SINGLE_COIL", "DIAGNOSTICS",
]
PROTO_ONE_HOT = ["TCP", "UDP", "ICMP"]


# ---------------------------------------------------------------------
# Shared lexical helpers (used by dns_features, and reusable elsewhere)
# ---------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _max_consecutive_consonants(s: str) -> int:
    run = 0
    best = 0
    for c in s:
        if c.isalpha() and c not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


# ---------------------------------------------------------------------
# 1. Flow features (IT: DDoS, recon, exfiltration -- stateless, per-record)
# ---------------------------------------------------------------------
def flow_feature_names() -> list[str]:
    return [
        "duration_s", "orig_bytes", "resp_bytes", "total_bytes",
        "byte_ratio", "bytes_per_second",
        "proto_tcp", "proto_udp", "proto_icmp",
    ]


def flow_features(flow: dict[str, Any]) -> dict[str, float]:
    """Stateless, single-flow features. Note: fan-out (recon) and
    inter-arrival periodicity (C2 beaconing) are inherently *aggregate*
    features requiring state across multiple flows -- they stay in the
    streaming engines' windowed aggregators (eng02, eng05), not here.
    This function only covers what's computable from one flow record."""
    duration = float(flow.get("duration_s", 0.0)) or 1e-6
    orig_b = float(flow.get("orig_bytes", 0))
    resp_b = float(flow.get("resp_bytes", 0))
    total = orig_b + resp_b
    proto = str(flow.get("proto", "TCP")).upper()
    return {
        "duration_s": duration,
        "orig_bytes": orig_b,
        "resp_bytes": resp_b,
        "total_bytes": total,
        "byte_ratio": orig_b / max(resp_b, 1.0),
        "bytes_per_second": total / duration,
        "proto_tcp": 1.0 if proto == "TCP" else 0.0,
        "proto_udp": 1.0 if proto == "UDP" else 0.0,
        "proto_icmp": 1.0 if proto == "ICMP" else 0.0,
    }


# ---------------------------------------------------------------------
# 2. DNS features (DGA domains, DNS tunnelling)
# ---------------------------------------------------------------------
def dns_feature_names() -> list[str]:
    return (
        [f"dns_hash_{i}" for i in range(256)]
        + ["dns_length", "dns_entropy", "dns_digit_ratio",
           "dns_vowel_ratio", "dns_unique_char_ratio", "dns_max_consec_consonant"]
    )


def dns_features(query: str) -> dict[str, float]:
    """Identical feature logic to train_dga_model.py's featurize() step --
    keep these in lockstep. If you retrain the DGA model with a different
    feature definition, update BOTH places or the model contract breaks."""
    query = (query or "").lower()
    hashed = _DNS_HASHER.transform([query]).toarray()[0]
    chars = [c for c in query if c.isalnum()]
    n = max(len(chars), 1)
    total = max(len(query), 1)
    feats = {f"dns_hash_{i}": float(v) for i, v in enumerate(hashed)}
    feats.update({
        "dns_length": float(len(query)),
        "dns_entropy": shannon_entropy(query),
        "dns_digit_ratio": sum(c.isdigit() for c in query) / total,
        "dns_vowel_ratio": sum(c in VOWELS for c in query) / n,
        "dns_unique_char_ratio": len(set(query)) / total,
        "dns_max_consec_consonant": float(_max_consecutive_consonants(query)),
    })
    return feats


# ---------------------------------------------------------------------
# 3. TLS/JA4 features (encrypted malware -- metadata only, never decrypted)
# ---------------------------------------------------------------------
def tls_feature_names() -> list[str]:
    return ["ja4_hash_bucket", "sni_entropy", "sni_length"]


def tls_features(flow: dict[str, Any]) -> dict[str, float]:
    """JA4 is a categorical fingerprint string, not a number -- we hash it
    into a stable bucket rather than one-hot encoding (an unbounded,
    ever-growing category space). This means the model learns clusters of
    *similar* fingerprints, which is more useful for catching fingerprint
    variants than an exact-match allowlist ever was."""
    ja4 = flow.get("ja4", "") or ""
    sni = flow.get("sni", "") or flow.get("server_name", "") or ""
    return {
        "ja4_hash_bucket": float(abs(hash(ja4)) % 10_000) if ja4 else 0.0,
        "sni_entropy": shannon_entropy(sni),
        "sni_length": float(len(sni)),
    }


# ---------------------------------------------------------------------
# 4. OT/Modbus features (industrial control anomaly)
# ---------------------------------------------------------------------
def modbus_feature_names() -> list[str]:
    return ["modbus_func_dangerous", "modbus_register_address", "modbus_is_write"]


def modbus_features(flow: dict[str, Any]) -> dict[str, float]:
    func = flow.get("modbus_func", "") or ""
    return {
        "modbus_func_dangerous": 1.0 if func in DANGEROUS_MODBUS_FUNCTIONS else 0.0,
        "modbus_register_address": float(flow.get("register_address", 0)),
        "modbus_is_write": 1.0 if "WRITE" in func else 0.0,
    }


# ---------------------------------------------------------------------
# Combinator: builds the exact, ordered vector a model expects
# ---------------------------------------------------------------------
_FAMILY_BUILDERS = {
    "flow": (flow_feature_names, flow_features),
    "dns": (dns_feature_names, dns_features),
    "tls": (tls_feature_names, tls_features),
    "modbus": (modbus_feature_names, modbus_features),
}


def build_feature_vector(flow: dict[str, Any], family: str) -> np.ndarray:
    """Returns a fixed-order float32 vector for the given protocol family.
    `family` must be one of 'flow', 'dns', 'tls', 'modbus'."""
    if family not in _FAMILY_BUILDERS:
        raise ValueError(f"unknown feature family '{family}', expected one of {list(_FAMILY_BUILDERS)}")
    names_fn, features_fn = _FAMILY_BUILDERS[family]
    if family == "dns":
        feats = features_fn(flow.get("dns_query", ""))
    else:
        feats = features_fn(flow)
    ordered = names_fn()
    return np.array([feats[name] for name in ordered], dtype=np.float32)
