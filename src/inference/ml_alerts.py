"""
Shared: turn a HybridModelServer scoring result into a standardized Alert.

Used by BOTH the upload path (src/api/pcap_analysis.py) and the live path
(src/streaming_engine.py) so ML-sourced alerts look identical regardless
of which pipeline produced them. Previously this logic lived only inside
pcap_analysis.py, so the live path had no ML alerting at all.
"""
from __future__ import annotations

import time
import uuid
from typing import Optional

from src.alert_schema import Alert, FlowIdentifier, MitreAttack

# Per-family MITRE mapping for ML-fired alerts. Only 'dns' has a
# full-scale trained model today; 'flow'/'modbus' are trained on the
# in-repo CSVs; 'tls' has no dataset yet. Mappings for the untrained
# families are best-effort and should be revisited once those models can
# distinguish sub-threats within a family.
ML_THREAT_MAPPING: dict[str, tuple[str, str, str, str]] = {
    "dns": ("DGA_DOMAIN", "Command and Control", "T1568.002", "Domain Generation Algorithms"),
    "tls": ("ENCRYPTED_MALWARE", "Defense Evasion", "T1027", "Obfuscated Files or Information"),
    "flow": ("RECONNAISSANCE", "Discovery", "T1046", "Network Service Discovery"),
    "modbus": ("ICS_UNAUTHORIZED_CONTROL_COMMAND", "Impair Process Control", "T0855", "Unauthorized Command Message"),
}


def build_ml_alert(flow: dict, family: str, result: dict, *, min_confidence: float) -> Optional[Alert]:
    """Returns an Alert if the hybrid score clears `min_confidence` and
    the family has a MITRE mapping, else None. `result` is a
    HybridModelServer.score_flow()/score_flows_batch() element:
    {"threat_score", "detection_mode", "model_scores"}."""
    if result is None or result.get("threat_score", 0.0) < min_confidence:
        return None
    if family not in ML_THREAT_MAPPING:
        return None
    threat_class, tactic, technique_id, technique_name = ML_THREAT_MAPPING[family]
    score = float(result["threat_score"])

    top_features = result.get("top_contributing_features")
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=float(flow.get("ts", time.time())),
        severity="HIGH" if score > 0.9 else "MEDIUM",
        confidence_score=round(score * 100, 2),
        threat_class=threat_class,
        flow_identifier=FlowIdentifier(
            src_ip=flow.get("src_ip", "0.0.0.0"), src_port=int(flow.get("src_port", 0) or 0),
            dst_ip=flow.get("dst_ip", "0.0.0.0"), dst_port=int(flow.get("dst_port", 0) or 0),
            protocol=_coerce_proto(flow.get("proto", "TCP")),
        ),
        mitre_attack=MitreAttack(tactic=tactic, technique_id=technique_id, technique_name=technique_name),
        evidence={"family": family, "raw_scores": result["model_scores"]},
        forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
        detection_mode=result["detection_mode"],
        model_scores=result["model_scores"],
        top_contributing_features=top_features if top_features else None,
    )


def _coerce_proto(proto) -> str:
    p = str(proto or "TCP").upper()
    return p if p in ("TCP", "UDP", "ICMP") else "TCP"
