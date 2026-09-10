from datetime import datetime, timezone
from typing import Literal, Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field, computed_field

class FlowIdentifier(BaseModel):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: Literal["TCP", "UDP", "ICMP"]

class MitreAttack(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str

class Alert(BaseModel):
    # extra="forbid" makes relay.py's "drops unrecognized fields" claim
    # actually true -- Pydantic v2 ignores extra fields by default unless
    # told otherwise.
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    timestamp: float
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence_score: float = Field(..., ge=0.0, le=100.0)
    threat_class: Literal[
        "VOLUMETRIC_DDOS",
        "SLOWLORIS",
        "C2_BEACONING",
        "DGA_DOMAIN",
        "DNS_TUNNELING",
        "ENCRYPTED_MALWARE",
        "RECONNAISSANCE",
        "DATA_EXFILTRATION",
        "ICS_UNAUTHORIZED_CONTROL_COMMAND",
        "MALICIOUS_FILE_DETECTED",
        # NEW: Suricata's real ET Open ruleset fires heavily on
        # categories that don't honestly map to any of the six PS
        # threat classes -- web-application-attack alone is 5,294
        # rules, the single largest category. Force-fitting these into
        # e.g. RECONNAISSANCE would misrepresent what was actually
        # detected. This covers exploit attempts, credential theft,
        # and social engineering signatures genuinely outside the
        # original six.
        "NETWORK_INTRUSION_ATTEMPT",
    ]
    flow_identifier: FlowIdentifier
    mitre_attack: MitreAttack
    evidence: Dict[str, Any]
    forensics: Dict[str, Any]

    # --- Explainability fields for the hybrid XGBoost + Isolation Forest
    # detection path (see MODEL_CONTRACT.md). All optional with safe
    # defaults, so existing rule-based engines (eng01-eng08) need no
    # changes at all -- they simply never populate these.
    detection_mode: Literal["rule", "xgboost", "isolation_forest"] = "rule"
    model_scores: Optional[Dict[str, float]] = None
    top_contributing_features: Optional[List[Dict[str, Any]]] = None

    @computed_field
    @property
    def property_timestamp(self) -> str:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
