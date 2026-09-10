"""
ENG-09 -- HTTP-based C2 and exfiltration detection.

Fills a real gap: Zeek's base analyzer already produces http.log for any
HTTP traffic in a pcap, but nothing downstream was reading it until this
engine existed. Detects two distinct signals neither flow-level stats nor
DNS-level analysis can see:

  1. Suspicious User-Agent strings -- many HTTP-based C2 frameworks use a
     library's default UA (python-requests, Go-http-client) or no UA at
     all, since the malware author never bothered to fake a browser
     string. Real browsers almost always send a full, versioned UA.
  2. Anomalously large POST bodies -- a flow-level byte-ratio check
     (ENG-06) sees aggregate bytes; this looks specifically at HTTP
     request body size, which is a more precise exfiltration signal when
     the transport happens to be HTTP.

Deliberately does NOT attempt HTTP-based beaconing (repeated requests at
regular intervals) -- ENG-02 already covers periodicity at the flow
level, and duplicating that logic at the HTTP layer would be redundant
without adding real signal.
"""
from __future__ import annotations

from typing import Optional

from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector
from src.features.feature_extraction import shannon_entropy

# Non-exhaustive, deliberately conservative: library-default UAs are a
# real but weak-on-their-own signal (plenty of legitimate automation
# uses these too) -- combined with URI entropy below, not used alone.
SUSPICIOUS_UA_MARKERS = [
    "python-requests", "python-urllib", "go-http-client", "curl/",
    "libwww-perl", "java/", "okhttp",
]

URI_ENTROPY_THRESHOLD = 4.2       # above this, a URI path looks closer to random than human-authored
MIN_URI_LENGTH_FOR_ENTROPY = 12   # skip short paths -- entropy on "/api" is meaningless noise
LARGE_POST_BYTES_THRESHOLD = 5_000_000  # 5MB -- conservative, tuned to avoid flagging normal file uploads


class HTTPThreatDetector(Detector):
    name = "ENG-09"

    async def score(self, flow: dict) -> Optional[Alert]:
        method = str(flow.get("http_method", "")).upper()
        uri = flow.get("http_uri", "") or ""
        user_agent = (flow.get("http_user_agent", "") or "").lower()
        request_body_len = int(flow.get("http_request_body_len", 0) or 0)

        evidence: dict = {}
        reasons: list[str] = []

        if request_body_len > LARGE_POST_BYTES_THRESHOLD and method == "POST":
            reasons.append("large_post_body")
            evidence["request_body_len"] = request_body_len

        suspicious_ua = any(marker in user_agent for marker in SUSPICIOUS_UA_MARKERS) or user_agent == ""
        uri_entropy = shannon_entropy(uri) if len(uri) >= MIN_URI_LENGTH_FOR_ENTROPY else 0.0
        if suspicious_ua and uri_entropy > URI_ENTROPY_THRESHOLD:
            reasons.append("suspicious_ua_and_high_entropy_uri")
            evidence["user_agent"] = user_agent or "(empty)"
            evidence["uri_entropy"] = round(uri_entropy, 2)

        if not reasons:
            return None

        threat_class = "DATA_EXFILTRATION" if "large_post_body" in reasons else "C2_BEACONING"
        severity = "HIGH" if len(reasons) > 1 else "MEDIUM"

        return Alert(
            alert_id=__import__("uuid").uuid4().hex,
            timestamp=float(flow.get("ts", 0.0)),
            severity=severity,
            confidence_score=60.0 + 15.0 * len(reasons),
            threat_class=threat_class,
            flow_identifier=FlowIdentifier(
                src_ip=flow.get("src_ip", "0.0.0.0"), src_port=int(flow.get("src_port", 0)),
                dst_ip=flow.get("dst_ip", "0.0.0.0"), dst_port=int(flow.get("dst_port", 0)),
                protocol="TCP",
            ),
            mitre_attack=MitreAttack(
                # T1071.001 -- more specific than ENG-02's generic T1071:
                # this is HTTP-based Application Layer Protocol C2
                # specifically, a real, distinct MITRE sub-technique.
                tactic="Command and Control", technique_id="T1071.001",
                technique_name="Application Layer Protocol: Web Protocols",
            ) if threat_class == "C2_BEACONING" else MitreAttack(
                tactic="Exfiltration", technique_id="T1041",
                technique_name="Exfiltration Over C2 Channel",
            ),
            evidence={"method": method, "uri": uri[:200], **evidence},
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
            detection_mode="rule",
        )
