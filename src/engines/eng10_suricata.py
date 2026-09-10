"""
ENG-10 -- Suricata signature-based network detection.

Parses eve.json alerts from a completed suricata-batch job and maps
them to this project's Alert schema. Complements Zeek (protocol
parsing/metadata) and YARA (file-content signatures) with real,
network-level signature matching -- known exploit patterns, C2
communication signatures, credential-theft attempts -- none of which
the other three detection layers (rule engines, ML, YARA) can see.

Mapping philosophy: where a Suricata classtype cleanly corresponds to
one of the PS's six threat classes, use it -- this REINFORCES existing
detections with independent signature evidence (e.g. a real
command-and-control signature match alongside ENG02's periodicity
detection is stronger evidence than either alone). Where it doesn't
honestly fit (the "web-application-attack" bucket alone is 5,294
rules), it's classified as NETWORK_INTRUSION_ATTEMPT rather than
force-fit into a misleading category.
"""
from __future__ import annotations
import uuid
from src.alert_schema import Alert, FlowIdentifier, MitreAttack

# Keyed on the EXACT human-readable strings from Suricata's own
# classification.config (verified directly against the installed
# config, not guessed) -- eve.json's alert.category field contains
# these strings, not the raw classtype keyword, which is why matching
# against the keyword itself (an earlier version of this mapping) was
# unreliable.
CLASSTYPE_MAPPING: dict[str, tuple[str, str, str, str]] = {
    "a network trojan was detected": ("C2_BEACONING", "Command and Control", "T1071", "Application Layer Protocol"),
    "malware command and control activity detected": ("C2_BEACONING", "Command and Control", "T1071", "Application Layer Protocol"),
    "attempted information leak": ("RECONNAISSANCE", "Discovery", "T1046", "Network Service Discovery"),
    "attempted denial of service": ("VOLUMETRIC_DDOS", "Impact", "T1498", "Network Denial of Service"),
    "detection of a denial of service attack": ("VOLUMETRIC_DDOS", "Impact", "T1498", "Network Denial of Service"),
    "web application attack": ("NETWORK_INTRUSION_ATTEMPT", "Initial Access", "T1190", "Exploit Public-Facing Application"),
    "exploit kit activity detected": ("NETWORK_INTRUSION_ATTEMPT", "Initial Access", "T1189", "Drive-by Compromise"),
    "attempted administrator privilege gain": ("NETWORK_INTRUSION_ATTEMPT", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    "attempted user privilege gain": ("NETWORK_INTRUSION_ATTEMPT", "Initial Access", "T1190", "Exploit Public-Facing Application"),
    "successful credential theft detected": ("NETWORK_INTRUSION_ATTEMPT", "Credential Access", "T1552", "Unsecured Credentials"),
    "possible social engineering attempted": ("NETWORK_INTRUSION_ATTEMPT", "Initial Access", "T1566", "Phishing"),
    "targeted malicious activity was detected": ("NETWORK_INTRUSION_ATTEMPT", "Command and Control", "T1071", "Application Layer Protocol"),
}
DEFAULT_MAPPING = ("NETWORK_INTRUSION_ATTEMPT", "Unknown", "T0000", "Unclassified Suricata Signature")

# Suricata's own severity (1=highest) maps inversely to this project's
# severity strings.
SURICATA_SEVERITY_MAPPING = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}


def parse_suricata_alerts(eve_records: list[dict]) -> list[dict]:
    """Takes parsed eve.json lines (already filtered to event_type ==
    'alert' by the caller, or not -- this filters again defensively)
    and returns a list of Alert dicts, ready to merge into the
    response's alert list alongside every other engine's output."""
    alerts: list[dict] = []
    for record in eve_records:
        if record.get("event_type") != "alert":
            continue
        alert_info = record.get("alert", {})
        category_str = alert_info.get("category", "").lower().strip()
        mapping = CLASSTYPE_MAPPING.get(category_str, DEFAULT_MAPPING)
        threat_class, tactic, technique_id, technique_name = mapping

        suricata_severity = alert_info.get("severity", 3)
        severity = SURICATA_SEVERITY_MAPPING.get(suricata_severity, "MEDIUM")

        alerts.append(Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=record.get("timestamp_epoch", 0.0) or 0.0,
            severity=severity,
            confidence_score=90.0 if suricata_severity == 1 else 70.0 if suricata_severity == 2 else 50.0,
            threat_class=threat_class,
            flow_identifier=FlowIdentifier(
                src_ip=record.get("src_ip", "0.0.0.0"), src_port=int(record.get("src_port", 0) or 0),
                dst_ip=record.get("dest_ip", "0.0.0.0"), dst_port=int(record.get("dest_port", 0) or 0),
                protocol=record.get("proto", "TCP").upper() if record.get("proto", "TCP").upper() in ("TCP", "UDP", "ICMP") else "TCP",
            ),
            mitre_attack=MitreAttack(tactic=tactic, technique_id=technique_id, technique_name=technique_name),
            evidence={
                "suricata_signature": alert_info.get("signature", ""),
                "suricata_sid": alert_info.get("signature_id"),
                "suricata_category": alert_info.get("category", ""),
                "suricata_severity": suricata_severity,
            },
            forensics={"raw_segment_hash_sha256": ""},
            detection_mode="rule",
        ).model_dump(mode="json"))
    return alerts
