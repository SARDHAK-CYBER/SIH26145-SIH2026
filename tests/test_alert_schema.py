import pytest
from pydantic import ValidationError

from src.alert_schema import Alert

VALID_ALERT = {
    "alert_id": "c7b3e1a0-8a4f-4d5e-9e12-3456789abcde",
    # Alert.timestamp is epoch seconds (float); the human-readable ISO
    # form is exposed as the computed `property_timestamp` field.
    "timestamp": 1788630300.124,
    "severity": "HIGH",
    "confidence_score": 94.2,
    "threat_class": "DNS_TUNNELING",
    "flow_identifier": {
        "src_ip": "10.0.4.15", "src_port": 53211,
        "dst_ip": "198.51.100.5", "dst_port": 53, "protocol": "UDP",
    },
    "mitre_attack": {
        "tactic": "Command and Control",
        "technique_id": "T1572",
        "technique_name": "Protocol Tunneling",
    },
    "evidence": {"dns_query": "b64payload.chunk01.exfil-c2.net", "record_type": "TXT", "entropy": 4.91},
    "forensics": {"raw_segment_hash_sha256": "7d3f9c1a8e2b4f6d0a5c9e3b7f1d8a4c6e2b9f5d3a7c1e8b4f6d2a9c5e3b7f1d"},
}


def test_valid_alert_parses():
    Alert.model_validate(VALID_ALERT)


def test_extra_field_rejected():
    """
    This is the actual boundary-crossing control the relay depends on:
    a record with a field the schema doesn't know about must be
    rejected outright, not silently stripped and forwarded.
    """
    payload = {**VALID_ALERT, "sneaky_extra_field": "should never cross the relay"}
    with pytest.raises(ValidationError):
        Alert.model_validate(payload)


def test_out_of_range_confidence_rejected():
    payload = {**VALID_ALERT, "confidence_score": 150.0}
    with pytest.raises(ValidationError):
        Alert.model_validate(payload)


def test_unknown_threat_class_rejected():
    payload = {**VALID_ALERT, "threat_class": "NOT_A_REAL_THREAT_CLASS"}
    with pytest.raises(ValidationError):
        Alert.model_validate(payload)
