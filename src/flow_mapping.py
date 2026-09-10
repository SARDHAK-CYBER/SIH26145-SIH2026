"""
Canonical Zeek/parser-record -> flow-dict mapping.

SINGLE SOURCE OF TRUTH. This function was previously copy-pasted three
times (offline_engine.py, streaming_engine.py, api/pcap_analysis.py) and
the copies silently drifted -- the Modbus `func` vs `func_name` field bug
existed in two copies while being fixed in only the third, which meant OT
detection quietly no-oped on the batch and streaming paths. Every ingest
path now imports THIS function so a field-name fix lands everywhere at
once.

Input record shape: raw Zeek JSON log line keys (`id.orig_h`,
`orig_bytes`, `func`, ...). pcap_parser.py deliberately emits the same
key shape, so this mapping works unmodified for the pure-Python upload
fallback too.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# Log types this mapper understands. Anything else falls through to the
# common flow fields only.
KNOWN_LOG_TYPES = ("conn", "dns", "ssl", "modbus", "dnp3", "http", "kerberos", "cip")


def compute_segment_hash(rec: dict[str, Any]) -> str:
    """Deterministic content hash for a record that carries no upstream
    `segment_hash`. Used for forensic chain-of-custody when the record
    was derived from Zeek logs rather than a raw packet segment. Stable
    across runs for identical input, unlike the old
    "simulated_hash_for_pcap" placeholder string."""
    canonical = json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def map_record(rec: dict[str, Any], log_type: str) -> dict[str, Any]:
    """Map one raw Zeek/parser record into the flat flow dict every
    detection engine consumes."""
    proto_raw = rec.get("proto", "tcp")
    proto_str = proto_raw.upper() if isinstance(proto_raw, str) and proto_raw else "TCP"

    segment_hash = rec.get("segment_hash") or compute_segment_hash(rec)

    flow: dict[str, Any] = {
        "flow_uid": rec.get("uid", "unknown"),
        "ts": rec.get("ts", 0.0),
        "src_ip": rec.get("id.orig_h", ""),
        "src_port": rec.get("id.orig_p", 0),
        "dst_ip": rec.get("id.resp_h", ""),
        "dst_port": rec.get("id.resp_p", 0),
        "proto": proto_str,
        "segment_hash": segment_hash,
    }

    if log_type == "conn":
        flow["duration_s"] = rec.get("duration", 0.0)
        flow["orig_bytes"] = rec.get("orig_bytes", 0)
        flow["resp_bytes"] = rec.get("resp_bytes", 0)
    elif log_type == "dns":
        flow["dns_query"] = rec.get("query", "")
        flow["dns_qtype"] = rec.get("qtype_name", "")
    elif log_type == "ssl":
        flow["ja4"] = rec.get("ja4", "")
        flow["sni"] = rec.get("server_name", "") or rec.get("sni", "")
    elif log_type == "modbus":
        flow["protocol_analyzed"] = "modbus"
        # Zeek's real field is "func" (base/protocols/modbus/main.zeek),
        # NOT "func_name". The wrong key silently defaulted to "" every
        # time, so ENG07's dangerous-function check never matched.
        flow["modbus_func"] = rec.get("func", "") or rec.get("func_name", "")
        flow["register_address"] = rec.get("register", 0)
    elif log_type == "dnp3":
        # icsnpp-dnp3 / base dnp3.log field is fc_request (request function
        # code name). Live capture's FlowAssembler emits the same key.
        flow["protocol_analyzed"] = "dnp3"
        flow["dnp3_func"] = rec.get("fc_request", "") or rec.get("func", "")
    elif log_type == "http":
        flow["http_method"] = rec.get("method", "")
        flow["http_uri"] = rec.get("uri", "")
        flow["http_user_agent"] = rec.get("user_agent", "")
        flow["http_request_body_len"] = rec.get("request_body_len", 0)
    elif log_type == "kerberos":
        flow["krb_request_type"] = rec.get("request_type", "")
        flow["krb_cipher"] = rec.get("cipher", "")
        flow["krb_service"] = rec.get("service", "")
    elif log_type == "cip":
        flow["protocol_analyzed"] = "enip"
        flow["cip_service"] = rec.get("service")
        flow["cip_response"] = bool(rec.get("response", False))
        flow["cip_class_id"] = rec.get("class_id")
        flow["cip_instance_id"] = rec.get("instance_id")

    return flow
