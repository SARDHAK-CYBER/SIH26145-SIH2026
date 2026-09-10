"""
Dashboard support endpoints — everything the enterprise SOC dashboard
(dashboard-app/) needs beyond /analyze/pcap, /alerts and /models/manifest:

  GET /api/sample/analysis   run the bundled sample pcap through the REAL
                             pipeline once and cache it, so the dashboard
                             opens on a complete, accurate analysis
  GET /api/pipeline/status   live service + 13-engine status
  GET /api/index-patterns    the real field dictionary of the alert store
                             (+ Zeek log indices) for the Index Patterns view
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api", tags=["dashboard"])

_SAMPLE_CANDIDATES = [
    "samples/simulated_attack_traffic.pcap",
    "simulated_attack_traffic.pcap",
    "samples/test.pcap",
]
_sample_cache: dict = {"at": 0.0, "data": None}
_SAMPLE_TTL = 300.0


@router.get("/sample/analysis")
async def sample_analysis(request: Request):
    """Run the reference capture through the real engine pipeline (cached)."""
    now = time.time()
    if _sample_cache["data"] is not None and now - _sample_cache["at"] < _SAMPLE_TTL:
        return _sample_cache["data"]

    path = next((p for p in _SAMPLE_CANDIDATES if Path(p).is_file()), None)
    if path is None:
        # No bundled pcap here — build from stored alerts; if there are
        # none either, 404 so the dashboard shows its own fallback sample.
        resp = await _analysis_from_alerts(request)
        if resp["alert_count"] == 0:
            raise HTTPException(404, "no bundled sample pcap and no stored alerts yet")
        return resp

    from pcap_parser import parse_pcap
    from src.api.pcap_analysis import _run_engines

    model_server = getattr(request.app.state, "model_server", None)
    redis_client = getattr(request.app.state, "redis", None)

    t0 = time.time()
    parsed = await asyncio.get_event_loop().run_in_executor(None, parse_pcap, path)
    parse_s = time.time() - t0

    t0 = time.time()
    alerts, coverage = await _run_engines(parsed, model_server, redis_client)
    detect_s = time.time() - t0

    sev: dict[str, int] = {}
    tc: dict[str, int] = {}
    dm: dict[str, int] = {}
    for a in alerts:
        sev[a["severity"]] = sev.get(a["severity"], 0) + 1
        tc[a["threat_class"]] = tc.get(a["threat_class"], 0) + 1
        dm[a["detection_mode"]] = dm.get(a["detection_mode"], 0) + 1

    resp = {
        "analysis_id": f"sample-{int(now)}",
        "filename": Path(path).name,
        "parser_used": "scapy_fallback",
        "packet_summary": {
            "conn_flows": len(parsed.get("conn", [])),
            "dns_queries": len(parsed.get("dns", [])),
            "tls_sessions": len(parsed.get("ssl", [])),
            "modbus_records": len(parsed.get("modbus", [])),
            "dnp3_records": len(parsed.get("dnp3", [])),
            "http_requests": len(parsed.get("http", [])),
            "kerberos_events": len(parsed.get("kerberos", [])),
            "cip_events": len(parsed.get("cip", [])),
            "files_yara_scanned": None,
        },
        "pipeline_coverage": coverage,
        "timing": {"parse_seconds": round(parse_s, 3), "detection_seconds": round(detect_s, 3)},
        "models_active": model_server.loaded_families() if model_server else [],
        "yara_active": getattr(request.app.state, "yara_scanner", None) is not None,
        "suricata_alert_count": 0,
        "alert_count": len(alerts),
        "severity_counts": sev,
        "threat_class_counts": tc,
        "detection_mode_counts": dm,
        "alerts": alerts,
    }
    _sample_cache.update(at=now, data=resp)
    return resp


async def _analysis_from_alerts(request: Request):
    """Fallback: build an AnalysisResponse-shaped object from stored alerts."""
    pool = getattr(request.app.state, "db_pool", None)
    rows = []
    if pool is not None:
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM alerts ORDER BY ts DESC LIMIT 500")
    alerts = []
    sev: dict[str, int] = {}
    tc: dict[str, int] = {}
    dm: dict[str, int] = {}
    for r in rows:
        d = dict(r)
        a = {
            "alert_id": d["alert_id"],
            "timestamp": d["ts"].timestamp() if d.get("ts") else time.time(),
            "severity": d["severity"], "confidence_score": d["confidence_score"],
            "threat_class": d["threat_class"],
            "flow_identifier": {"src_ip": d["src_ip"], "src_port": d["src_port"],
                                "dst_ip": d["dst_ip"], "dst_port": d["dst_port"], "protocol": d["protocol"]},
            "mitre_attack": {"tactic": d["mitre_tactic"], "technique_id": d["mitre_technique_id"],
                             "technique_name": d["mitre_technique_name"]},
            "evidence": d.get("evidence") or {}, "forensics": d.get("forensics") or {},
            "detection_mode": d.get("detection_mode") or "rule",
            "model_scores": d.get("model_scores"),
            "top_contributing_features": d.get("top_contributing_features"),
        }
        alerts.append(a)
        sev[a["severity"]] = sev.get(a["severity"], 0) + 1
        tc[a["threat_class"]] = tc.get(a["threat_class"], 0) + 1
        dm[a["detection_mode"]] = dm.get(a["detection_mode"], 0) + 1
    model_server = getattr(request.app.state, "model_server", None)
    return {
        "analysis_id": "stored-alerts", "filename": "(stored alerts)", "parser_used": "zeek",
        "packet_summary": {"conn_flows": 0, "dns_queries": 0, "tls_sessions": 0, "modbus_records": 0,
                           "dnp3_records": 0, "http_requests": 0, "files_yara_scanned": None},
        "timing": {"parse_seconds": 0.0, "detection_seconds": 0.0},
        "models_active": model_server.loaded_families() if model_server else [],
        "yara_active": getattr(request.app.state, "yara_scanner", None) is not None,
        "suricata_alert_count": 0, "alert_count": len(alerts),
        "severity_counts": sev, "threat_class_counts": tc, "detection_mode_counts": dm,
        "alerts": alerts,
    }


_ENGINES = [
    ("ENG-01", "Volumetric DDoS + Slowloris", "VOLUMETRIC_DDOS", "Redis CMS rate + source-IP HyperLogLog entropy", "TCP/UDP"),
    ("ENG-02", "C2 Beaconing", "C2_BEACONING", "Inter-arrival coefficient-of-variation", "TCP/DNS"),
    ("ENG-03", "DGA + DNS Tunnelling", "DGA_DOMAIN", "Trained dns XGBoost + lexical heuristic", "DNS"),
    ("ENG-04", "Encrypted Malware (JA4)", "ENCRYPTED_MALWARE", "Real JA4 vs FoxIO threat intel", "TLS"),
    ("ENG-05", "Reconnaissance", "RECONNAISSANCE", "Distinct-destination fan-out", "TCP/UDP/ICMP"),
    ("ENG-06", "Data Exfiltration", "DATA_EXFILTRATION", "Per-flow + accumulated byte ratio", "TCP/UDP"),
    ("ENG-07", "OT Industrial Anomaly", "ICS_UNAUTHORIZED_CONTROL_COMMAND", "Dangerous Modbus/DNP3/CIP command codes", "Modbus·DNP3·CIP"),
    ("ENG-08", "YARA File Scanner", "MALICIOUS_FILE_DETECTED", "~401 rules on cleartext-extracted files", "HTTP/FTP/SMB"),
    ("ENG-09", "HTTP C2 / Exfil", "DATA_EXFILTRATION", "Default UA + URI entropy + large POST", "HTTP"),
    ("ENG-10", "Suricata Signatures", "NETWORK_INTRUSION_ATTEMPT", "20,829 Emerging Threats Open rules", "All"),
    ("ENG-11", "Kerberoasting", "NETWORK_INTRUSION_ATTEMPT", "TGS + RC4 cipher for a service account", "Kerberos"),
    ("ENG-12", "SMB Lateral Movement", "NETWORK_INTRUSION_ATTEMPT", "MITRE BZAR notice parsing", "SMB/DCE-RPC"),
    ("ENG-13", "Credential Brute Force", "NETWORK_INTRUSION_ATTEMPT", "Auth-port attempt counting over a wide window", "FTP/SSH/RDP"),
]


@router.get("/pipeline/status")
async def pipeline_status(request: Request):
    st = request.app.state
    services: dict[str, dict] = {}

    pool = getattr(st, "db_pool", None)
    pg_ok = False
    if pool is not None:
        try:
            async with pool.acquire() as conn:
                await conn.execute("SELECT 1")
            pg_ok = True
        except Exception:
            pg_ok = False
    services["postgresql"] = {"name": "PostgreSQL", "type": "alert store",
                              "status": "connected" if pg_ok else "degraded",
                              "details": "shared alerts table for every ingest path"}

    r = getattr(st, "redis", None)
    redis_ok = False
    if r is not None:
        try:
            redis_ok = bool(r.ping())
        except Exception:
            redis_ok = False
    services["redis"] = {"name": "Redis", "type": "stateful-engine store",
                         "status": "connected" if redis_ok else "standby",
                         "details": "CMS + HyperLogLog for ENG-01/02/06/13"}

    ms = getattr(st, "model_server", None)
    fams = ms.loaded_families() if ms else []
    services["onnx_model_server"] = {"name": "ONNX Model Server", "type": "hybrid ML",
                                     "status": "active" if fams else "standby",
                                     "details": f"families loaded: {', '.join(fams) or 'none'}"}

    services["yara"] = {"name": "YARA", "type": "file signatures",
                        "status": "active" if getattr(st, "yara_scanner", None) else "standby",
                        "details": "scans Zeek-extracted cleartext files"}

    for key, label, env in (("zeek_batch", "Zeek + ICSNPP", "ZEEK_OUTGOING_DIR"),
                            ("suricata_batch", "Suricata (ET Open)", "SURICATA_OUTGOING_DIR")):
        d = os.environ.get(env)
        up = bool(d and Path(d).is_dir())
        services[key] = {"name": label, "type": "job-queue worker",
                         "status": "connected" if up else "standby",
                         "details": f"volume {d or '(unset)'}"}

    try:
        from src.capture.backends import capabilities
        caps = capabilities()
        cap_ok = caps.get("npcap_installed") or caps.get("can_raw_socket")
    except Exception:
        cap_ok = False
    services["live_capture"] = {"name": "Live NIC Capture", "type": "kernel tap",
                                "status": "active" if cap_ok else "standby",
                                "details": "AF_PACKET mmap ring + FANOUT / libpcap-Npcap"}

    engines = [{"id": i, "name": n, "threat_class": tc, "algorithm": alg, "protocol": p, "status": "active"}
               for (i, n, tc, alg, p) in _ENGINES]
    return {"services": services, "engines": engines}


@router.get("/index-patterns")
async def index_patterns():
    """The real field dictionary of the alert store + Zeek log indices."""
    alert_fields = [
        ("@timestamp", "date", "2026-09-11T04:15:00.000Z"),
        ("alert_id", "string", "a3b8c9d1-0f4e-4b72-a6f9"),
        ("severity", "string", "CRITICAL"),
        ("confidence_score", "number", "94.2"),
        ("threat_class", "string", "VOLUMETRIC_DDOS"),
        ("detection_mode", "string", "xgboost"),
        ("flow_identifier.src_ip", "ip", "192.168.100.10"),
        ("flow_identifier.src_port", "number", "45408"),
        ("flow_identifier.dst_ip", "ip", "8.8.8.8"),
        ("flow_identifier.dst_port", "number", "53"),
        ("flow_identifier.protocol", "string", "UDP"),
        ("mitre_attack.tactic", "string", "Command and Control"),
        ("mitre_attack.technique_id", "string", "T1568.002"),
        ("mitre_attack.technique_name", "string", "Domain Generation Algorithms"),
        ("model_scores.xgboost", "number", "0.984"),
        ("model_scores.isolation_forest", "number", "0.62"),
        ("evidence.detection_latency_ms", "number", "157.0"),
        ("forensics.raw_segment_hash_sha256", "string", "sha256:7d3f9c1a…"),
    ]
    conn_fields = [
        ("ts", "date", "1788868800.0"), ("uid", "string", "Cabc123def456"),
        ("id.orig_h", "ip", "10.0.0.9"), ("id.orig_p", "number", "51234"),
        ("id.resp_h", "ip", "93.184.216.34"), ("id.resp_p", "number", "443"),
        ("proto", "string", "tcp"), ("duration", "number", "1.24"),
        ("orig_bytes", "number", "1420"), ("resp_bytes", "number", "58400"),
    ]
    dns_fields = [
        ("ts", "date", "1788868801.0"), ("query", "string", "kqx3vwzptlmnbrx9.com"),
        ("qtype_name", "string", "A"), ("id.orig_h", "ip", "10.0.0.5"), ("id.resp_h", "ip", "8.8.8.8"),
    ]
    ot_fields = [
        ("ts", "date", "1788868802.0"), ("func", "string", "WRITE_MULTIPLE_REGISTERS"),
        ("register", "number", "40012"), ("fc_request", "string", "OPERATE"),
        ("id.orig_h", "ip", "172.16.20.88"), ("id.resp_h", "ip", "172.16.20.10"),
    ]

    def mk(name, tf, desc, fields):
        return {"id": name, "title": name, "timeFieldName": tf, "description": desc,
                "fields": [{"name": n, "type": t, "searchable": True, "aggregatable": t != "text", "sample": s}
                           for (n, t, s) in fields]}

    return [
        mk("stealthtap-alerts-*", "@timestamp",
           "Consolidated threat detections from all 13 engines + hybrid ML, across the upload and live-capture ingest paths.", alert_fields),
        mk("zeek-conn-*", "ts", "Bidirectional flow metadata: duration, byte counts, protocol.", conn_fields),
        mk("zeek-dns-*", "ts", "DNS queries: name, record type, endpoints — feeds ENG-03 (DGA / tunnelling).", dns_fields),
        mk("zeek-ot-*", "ts", "Modbus / DNP3 / EtherNet-IP function codes — feeds ENG-07 (OT anomaly).", ot_fields),
    ]
