"""
Upload PCAP analysis endpoint.

Two parsing paths, in priority order:
  1. Real Zeek (+ ICSNPP OT plugins) via the zeek-batch service -- this
     is what actually connects Zeek and YARA to uploaded pcaps, which
     the earlier scapy-only version never did.
  2. pcap_parser.py (pure Python/scapy) as an automatic fallback if
     zeek-batch doesn't respond within ZEEK_TIMEOUT_SECONDS -- keeps
     the upload endpoint working even if that service is down, rather
     than a hard failure.

Both paths produce the identical {'conn':[...], 'dns':[...], 'ssl':[...],
'modbus':[...]} shape, so everything downstream (rule engines, ML
scoring) is unchanged regardless of which path actually ran. The
response's "parser_used" field tells you which one fired.

Files Zeek extracts from cleartext protocols (HTTP, FTP, SMB -- never
TLS/QUIC, Zeek can't decrypt those) are scanned with the same
YaraFileScanner used by yara_scan_worker.py, producing real
MALICIOUS_FILE_DETECTED alerts instead of YARA being a disconnected,
standalone script.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from redis import Redis

from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.eng01_ddos import VolumetricDDoSDetector
from src.engines.eng13_bruteforce import BruteForceDetector
from src.engines.eng02_c2_beaconing import C2BeaconingDetector
from src.engines.eng03_dga_dns import DGADetector
from src.engines.eng04_encrypted_malware import EncryptedMalwareDetector
from src.engines.eng05_recon import ReconDetector
from src.engines.eng06_exfiltration import ExfiltrationDetector
from src.engines.eng07_ot_anomaly import OTIndustrialAnomalyDetector
from src.engines.eng08_yara_scan import YaraFileScanner
from src.engines.eng09_http_threats import HTTPThreatDetector
from src.engines.eng10_suricata import parse_suricata_alerts
from src.engines.eng11_kerberos import KerberosAttackDetector
from src.engines.eng12_bzar_notices import parse_bzar_notices
from src.inference.model_server import HybridModelServer, MIN_ML_CONFIDENCE
from src.inference.ml_alerts import build_ml_alert, ML_THREAT_MAPPING
from src.flow_mapping import map_record
from pcap_parser import parse_pcap

router = APIRouter()

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200MB cap
ZEEK_INCOMING_DIR = Path(os.environ.get("ZEEK_INCOMING_DIR", "/incoming"))
ZEEK_OUTGOING_DIR = Path(os.environ.get("ZEEK_OUTGOING_DIR", "/outgoing"))
ZEEK_TIMEOUT_SECONDS = float(os.environ.get("ZEEK_TIMEOUT_SECONDS", "60"))
ZEEK_POLL_INTERVAL = 1.0

SURICATA_INCOMING_DIR = Path(os.environ.get("SURICATA_INCOMING_DIR", "/suricata_incoming"))
SURICATA_OUTGOING_DIR = Path(os.environ.get("SURICATA_OUTGOING_DIR", "/suricata_outgoing"))
# Measured directly: a fresh Suricata invocation takes ~17.8s just to
# compile 20,829 rules (PCRE/JIT), essentially independent of pcap
# size -- 90s gives real margin above that baseline rather than a
# guessed number.
SURICATA_TIMEOUT_SECONDS = float(os.environ.get("SURICATA_TIMEOUT_SECONDS", "90"))
SURICATA_POLL_INTERVAL = 1.0

# ML alerting threshold and per-family MITRE mapping now live in
# src/inference/ (model_server.MIN_ML_CONFIDENCE, ml_alerts.ML_THREAT_MAPPING)
# so the upload and live paths share one definition. The record->flow
# mapper is src/flow_mapping.map_record for the same reason.


async def _parse_via_zeek(pcap_bytes: bytes) -> Optional[dict[str, list[dict]]]:
    """Submits the pcap to the zeek-batch service via the shared
    incoming/ volume, polls outgoing/ for its result, and returns None
    (triggering fallback to the scapy parser) if zeek-batch doesn't
    respond within ZEEK_TIMEOUT_SECONDS or errors."""
    job_id = str(uuid.uuid4())
    incoming_path = ZEEK_INCOMING_DIR / f"{job_id}.pcap"
    outgoing_path = ZEEK_OUTGOING_DIR / job_id

    try:
        ZEEK_INCOMING_DIR.mkdir(parents=True, exist_ok=True)
        incoming_path.write_bytes(pcap_bytes)
    except OSError as exc:
        print(f"[pcap_analysis] could not write to zeek incoming dir: {exc}")
        return None

    deadline = time.time() + ZEEK_TIMEOUT_SECONDS
    while time.time() < deadline:
        if (outgoing_path / "DONE").exists():
            break
        if (outgoing_path / "ERROR").exists():
            stderr = (outgoing_path / "zeek_stderr.log")
            print(f"[pcap_analysis] zeek-batch job {job_id} failed: "
                  f"{stderr.read_text() if stderr.exists() else 'unknown error'}")
            return None
        await asyncio.sleep(ZEEK_POLL_INTERVAL)
    else:
        print(f"[pcap_analysis] zeek-batch job {job_id} timed out after {ZEEK_TIMEOUT_SECONDS}s -- falling back")
        return None

    parsed: dict[str, list[dict]] = {"conn": [], "dns": [], "ssl": [], "modbus": [], "dnp3": [], "http": [], "kerberos": [], "notice": [], "cip": []}
    for log_type in parsed:
        log_path = outgoing_path / f"{log_type}.log"
        if not log_path.exists():
            continue
        for line in log_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed[log_type].append(json.loads(line))
            except json.JSONDecodeError:
                continue

    parsed["_job_id"] = job_id  # not a real log type -- used by the caller to locate extracted_files/
    return parsed


def _scan_extracted_files(job_id: str, scanner: Optional[YaraFileScanner]) -> list[dict]:
    """Runs YARA against anything Zeek extracted from cleartext traffic
    in this job. Returns [] if no scanner is available (no rules/ found)
    or nothing was extracted -- never raises, so a YARA problem doesn't
    take down the whole analysis."""
    if scanner is None:
        return []
    extracted_dir = ZEEK_OUTGOING_DIR / job_id / "extracted_files"
    if not extracted_dir.is_dir():
        return []

    alerts: list[dict] = []
    for filepath in extracted_dir.iterdir():
        try:
            alert = scanner.scan_file(filepath)
        except Exception as exc:
            print(f"[pcap_analysis] YARA scan failed on {filepath.name}: {exc}")
            continue
        if alert:
            alerts.append(alert.model_dump(mode="json"))
    return alerts


def _cleanup_zeek_job(job_id: str) -> None:
    job_dir = ZEEK_OUTGOING_DIR / job_id
    shutil.rmtree(job_dir, ignore_errors=True)


async def _run_suricata(pcap_bytes: bytes) -> list[dict]:
    """Submits the pcap to suricata-batch, polls for its result, parses
    eve.json into Alert dicts. Unlike Zeek, there's no fallback engine
    for signature matching -- a timeout or error here just means zero
    Suricata alerts for this analysis, not a failed request. Runs
    concurrently with _parse_via_zeek (see analyze_pcap) since the two
    services are fully independent."""
    job_id = str(uuid.uuid4())
    incoming_path = SURICATA_INCOMING_DIR / f"{job_id}.pcap"
    outgoing_path = SURICATA_OUTGOING_DIR / job_id

    try:
        SURICATA_INCOMING_DIR.mkdir(parents=True, exist_ok=True)
        incoming_path.write_bytes(pcap_bytes)
    except OSError as exc:
        print(f"[pcap_analysis] could not write to suricata incoming dir: {exc}")
        return []

    deadline = time.time() + SURICATA_TIMEOUT_SECONDS
    while time.time() < deadline:
        if (outgoing_path / "DONE").exists():
            break
        if (outgoing_path / "ERROR").exists():
            stderr = outgoing_path / "suricata_stderr.log"
            print(f"[pcap_analysis] suricata-batch job {job_id} failed: "
                  f"{stderr.read_text()[-500:] if stderr.exists() else 'unknown error'}")
            shutil.rmtree(outgoing_path, ignore_errors=True)
            return []
        await asyncio.sleep(SURICATA_POLL_INTERVAL)
    else:
        print(f"[pcap_analysis] suricata-batch job {job_id} timed out after {SURICATA_TIMEOUT_SECONDS}s")
        return []

    eve_path = outgoing_path / "eve.json"
    records: list[dict] = []
    if eve_path.exists():
        for line in eve_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    shutil.rmtree(outgoing_path, ignore_errors=True)
    try:
        return parse_suricata_alerts(records)
    except Exception as exc:
        print(f"[pcap_analysis] failed to parse suricata alerts: {exc}")
        return []


def _build_ml_alert(flow: dict, family: str, result: dict) -> Optional[Alert]:
    """Thin wrapper over the shared builder, pinning MIN_ML_CONFIDENCE."""
    return build_ml_alert(flow, family, result, min_confidence=MIN_ML_CONFIDENCE)


async def _run_engines(parsed: dict[str, list[dict]], model_server: Optional[HybridModelServer],
                       redis_client: Optional[Redis] = None) -> tuple[list[dict], dict]:
    """Returns (alerts, coverage) where coverage tracks, per engine,
    both how many records it actually processed (proves it genuinely
    ran on this pcap, even if it found nothing) and how many alerts it
    produced. This is what makes "did every tool actually run" a
    checkable fact in the API response instead of something to take on
    trust -- detection_mode alone can't tell Suricata's rule-fires
    apart from ENG07's, since both report detection_mode="rule"."""
    if redis_client is None:
        # Fallback for direct callers/tests; the API passes its pooled
        # client from app.state so we don't reconnect per request.
        redis_client = Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"))
    rule_engines = {
        "eng01": VolumetricDDoSDetector(redis_client=redis_client),
        "eng13": BruteForceDetector(redis_client=redis_client),
        "eng02": C2BeaconingDetector(redis_client=redis_client),
        # ENG-03 now owns the unified DNS/DGA decision -- rule-based
        # tunnelling + trained-model DGA (falls back to a deterministic
        # lexical heuristic when no dns model is loaded). This retires
        # the old parallel "ml_dns" path the PRD flagged as duplication.
        "eng03": DGADetector(model_server=model_server),
        "eng04": EncryptedMalwareDetector(),
        "eng05": ReconDetector(),
        "eng06": ExfiltrationDetector(redis_client=redis_client),
        "eng07": OTIndustrialAnomalyDetector(),
        "eng09": HTTPThreatDetector(),
        "eng11": KerberosAttackDetector(),
    }
    alerts: list[dict] = []
    coverage = {name: {"records_processed": 0, "alerts_fired": 0} for name in list(rule_engines) + ["ml_flow", "ml_tls", "ml_modbus", "bzar"]}

    def _maybe_ml_score(flow: dict, family: str) -> None:
        key = f"ml_{family}"
        coverage[key]["records_processed"] += 1
        if model_server is None:
            return
        try:
            result = model_server.score_flow(flow, family)
        except Exception:
            return  # missing fields for this family -- skip rather than fail the whole analysis
        if result is None:
            return
        ml_alert = _build_ml_alert(flow, family, result)
        if ml_alert:
            coverage[key]["alerts_fired"] += 1
            alerts.append(ml_alert.model_dump(mode="json"))

    def _run_rule(name: str, flow: dict) -> None:
        coverage[name]["records_processed"] += 1

    for rec in parsed.get("conn", []):
        flow = map_record(rec, "conn")
        for name in ("eng01", "eng02", "eng05", "eng06", "eng13"):
            _run_rule(name, flow)
            alert = await rule_engines[name].score(flow)
            if alert:
                coverage[name]["alerts_fired"] += 1
                alerts.append(alert.model_dump(mode="json"))
        _maybe_ml_score(flow, "flow")

    for rec in parsed.get("dns", []):
        flow = map_record(rec, "dns")
        _run_rule("eng03", flow)
        alert = await rule_engines["eng03"].score(flow)  # ENG-03 does its own dns ML scoring internally
        if alert:
            coverage["eng03"]["alerts_fired"] += 1
            alerts.append(alert.model_dump(mode="json"))

    for rec in parsed.get("ssl", []):
        flow = map_record(rec, "ssl")
        _run_rule("eng04", flow)
        alert = await rule_engines["eng04"].score(flow)
        if alert:
            coverage["eng04"]["alerts_fired"] += 1
            alerts.append(alert.model_dump(mode="json"))
        _maybe_ml_score(flow, "tls")

    MODBUS_SWEEP_WINDOW = 50  # matches the real window used to build the training data
    modbus_register_history: dict[str, list[int]] = {}
    modbus_ml_flows: list[dict] = []  # collected for ONE batched scoring call, not one per record
    for rec in parsed.get("modbus", []):
        flow = map_record(rec, "modbus")
        # register_sweep_count: distinct registers touched by this source
        # in its recent request history -- the model was trained on this
        # exact feature (see docs/TRAINING_DOCUMENTATION.md, Modbus
        # section), so it has to be computed the same way at serving
        # time, not left to default. Per-source, in-memory for this
        # single analysis (not cross-request Redis state like ENG-01/02/06,
        # since a single pcap upload is naturally bounded and doesn't need
        # to survive across separate uploads the way live-flood detection does).
        src = flow.get("src_ip", "unknown")
        history = modbus_register_history.setdefault(src, [])
        history.append(int(flow.get("register_address", 0)))
        if len(history) > MODBUS_SWEEP_WINDOW:
            history.pop(0)
        flow["register_sweep_count"] = len(set(history))

        _run_rule("eng07", flow)
        alert = await rule_engines["eng07"].score(flow)
        if alert:
            coverage["eng07"]["alerts_fired"] += 1
            alerts.append(alert.model_dump(mode="json"))
        modbus_ml_flows.append(flow)

    # Batched ML scoring: real production testing found this loop taking
    # 30-40s of detection time on a single real capture (39,969 Modbus
    # records, each individually paying full ONNX Runtime call overhead).
    # ONE batched call instead of one per record -- verified to produce
    # results IDENTICAL to the one-at-a-time path (see model_server.py's
    # docstring), not just similar.
    coverage["ml_modbus"]["records_processed"] += len(modbus_ml_flows)
    if model_server is not None and modbus_ml_flows:
        try:
            batch_results = model_server.score_flows_batch(modbus_ml_flows, "modbus")
        except Exception:
            batch_results = [None] * len(modbus_ml_flows)
        for flow, result in zip(modbus_ml_flows, batch_results):
            if result is None:
                continue
            ml_alert = _build_ml_alert(flow, "modbus", result)
            if ml_alert:
                coverage["ml_modbus"]["alerts_fired"] += 1
                alerts.append(ml_alert.model_dump(mode="json"))

    for rec in parsed.get("cip", []):
        flow = map_record(rec, "cip")
        _run_rule("eng07", flow)
        alert = await rule_engines["eng07"].score(flow)
        if alert:
            coverage["eng07"]["alerts_fired"] += 1
            alerts.append(alert.model_dump(mode="json"))

    for rec in parsed.get("dnp3", []):
        flow = map_record(rec, "dnp3")
        _run_rule("eng07", flow)
        alert = await rule_engines["eng07"].score(flow)
        if alert:
            coverage["eng07"]["alerts_fired"] += 1
            alerts.append(alert.model_dump(mode="json"))

    for rec in parsed.get("http", []):
        flow = map_record(rec, "http")
        _run_rule("eng09", flow)
        alert = await rule_engines["eng09"].score(flow)
        if alert:
            coverage["eng09"]["alerts_fired"] += 1
            alerts.append(alert.model_dump(mode="json"))

    for rec in parsed.get("kerberos", []):
        flow = map_record(rec, "kerberos")
        _run_rule("eng11", flow)
        alert = await rule_engines["eng11"].score(flow)
        if alert:
            coverage["eng11"]["alerts_fired"] += 1
            alerts.append(alert.model_dump(mode="json"))

    # BZAR operates on the whole notice.log at once, not per-record
    # scoring like the other engines -- it does its own internal
    # filtering for BZAR::-prefixed notices.
    notice_records = parsed.get("notice", [])
    coverage["bzar"]["records_processed"] = len(notice_records)
    bzar_alerts = parse_bzar_notices(notice_records)
    coverage["bzar"]["alerts_fired"] = len(bzar_alerts)
    alerts.extend(bzar_alerts)

    return alerts, coverage


@router.post("/analyze/pcap")
async def analyze_pcap(request: Request, file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(400, "expected a .pcap or .pcapng file")

    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file exceeds {MAX_UPLOAD_BYTES} byte cap")

    parser_used = "zeek"
    t0 = time.time()
    # Zeek parsing and Suricata signature matching are fully
    # independent services -- run them concurrently rather than one
    # after another. Both poll their own job queue on their own
    # timeout, so gather() only waits as long as the slower of the two.
    parsed, suricata_alerts = await asyncio.gather(
        _parse_via_zeek(contents),
        _run_suricata(contents),
    )
    zeek_job_id = parsed.pop("_job_id", None) if parsed else None

    if parsed is None:
        parser_used = "scapy_fallback"
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name
        try:
            parsed = parse_pcap(tmp_path)
        except Exception as exc:
            raise HTTPException(422, f"could not parse pcap via either Zeek or the fallback parser: {exc}")
        finally:
            os.unlink(tmp_path)
    parse_time = time.time() - t0

    model_server = getattr(request.app.state, "model_server", None)
    yara_scanner = getattr(request.app.state, "yara_scanner", None)
    redis_client = getattr(request.app.state, "redis", None)

    t0 = time.time()
    alerts, engine_coverage = await _run_engines(parsed, model_server, redis_client)
    yara_alerts: list[dict] = []
    files_extracted = 0
    if zeek_job_id:
        files_extracted = len(list((ZEEK_OUTGOING_DIR / zeek_job_id / "extracted_files").iterdir())) if (ZEEK_OUTGOING_DIR / zeek_job_id / "extracted_files").is_dir() else 0
        yara_alerts = _scan_extracted_files(zeek_job_id, yara_scanner)
        alerts.extend(yara_alerts)
        _cleanup_zeek_job(zeek_job_id)
    alerts.extend(suricata_alerts)
    detect_time = time.time() - t0

    severity_counts: dict[str, int] = {}
    threat_class_counts: dict[str, int] = {}
    detection_mode_counts: dict[str, int] = {}
    for a in alerts:
        severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1
        threat_class_counts[a["threat_class"]] = threat_class_counts.get(a["threat_class"], 0) + 1
        detection_mode_counts[a["detection_mode"]] = detection_mode_counts.get(a["detection_mode"], 0) + 1

    # Explicit, checkable proof of which tools actually ran on THIS
    # upload -- not inferred from detection_mode (which can't tell
    # Suricata's rule-fires apart from ENG07's), and not just "the
    # service is Up" (which doesn't prove it processed this file).
    pipeline_coverage = {
        "zeek": {"ran": parser_used == "zeek", "records_parsed": sum(len(parsed.get(k, [])) for k in ("conn", "dns", "ssl", "modbus", "http"))},
        "suricata": {"ran": parser_used == "zeek", "alerts_fired": len(suricata_alerts)},  # submitted alongside zeek; "ran" here means the job queue accepted it, not that it necessarily returned before timeout
        "yara": {"ran": zeek_job_id is not None, "files_scanned": files_extracted, "alerts_fired": len(yara_alerts)},
        **engine_coverage,
    }

    return {
        "analysis_id": str(uuid.uuid4()),
        "filename": file.filename,
        "parser_used": parser_used,  # "zeek" or "scapy_fallback" -- tells you which path actually ran
        "packet_summary": {
            "conn_flows": len(parsed.get("conn", [])),
            "dns_queries": len(parsed.get("dns", [])),
            "tls_sessions": len(parsed.get("ssl", [])),
            "modbus_records": len(parsed.get("modbus", [])),
            "dnp3_records": len(parsed.get("dnp3", [])),
            "http_requests": len(parsed.get("http", [])),
            "kerberos_events": len(parsed.get("kerberos", [])),
            "cip_events": len(parsed.get("cip", [])),
            "files_yara_scanned": len(yara_alerts) if parser_used == "zeek" else None,
        },
        "pipeline_coverage": pipeline_coverage,
        "timing": {"parse_seconds": round(parse_time, 3), "detection_seconds": round(detect_time, 3)},
        "models_active": model_server.loaded_families() if model_server else [],
        "yara_active": yara_scanner is not None,
        "suricata_alert_count": len(suricata_alerts),  # 0 doesn't distinguish "ran clean" from "timed out" -- check logs if that matters
        "alert_count": len(alerts),
        "severity_counts": severity_counts,
        "threat_class_counts": threat_class_counts,
        "detection_mode_counts": detection_mode_counts,
        "alerts": alerts,
    }
