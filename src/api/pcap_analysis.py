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
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from redis import Redis

from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.eng01_ddos import VolumetricDDoSDetector
from src.engines.eng13_bruteforce import BruteForceDetector
from src.engines.eng02_c2_beaconing import C2BeaconingDetector
from src.engines.eng03_dga_dns import DGADetector, TlsSniDetector
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
from src.inference.fusion import effective_threshold
from src.flow_mapping import map_record
from pcap_parser import parse_pcap

router = APIRouter()

# Desktop/standalone build: no zeek-batch / suricata-batch containers exist,
# so don't spend a 60-90 s timeout (or create /incoming on the host) waiting
# for them -- go straight to the in-process parser.
STANDALONE = os.environ.get("STEALTHTAP_STANDALONE") == "1"

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

# --- availability limits -------------------------------------------------
# One 93MB upload (564,832 flows) used to freeze the ENTIRE API -- /health
# included -- for minutes, because the CPU-heavy stages below ran ON the
# asyncio event loop with no concurrency cap and no deadline. Now:
#   * heavy stages run in a small dedicated thread pool (event loop stays free)
#   * at most MAX_CONCURRENT_ANALYSES run at once; up to MAX_QUEUED_ANALYSES
#     wait; beyond that the caller gets 429 + Retry-After instead of piling on
#   * every analysis has a hard wall-clock deadline (-> 504, not an open socket)
#   * files too large for the single-worker Suricata queue skip Suricata
#     rather than stall every later upload behind them (measured: one 93.8MB
#     file kept that queue busy for minutes)
MAX_CONCURRENT_ANALYSES = int(os.environ.get("MAX_CONCURRENT_ANALYSES", "2"))
MAX_QUEUED_ANALYSES = int(os.environ.get("MAX_QUEUED_ANALYSES", "8"))
ANALYSIS_TIMEOUT_SECONDS = float(os.environ.get("ANALYSIS_TIMEOUT_SECONDS", "600"))
SURICATA_MAX_BYTES = int(os.environ.get("SURICATA_MAX_BYTES", str(40 * 1024 * 1024)))
JOB_TTL_SECONDS = 3600

_ANALYSIS_POOL = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_ANALYSES, thread_name_prefix="analysis")
_inflight = 0
_inflight_lock = threading.Lock()
_JOBS: dict[str, dict] = {}

# ML alerting threshold and per-family MITRE mapping now live in
# src/inference/ (model_server.MIN_ML_CONFIDENCE, ml_alerts.ML_THREAT_MAPPING)
# so the upload and live paths share one definition. The record->flow
# mapper is src/flow_mapping.map_record for the same reason.


async def _parse_via_zeek(pcap_bytes: bytes) -> Optional[dict[str, list[dict]]]:
    """Submits the pcap to the zeek-batch service via the shared
    incoming/ volume, polls outgoing/ for its result, and returns None
    (triggering fallback to the scapy parser) if zeek-batch doesn't
    respond within ZEEK_TIMEOUT_SECONDS or errors."""
    if STANDALONE:
        return None
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
        incoming_path.unlink(missing_ok=True)
        return None

    # Reading + json-parsing multi-hundred-MB Zeek logs is CPU/IO-heavy: off the loop.
    parsed = await asyncio.to_thread(_read_zeek_logs, outgoing_path)
    parsed["_job_id"] = job_id  # not a real log type -- used by the caller to locate extracted_files/
    return parsed


def _read_zeek_logs(outgoing_path: Path) -> dict[str, list[dict]]:
    parsed: dict[str, list[dict]] = {"conn": [], "dns": [], "ssl": [], "modbus": [], "dnp3": [], "http": [], "kerberos": [], "notice": [], "cip": []}
    for log_type in parsed:
        log_path = outgoing_path / f"{log_type}.log"
        if not log_path.exists():
            continue
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed[log_type].append(json.loads(line))
                except json.JSONDecodeError:
                    continue
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
    if STANDALONE:
        return []
    if len(pcap_bytes) > SURICATA_MAX_BYTES:
        print(f"[pcap_analysis] skipping suricata: {len(pcap_bytes)/1e6:.0f}MB exceeds SURICATA_MAX_BYTES "
              f"({SURICATA_MAX_BYTES/1e6:.0f}MB) -- one huge file would stall the single-worker queue for every later upload")
        return []
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
        incoming_path.unlink(missing_ok=True)   # not started yet? then don't let it clog the queue later
        return []

    def _read_eve() -> list[dict]:
        recs: list[dict] = []
        eve_path = outgoing_path / "eve.json"
        if eve_path.exists():
            with open(eve_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        recs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        shutil.rmtree(outgoing_path, ignore_errors=True)
        return recs
    records = await asyncio.to_thread(_read_eve)
    try:
        return parse_suricata_alerts(records)
    except Exception as exc:
        print(f"[pcap_analysis] failed to parse suricata alerts: {exc}")
        return []


def _build_ml_alert(flow: dict, family: str, result: dict, corroborated: bool = False) -> Optional[Alert]:
    """Thin wrapper over the shared builder; the score an ML verdict needs
    depends on the family and on rule corroboration (src/inference/fusion.py)."""
    return build_ml_alert(flow, family, result, min_confidence=effective_threshold(family, corroborated))


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

    # eng01/eng02/eng06/eng13 key their Redis state by (src_ip[, dst_ip][,
    # dst_port]) and a bucket derived from the FLOW'S OWN embedded
    # timestamp -- correct for live capture, where that state is meant to
    # persist across the whole run. For a one-shot pcap upload it is
    # exactly the wrong default: two uploads whose packets happen to share
    # a 10s-60s timestamp bucket (trivially true re-analyzing the same
    # file, or any two pcaps from the same capture session) would
    # otherwise silently inherit each other's flood/beacon/exfil/
    # brute-force counters -- producing alert categories that have
    # nothing to do with THIS pcap and aren't reproducible run-to-run.
    # A fresh prefix per call isolates every upload's state completely;
    # the engines' own TTLs (30s-3600s) then garbage-collect it.
    state_prefix = f"upload:{uuid.uuid4().hex[:12]}:"
    rule_engines = {
        "eng01": VolumetricDDoSDetector(redis_client=redis_client, key_prefix=state_prefix),
        "eng13": BruteForceDetector(redis_client=redis_client, key_prefix=state_prefix),
        "eng02": C2BeaconingDetector(redis_client=redis_client, key_prefix=state_prefix),
        # ENG-03 now owns the unified DNS/DGA decision -- rule-based
        # tunnelling + trained-model DGA (falls back to a deterministic
        # lexical heuristic when no dns model is loaded). This retires
        # the old parallel "ml_dns" path the PRD flagged as duplication.
        "eng03": DGADetector(model_server=model_server),
        "eng03s": TlsSniDetector(model_server=model_server),
        "eng04": EncryptedMalwareDetector(),
        "eng05": ReconDetector(),
        "eng06": ExfiltrationDetector(redis_client=redis_client, key_prefix=state_prefix),
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

    flow_ml_flows: list[dict] = []  # scored in ONE batch after the rule engines (below)
    for rec in parsed.get("conn", []):
        flow = map_record(rec, "conn")
        for name in ("eng01", "eng02", "eng05", "eng06", "eng13"):
            _run_rule(name, flow)
            alert = await rule_engines[name].score(flow)
            if alert:
                coverage[name]["alerts_fired"] += 1
                alerts.append(alert.model_dump(mode="json"))
        flow_ml_flows.append(flow)

    # Flow-family ML: one batched ONNX call (was one call per flow, ~3.5 ms
    # each), and an alert policy that lets the weak flow model raise an
    # alert alone only at very high confidence -- otherwise only when a
    # rule engine flagged the same flow (src/inference/fusion.py).
    coverage["ml_flow"]["records_processed"] += len(flow_ml_flows)
    if model_server is not None and flow_ml_flows:
        rule_uids = {a["alert_id"] for a in alerts if a.get("detection_mode") == "rule"}
        try:
            flow_results = model_server.score_flows_batch(flow_ml_flows, "flow")
        except Exception:
            flow_results = [None] * len(flow_ml_flows)
        for fl, res in zip(flow_ml_flows, flow_results):
            if res is None:
                continue
            ml_alert = _build_ml_alert(fl, "flow", res, corroborated=fl.get("flow_uid") in rule_uids)
            if ml_alert:
                coverage["ml_flow"]["alerts_fired"] += 1
                alerts.append(ml_alert.model_dump(mode="json"))

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
        # TLS has no trained model of its own (no labeled data) -- the SNI is a
        # domain, so the trained DNS/DGA model scores it (ENG-03, SNI variant)
        _run_rule("eng03s", flow)
        alert = await rule_engines["eng03s"].score(flow)
        if alert:
            coverage["eng03s"]["alerts_fired"] += 1
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


def _run_engines_blocking(parsed, model_server, redis_client):
    """The engine stage is CPU-bound Python/Rust (+ Redis when the native module
    is absent); run it in a worker thread with its own event loop so the API's
    loop keeps answering /health while a big capture is scored."""
    return asyncio.run(_run_engines(parsed, model_server, redis_client))


def _parse_fallback(contents: bytes) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name
    try:
        return parse_pcap(tmp_path)
    finally:
        os.unlink(tmp_path)


def _admit() -> None:
    """Backpressure: refuse (429) rather than queue unboundedly."""
    global _inflight
    with _inflight_lock:
        if _inflight >= MAX_CONCURRENT_ANALYSES + MAX_QUEUED_ANALYSES:
            raise HTTPException(429, f"analysis queue full ({_inflight} in flight, cap "
                                     f"{MAX_CONCURRENT_ANALYSES}+{MAX_QUEUED_ANALYSES}); retry shortly",
                                headers={"Retry-After": "15"})
        _inflight += 1


def _release() -> None:
    global _inflight
    with _inflight_lock:
        _inflight = max(0, _inflight - 1)


async def _analyze_contents(contents: bytes, filename: str, app_state) -> dict:
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
        try:
            parsed = await asyncio.to_thread(_parse_fallback, contents)
        except Exception as exc:
            raise HTTPException(422, f"could not parse pcap via either Zeek or the fallback parser: {exc}")
    parse_time = time.time() - t0

    model_server = getattr(app_state, "model_server", None)
    yara_scanner = getattr(app_state, "yara_scanner", None)
    redis_client = getattr(app_state, "redis", None)

    t0 = time.time()
    loop = asyncio.get_running_loop()
    alerts, engine_coverage = await loop.run_in_executor(
        _ANALYSIS_POOL, _run_engines_blocking, parsed, model_server, redis_client)
    yara_alerts: list[dict] = []
    files_extracted = 0
    if zeek_job_id:
        extracted = ZEEK_OUTGOING_DIR / zeek_job_id / "extracted_files"
        files_extracted = len(list(extracted.iterdir())) if extracted.is_dir() else 0
        yara_alerts = await asyncio.to_thread(_scan_extracted_files, zeek_job_id, yara_scanner)
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
        "suricata": {"ran": parser_used == "zeek" and len(contents) <= SURICATA_MAX_BYTES, "alerts_fired": len(suricata_alerts),
                     **({"skipped": f"file larger than {SURICATA_MAX_BYTES // (1024 * 1024)}MB -- would stall the single-worker Suricata queue"} if len(contents) > SURICATA_MAX_BYTES else {})},  # submitted alongside zeek; "ran" here means the job queue accepted it, not that it necessarily returned before timeout
        "yara": {"ran": zeek_job_id is not None, "files_scanned": files_extracted, "alerts_fired": len(yara_alerts)},
        **engine_coverage,
    }

    return {
        "analysis_id": str(uuid.uuid4()),
        "filename": filename,
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


async def _guarded_analysis(contents: bytes, filename: str, app_state) -> dict:
    try:
        return await asyncio.wait_for(_analyze_contents(contents, filename, app_state), ANALYSIS_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise HTTPException(504, f"analysis exceeded {ANALYSIS_TIMEOUT_SECONDS:.0f}s; use POST /analyze/pcap/async "
                                 f"and poll GET /analyze/jobs/<id> for large captures")


@router.post("/analyze/pcap")
async def analyze_pcap(request: Request, file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(400, "expected a .pcap or .pcapng file")
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file exceeds {MAX_UPLOAD_BYTES} byte cap")
    _admit()
    try:
        return await _guarded_analysis(contents, file.filename, request.app.state)
    finally:
        _release()


def _sweep_jobs() -> None:
    cutoff = time.time() - JOB_TTL_SECONDS
    for jid in [j for j, v in _JOBS.items() if v["created"] < cutoff]:
        _JOBS.pop(jid, None)


@router.post("/analyze/pcap/async", status_code=202)
async def analyze_pcap_async(request: Request, file: UploadFile = File(...)):
    """Submit-and-poll variant for large captures: returns immediately with a
    job id; the analysis runs in the background under the same concurrency cap
    and deadline. Poll GET /analyze/jobs/{job_id}."""
    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(400, "expected a .pcap or .pcapng file")
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file exceeds {MAX_UPLOAD_BYTES} byte cap")
    _admit()
    _sweep_jobs()
    job_id = uuid.uuid4().hex
    _JOBS[job_id] = {"status": "running", "created": time.time(), "filename": file.filename}
    app_state = request.app.state
    filename = file.filename

    async def _run():
        try:
            _JOBS[job_id].update(status="done", result=await _guarded_analysis(contents, filename, app_state))
        except HTTPException as exc:
            _JOBS[job_id].update(status="error", error=exc.detail, http_status=exc.status_code)
        except Exception as exc:  # never let a background task die silently
            _JOBS[job_id].update(status="error", error=f"{type(exc).__name__}: {exc}", http_status=500)
        finally:
            _release()

    asyncio.create_task(_run())
    return {"job_id": job_id, "status": "running", "poll": f"/analyze/jobs/{job_id}"}


@router.get("/analyze/jobs/{job_id}")
async def analyze_job(job_id: str):
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown or expired job id")
    if job["status"] == "done":
        return {"job_id": job_id, "status": "done", "result": job["result"]}
    if job["status"] == "error":
        return JSONResponse({"job_id": job_id, "status": "error", "error": job["error"]}, status_code=job.get("http_status", 500))
    return {"job_id": job_id, "status": "running", "elapsed_s": round(time.time() - job["created"], 1)}
