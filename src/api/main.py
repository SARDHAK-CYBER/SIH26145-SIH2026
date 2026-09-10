"""
StealthTap API — hybrid ML inference + alert query layer.

Endpoints:
  POST /score/{family}      run hybrid XGBoost + Isolation Forest inference on a flow record
  GET  /alerts               query stored alerts (filters: threat_class, severity, since, limit)
  GET  /alerts/{alert_id}    fetch one alert
  GET  /health                liveness/readiness -- reports which model families actually loaded
  GET  /models/manifest       exposes MANIFEST.json (dataset, training date, metrics) --
                               lets a jury see exactly what's running and how it was validated

Grafana connects directly to PostgreSQL as its data source (standard
Grafana practice) -- this API exists for the React dashboard and for the
ML scoring path itself, not for Grafana.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncpg
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from redis import Redis
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.features.feature_extraction import FEATURE_SCHEMA_VERSION
from src.inference.model_server import HybridModelServer, MIN_ML_CONFIDENCE
from src.inference.ml_alerts import ML_THREAT_MAPPING
from src.engines.eng08_yara_scan import YaraFileScanner
from src.api.pcap_analysis import router as pcap_router
try:
    from src.api.live_capture import router as live_capture_router
except Exception as _lc_exc:  # scapy/psutil missing -> live capture simply unavailable
    live_capture_router = None
    print(f"[api] live-capture router unavailable: {_lc_exc}")

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://stealthtap:stealthtap@postgres:5432/stealthtap")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

app = FastAPI(title="StealthTap API", version="1.0.0")

# The TSX dashboard (dashboard-app/) runs on its own dev server (port 5173)
# or its own container (port 4173). CORS origins are configurable via
# STEALTHTAP_CORS_ORIGINS (comma-separated); the default covers the known
# dev/prod dashboard origins rather than a blanket wildcard.
_default_origins = "http://localhost:5173,http://localhost:4173,http://127.0.0.1:5173,http://127.0.0.1:4173"
_cors_origins = [o.strip() for o in os.environ.get("STEALTHTAP_CORS_ORIGINS", _default_origins).split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware, allow_origins=_cors_origins, allow_methods=["*"], allow_headers=["*"],
)

app.include_router(pcap_router)
if live_capture_router is not None:
    app.include_router(live_capture_router)
try:
    from src.api.dashboard import router as dashboard_router
    app.include_router(dashboard_router)
except Exception as _dash_exc:  # pragma: no cover
    print(f"[api] dashboard router unavailable: {_dash_exc}")

# Serves dashboard.html (the framework-free fallback version) at /ui.
# The TSX dashboard is a separate service (see docker-compose.yml) --
# this static mount is for the simple version only, so the API still
# has a working UI even if the TSX app isn't built/running.
if os.path.isdir("dashboard"):
    app.mount("/ui", StaticFiles(directory="dashboard", html=True), name="dashboard")

model_server: Optional[HybridModelServer] = None
db_pool: Optional[asyncpg.Pool] = None
redis_client: Optional[Redis] = None

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    severity TEXT NOT NULL,
    confidence_score REAL NOT NULL,
    threat_class TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    mitre_tactic TEXT NOT NULL,
    mitre_technique_id TEXT NOT NULL,
    mitre_technique_name TEXT NOT NULL,
    evidence JSONB NOT NULL,
    forensics JSONB NOT NULL,
    detection_mode TEXT NOT NULL DEFAULT 'rule',
    model_scores JSONB,
    top_contributing_features JSONB
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts (threat_class);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip);
"""


async def _init_connection(conn: asyncpg.Connection) -> None:
    # Without this, JSONB columns come back as raw strings instead of
    # parsed dicts -- register the codec once per connection so callers
    # get real Python objects.
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


@app.on_event("startup")
async def startup() -> None:
    global model_server, db_pool, redis_client
    model_server = HybridModelServer()
    app.state.model_server = model_server  # shared with pcap_analysis.py's router

    # One shared Redis client for the whole process -- pcap_analysis.py's
    # _run_engines used to build a fresh connection on every upload.
    try:
        redis_client = Redis.from_url(REDIS_URL)
        redis_client.ping()
        print(f"[api] redis connected at {REDIS_URL}")
    except Exception as exc:
        redis_client = Redis.from_url(REDIS_URL)  # keep the handle; engines fail open if it's down
        print(f"[api] redis not reachable ({type(exc).__name__}: {exc}) -- stateful engines will fail open")
    app.state.redis = redis_client

    try:
        app.state.yara_scanner = YaraFileScanner(rules_dir=os.environ.get("YARA_RULES_DIR", "rules"))
        print("[api] YARA scanner ready")
    except FileNotFoundError as exc:
        app.state.yara_scanner = None
        print(f"[api] YARA scanner not available: {exc} -- pcap uploads will skip file scanning")

    # Retries on ANY exception, not just DNS errors -- we've seen this
    # fail on transient DNS blips before, but printing the real
    # exception type/message on every attempt means if it's something
    # else entirely (bad password, wrong db name), that reason is
    # visible in the logs immediately instead of retrying blind for 30s
    # and then raising a generic timeout.
    db_pool = None
    last_exc: Exception | None = None
    for attempt in range(1, 11):
        try:
            db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10, init=_init_connection)
            break
        except Exception as exc:
            last_exc = exc
            print(f"[api] waiting for postgres (attempt {attempt}/10): {type(exc).__name__}: {exc}")
            await asyncio.sleep(3)
    if db_pool is None:
        raise RuntimeError(f"Could not connect to postgres after 10 attempts. Last error: {last_exc!r}")

    async with db_pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)
    app.state.db_pool = db_pool  # shared with src/api/dashboard.py
    print("[api] startup complete")


@app.on_event("shutdown")
async def shutdown() -> None:
    if db_pool:
        await db_pool.close()
    if redis_client is not None:
        try:
            redis_client.close()
        except Exception:
            pass


class FlowScoreRequest(BaseModel):
    flow: dict
    threat_class: Optional[str] = None   # defaults to the family's mapped class
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None


@app.post("/score/{family}")
async def score_flow(family: str, req: FlowScoreRequest):
    if model_server is None:
        raise HTTPException(503, "model server not initialized")
    if family not in ("flow", "dns", "tls", "modbus"):
        raise HTTPException(400, f"unknown family '{family}', expected flow/dns/tls/modbus")

    try:
        result = model_server.score_flow(req.flow, family)
    except KeyError as exc:
        raise HTTPException(422, f"flow record missing expected field: {exc}")
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    if result is None:
        return {"fired": False, "reason": "no model loaded for this family yet"}

    # Gate identically to the upload path -- a hybrid score below
    # MIN_ML_CONFIDENCE is not an alert on any path.
    if result["threat_score"] < MIN_ML_CONFIDENCE:
        return {"fired": False, "reason": f"below MIN_ML_CONFIDENCE ({MIN_ML_CONFIDENCE})",
                "threat_score": round(result["threat_score"], 4), "model_scores": result["model_scores"]}

    flow = req.flow
    _mapped = ML_THREAT_MAPPING.get(family, ("RECONNAISSANCE", "Unknown", "T0000", "Unclassified"))
    threat_class = req.threat_class or _mapped[0]
    mitre_tactic = req.mitre_tactic or _mapped[1]
    mitre_technique_id = req.mitre_technique_id or _mapped[2]
    mitre_technique_name = req.mitre_technique_name or _mapped[3]
    _proto = str(flow.get("proto", "TCP")).upper()
    _proto = _proto if _proto in ("TCP", "UDP", "ICMP") else "TCP"
    alert = Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=float(flow.get("ts", time.time())),
        severity="HIGH" if result["threat_score"] > 0.9 else "MEDIUM",
        confidence_score=round(result["threat_score"] * 100, 2),
        threat_class=threat_class,
        flow_identifier=FlowIdentifier(
            src_ip=flow.get("src_ip", "0.0.0.0"), src_port=int(flow.get("src_port", 0) or 0),
            dst_ip=flow.get("dst_ip", "0.0.0.0"), dst_port=int(flow.get("dst_port", 0) or 0),
            protocol=_proto,
        ),
        mitre_attack=MitreAttack(
            tactic=mitre_tactic, technique_id=mitre_technique_id,
            technique_name=mitre_technique_name,
        ),
        evidence={"family": family, "raw_scores": result["model_scores"]},
        forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
        detection_mode=result["detection_mode"],
        model_scores=result["model_scores"],
    )
    await _store_alert(alert)
    return {"fired": True, "alert": json.loads(alert.model_dump_json())}


async def _store_alert(alert: Alert) -> bool:
    async with db_pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO alerts (alert_id, ts, severity, confidence_score, threat_class,
                src_ip, src_port, dst_ip, dst_port, protocol,
                mitre_tactic, mitre_technique_id, mitre_technique_name,
                evidence, forensics, detection_mode, model_scores, top_contributing_features)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
               ON CONFLICT (alert_id) DO NOTHING""",
            alert.alert_id, datetime.fromtimestamp(alert.timestamp, tz=timezone.utc),
            alert.severity, alert.confidence_score, alert.threat_class,
            alert.flow_identifier.src_ip, alert.flow_identifier.src_port,
            alert.flow_identifier.dst_ip, alert.flow_identifier.dst_port,
            alert.flow_identifier.protocol,
            alert.mitre_attack.tactic, alert.mitre_attack.technique_id, alert.mitre_attack.technique_name,
            alert.evidence, alert.forensics,
            alert.detection_mode, alert.model_scores, alert.top_contributing_features,
        )
    return True


@app.post("/alerts/ingest")
async def ingest_alerts(alerts: list[dict]):
    """Bulk-insert alerts into the shared store. Used by the live sensor
    (src/capture) so live-capture alerts land in the SAME `alerts` table
    the PCAP-upload path writes to -- one queryable history for the
    dashboard regardless of ingest path."""
    if db_pool is None:
        raise HTTPException(503, "db not ready")
    stored = 0
    for raw in alerts:
        try:
            stored += 1 if await _store_alert(Alert.model_validate(raw)) else 0
        except Exception as exc:
            # one bad record must not fail the batch
            print(f"[api] /alerts/ingest skipped a record: {exc}")
    return {"received": len(alerts), "stored": stored}


@app.get("/alerts")
async def list_alerts(
    threat_class: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = Query(100, le=1000),
):
    conditions = []
    params: list = []
    if threat_class:
        params.append(threat_class)
        conditions.append(f"threat_class = ${len(params)}")
    if severity:
        params.append(severity)
        conditions.append(f"severity = ${len(params)}")
    if since:
        params.append(datetime.fromisoformat(since))
        conditions.append(f"ts >= ${len(params)}")
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit)
    query = f"SELECT * FROM alerts {where} ORDER BY ts DESC LIMIT ${len(params)}"
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    return [dict(r) for r in rows]


@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM alerts WHERE alert_id = $1", alert_id)
    if not row:
        raise HTTPException(404, "alert not found")
    return dict(row)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "models_loaded": model_server.loaded_families() if model_server else [],
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "db_connected": db_pool is not None,
    }


@app.get("/models/manifest")
async def models_manifest():
    if model_server is None:
        raise HTTPException(503, "model server not initialized")
    if not model_server.manifest:
        raise HTTPException(404, "no MANIFEST.json found in models/ yet")
    return model_server.manifest
