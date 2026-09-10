"""
StealthTap — built by TeamXOR
Streaming engine entrypoint (live path).

ARCHITECTURE NOTE: this process runs on the normal Docker network,
alongside Redpanda -- NOT inside the "capture" network namespace. Only
Zeek itself (zero IP, promiscuous-only, see scripts/setup_netns.sh) runs
air-gapped. This process consumes already-shipped, already-parsed records
from Redpanda, produced there by src/log_shipper.py.

Engine parity: this path now runs the SAME engine set as the upload path
(src/api/pcap_analysis.py) -- ENG01-07, ENG09, ENG11, ENG13, BZAR notice
parsing, plus hybrid ML scoring on every family with a loaded model.
Previously ENG09/11/13 and ML were upload-only, a real live-detection
coverage gap.

ENG-08 (YARA) is NOT here: it operates on extracted files, not flow
records, and runs as its own process (yara_scan_worker.py --watch).
"""
from __future__ import annotations

import json
import os
import socket

import faust
from redis import Redis

from src.engines.eng01_ddos import VolumetricDDoSDetector
from src.engines.eng02_c2_beaconing import C2BeaconingDetector
from src.engines.eng03_dga_dns import DGADetector
from src.engines.eng04_encrypted_malware import EncryptedMalwareDetector
from src.engines.eng05_recon import ReconDetector
from src.engines.eng06_exfiltration import ExfiltrationDetector
from src.engines.eng07_ot_anomaly import OTIndustrialAnomalyDetector
from src.engines.eng09_http_threats import HTTPThreatDetector
from src.engines.eng11_kerberos import KerberosAttackDetector
from src.engines.eng12_bzar_notices import parse_bzar_notices
from src.engines.eng13_bruteforce import BruteForceDetector
from src.flow_mapping import map_record

try:
    from src.inference.model_server import HybridModelServer, MIN_ML_CONFIDENCE
    from src.inference.ml_alerts import build_ml_alert
    _ML_AVAILABLE = True
except Exception as exc:  # onnxruntime not installed, etc. -- ML stays optional
    print(f"[streaming_engine] ML scoring disabled: {exc}")
    _ML_AVAILABLE = False

app = faust.App(
    "stealthtap",
    broker=os.environ.get("REDPANDA_BROKER", "kafka://redpanda:9092"),
    store="memory://",
)

# One topic per Zeek log type, matching src/log_shipper.py's LOG_TOPIC_MAP.
conn_topic = app.topic("stealthtap.flows.conn", value_type=bytes)
dns_topic = app.topic("stealthtap.flows.dns", value_type=bytes)
ssl_topic = app.topic("stealthtap.flows.ssl", value_type=bytes)
modbus_topic = app.topic("stealthtap.flows.modbus", value_type=bytes)
http_topic = app.topic("stealthtap.flows.http", value_type=bytes)
kerberos_topic = app.topic("stealthtap.flows.kerberos", value_type=bytes)
notice_topic = app.topic("stealthtap.flows.notice", value_type=bytes)

redis_client = Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"))

model_server = HybridModelServer() if _ML_AVAILABLE else None

conn_detectors = [
    VolumetricDDoSDetector(redis_client),
    C2BeaconingDetector(redis_client),
    ReconDetector(),
    ExfiltrationDetector(redis_client),
    BruteForceDetector(redis_client),
]
dns_detector = DGADetector(model_server=model_server)
tls_detector = EncryptedMalwareDetector()
ot_detector = OTIndustrialAnomalyDetector()
http_detector = HTTPThreatDetector()
kerberos_detector = KerberosAttackDetector()

RELAY_SOCKET = os.environ.get("RELAY_SOCKET", "/var/run/stealthtap/alerts.sock")


def send_to_relay(alert_json: str) -> None:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(RELAY_SOCKET)
            sock.sendall(alert_json.encode())
    except OSError as exc:
        # The relay being unreachable must never crash the streaming side --
        # log and drop rather than block on a queue that could back-pressure
        # into the isolation boundary.
        print(f"[streaming_engine] could not reach relay: {exc}")


def _ml_score_and_relay(flow: dict, family: str) -> None:
    if model_server is None:
        return
    try:
        result = model_server.score_flow(flow, family)
    except Exception:
        return
    if not result:
        return
    alert = build_ml_alert(flow, family, result, min_confidence=MIN_ML_CONFIDENCE)
    if alert:
        send_to_relay(alert.model_dump_json())


@app.agent(conn_topic)
async def process_conn(records):
    async for raw in records:
        flow = map_record(json.loads(raw), "conn")
        for detector in conn_detectors:
            alert = await detector.score(flow)
            if alert:
                send_to_relay(alert.model_dump_json())
        _ml_score_and_relay(flow, "flow")


@app.agent(dns_topic)
async def process_dns(records):
    async for raw in records:
        flow = map_record(json.loads(raw), "dns")
        alert = await dns_detector.score(flow)
        if alert:
            send_to_relay(alert.model_dump_json())
        _ml_score_and_relay(flow, "dns")


@app.agent(ssl_topic)
async def process_ssl(records):
    async for raw in records:
        flow = map_record(json.loads(raw), "ssl")
        alert = await tls_detector.score(flow)
        if alert:
            send_to_relay(alert.model_dump_json())
        _ml_score_and_relay(flow, "tls")


@app.agent(modbus_topic)
async def process_modbus(records):
    async for raw in records:
        flow = map_record(json.loads(raw), "modbus")
        alert = await ot_detector.score(flow)
        if alert:
            send_to_relay(alert.model_dump_json())
        _ml_score_and_relay(flow, "modbus")


@app.agent(http_topic)
async def process_http(records):
    async for raw in records:
        flow = map_record(json.loads(raw), "http")
        alert = await http_detector.score(flow)
        if alert:
            send_to_relay(alert.model_dump_json())


@app.agent(kerberos_topic)
async def process_kerberos(records):
    async for raw in records:
        flow = map_record(json.loads(raw), "kerberos")
        alert = await kerberos_detector.score(flow)
        if alert:
            send_to_relay(alert.model_dump_json())


@app.agent(notice_topic)
async def process_notice(records):
    async for raw in records:
        for alert_dict in parse_bzar_notices([json.loads(raw)]):
            send_to_relay(json.dumps(alert_dict))


if __name__ == "__main__":
    app.main()
