"""
StealthTap batch/offline entrypoint.

Reads static Zeek JSON logs from a directory and runs the full rule-engine
set over them, indexing alerts into OpenSearch. This is the offline
validation path -- the live path is log_shipper.py -> Redpanda ->
streaming_engine.py, and the upload path is src/api/. All three share the
SAME engines and the SAME record->flow mapping (src/flow_mapping.py), so
results are consistent regardless of which path ran.
"""
import json
import os
import sys
import asyncio
from redis import Redis

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
from src.storage.opensearch_client import OpenSearchStorage

try:
    from src.inference.model_server import HybridModelServer
except Exception as _exc:  # onnxruntime absent -- ML stays optional
    HybridModelServer = None
    print(f"[offline_engine] ML scoring disabled: {_exc}")

# Which engines run over which log type -- kept identical to the upload
# path's dispatch table in src/api/pcap_analysis.py.
CONN_ENGINES = ("eng01", "eng02", "eng05", "eng06", "eng13")
LOG_TYPE_ENGINES = {
    "conn": CONN_ENGINES,
    "dns": ("eng03",),
    "ssl": ("eng04",),
    "modbus": ("eng07",),
    "http": ("eng09",),
    "kerberos": ("eng11",),
}


async def process_static_log(filepath: str, engines_map: dict, storage: OpenSearchStorage, log_type: str) -> int:
    if not os.path.exists(filepath):
        return 0

    print(f"[*] Processing {filepath}...")
    fired = 0
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            flow = map_record(rec, log_type)
            for eng_name in LOG_TYPE_ENGINES.get(log_type, ()):
                alert = await engines_map[eng_name].score(flow)
                if alert:
                    storage.index_alert(alert)
                    fired += 1
    return fired


def process_notice_log(filepath: str, storage: OpenSearchStorage) -> int:
    """BZAR (ENG-12) operates on the whole notice.log at once."""
    if not os.path.exists(filepath):
        return 0
    records = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    alerts = parse_bzar_notices(records)
    for alert_dict in alerts:
        # parse_bzar_notices returns dicts, not Alert objects
        storage.client.index(index=storage.index_name, body=alert_dict, id=alert_dict["alert_id"])
    return len(alerts)


async def run_pipeline():
    print("[*] Starting StealthTap batch IT/OT pipeline...")
    storage = OpenSearchStorage()

    redis_client = Redis(
        host=os.environ.get("REDIS_HOST", "localhost"),
        port=int(os.environ.get("REDIS_PORT", "6379")),
        decode_responses=True,
    )

    model_server = HybridModelServer() if HybridModelServer is not None else None

    engines = {
        "eng01": VolumetricDDoSDetector(redis_client=redis_client),
        "eng02": C2BeaconingDetector(redis_client=redis_client),
        "eng03": DGADetector(model_server=model_server),
        "eng04": EncryptedMalwareDetector(),
        "eng05": ReconDetector(),
        "eng06": ExfiltrationDetector(redis_client=redis_client),
        "eng07": OTIndustrialAnomalyDetector(),
        "eng09": HTTPThreatDetector(),
        "eng11": KerberosAttackDetector(),
        "eng13": BruteForceDetector(redis_client=redis_client),
    }

    log_dir = os.environ.get("ZEEK_LOG_DIR", "logs/pcap_run")

    total = 0
    for log_type in ("conn", "dns", "ssl", "modbus", "http", "kerberos"):
        total += await process_static_log(f"{log_dir}/{log_type}.log", engines, storage, log_type)
    total += process_notice_log(f"{log_dir}/notice.log", storage)

    print(f"[+] Batch IT/OT analysis complete. {total} alerts indexed. "
          f"Check OpenSearch Dashboards at http://localhost:5601")


if __name__ == "__main__":
    asyncio.run(run_pipeline())
