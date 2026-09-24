"""
ScoringEngine -- builds the engine set (ENG01..13 + ML model server + live
baseline) and scores assembled records against them.

Extracted from LiveAgent so the EXACT same detection logic can run either
in-process (single core, num_workers=1, the original behaviour) or inside
a worker process spawned by src/capture/engine_pool.py (multi-core mode)
-- one code path, so multi-core mode can never silently diverge from the
validated single-process detection logic.

Builds nothing until asked to (no Redis connection, no ONNX session) so
constructing one of these inside a freshly-spawned worker process (Windows
`spawn`, no inherited file descriptors/sockets) is safe -- everything
unpicklable is created AFTER the process starts, never passed across the
process boundary.
"""
from __future__ import annotations

import os
from typing import Optional

from src.flow_mapping import map_record

try:
    from src.inference.model_server import HybridModelServer, MIN_ML_CONFIDENCE
    from src.inference.ml_alerts import build_ml_alert
    from src.inference.fusion import standalone_threshold
    _ML_OK = True
except Exception:
    _ML_OK = False
    MIN_ML_CONFIDENCE = 0.6

# log_type -> engine keys (mirrors src/api/pcap_analysis.py). For `conn`
# the engine set depends on the phase: a mid-flight SNAPSHOT feeds only
# the rate/fan-out engines that genuinely benefit from an incremental
# view; the per-flow byte-ratio (ENG-06) and cross-flow periodicity
# (ENG-02) run when the flow is COMPLETE (expire), so a half-finished
# TLS handshake snapshot can't false-positive as exfiltration.
DISPATCH_IMMEDIATE = {
    "dns": ("eng03",), "ssl": ("eng04",),
    "modbus": ("eng07",), "dnp3": ("eng07",),
    "http": ("eng09",), "kerberos": ("eng11",),
}
IMMEDIATE_ML_FAMILY = {"ssl": "tls", "modbus": "modbus"}
DISPATCH_CONN_SNAPSHOT = ("eng01", "eng05", "eng13")
DISPATCH_CONN_EXPIRE = ("eng01", "eng02", "eng05", "eng06", "eng13")


def make_redis_client(explicit_only: bool = False):
    """Real Redis if reachable, else the in-process MemoryStore fallback
    (same pattern as Zeek/native-module fallbacks elsewhere in this repo).

    explicit_only=True (the default single-process live-capture path)
    does not probe localhost:6379 at all unless the user explicitly set
    REDIS_URL -- measured directly (scripts/bench_throughput.py,
    samples/netbios_ssn2.pcap): single-process ENG01/02/06/13 scoring
    against real Redis on this dev machine hits ~1,580 pps; the
    identical pipeline against MemoryStore hits ~4,766 pps. Live
    capture's stateful-engine data (flood counters, beacon windows,
    10-300s TTLs) is inherently session-scoped, so MemoryStore's lack of
    cross-restart persistence costs nothing real for the default
    single-process deployment -- Redis stays available on request
    (REDIS_URL set) for observability, or unconditionally for
    multi-worker mode (explicit_only=False), which genuinely needs a
    store shared across processes to stay correct."""
    from redis import Redis
    from src.memstore import MemoryStore

    if explicit_only and not os.environ.get("REDIS_URL"):
        return MemoryStore(), False

    try:
        r = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
                           socket_connect_timeout=1, socket_timeout=1)
        r.ping()
        return r, True
    except Exception:
        return MemoryStore(), False


class ScoringEngine:
    """One full detection stack: ENG01..13 + hybrid ML + live baseline.
    Stateful (per-source dedup windows, Redis/MemoryStore handles, ONNX
    session) -- one instance per process (main process for num_workers=1,
    one per worker process for num_workers>1)."""

    def __init__(self, worker_id: Optional[int] = None):
        self.worker_id = worker_id
        self.redis_is_shared = False
        self._model_server = None
        self._baseline = None
        self._engines: dict = {}
        self._build()

    def _build(self) -> None:
        from src.engines.eng01_ddos import VolumetricDDoSDetector
        from src.engines.eng02_c2_beaconing import C2BeaconingDetector
        from src.engines.eng03_dga_dns import DGADetector
        from src.engines.eng04_encrypted_malware import EncryptedMalwareDetector
        from src.engines.eng05_recon import ReconDetector
        from src.engines.eng06_exfiltration import ExfiltrationDetector
        from src.engines.eng07_ot_anomaly import OTIndustrialAnomalyDetector
        from src.engines.eng09_http_threats import HTTPThreatDetector
        from src.engines.eng11_kerberos import KerberosAttackDetector
        from src.engines.eng13_bruteforce import BruteForceDetector

        tag = f"[live_agent worker={self.worker_id}]" if self.worker_id is not None else "[live_agent]"
        # Single-process (worker_id is None): prefer the faster MemoryStore
        # unless the user explicitly opted into Redis (REDIS_URL set).
        # Pool workers (worker_id is not None): always try real Redis --
        # multi-worker mode needs the cross-process shared store to stay
        # correct, and LiveAgent._build_engines() already verified one is
        # reachable before starting the pool at all.
        r, self.redis_is_shared = make_redis_client(explicit_only=self.worker_id is None)
        if not self.redis_is_shared:
            if self.worker_id is None and not os.environ.get("REDIS_URL"):
                reason = "not requested -- set REDIS_URL to opt in"
            else:
                reason = "unreachable"
            print(f"{tag} using the in-process state store (Redis {reason})")

        if self.worker_id is not None:
            # Cap each worker's ONNX thread pool so N processes don't each
            # try to claim every core -- see model_server._session_options.
            import multiprocessing as _mp
            cores = _mp.cpu_count() or 4
            num_workers = int(os.environ.get("LIVE_ENGINE_WORKERS", "1")) or 1
            os.environ["STEALTHTAP_ONNX_INTRA_THREADS"] = str(max(1, cores // max(1, num_workers)))

        if _ML_OK:
            try:
                # Real-time hot path: an untrusted IsolationForest (see
                # IFOREST_MIN_F1) never affects a live alert, so skip
                # running it -- see FamilyModels.skip_untrusted_iforest
                # for the measured per-row cost this avoids.
                self._model_server = HybridModelServer(skip_untrusted_iforest=True)
            except Exception as exc:
                print(f"{tag} ML disabled: {exc}")
                self._model_server = None

        # Live-learning per-network baseline (no pre-trained data): learns this
        # network's normal flows first, then alerts on conformal outliers.
        from src.inference.online_baseline import OnlineBaseline
        self._baseline = OnlineBaseline(
            learn_min_flows=int(os.environ.get("LIVE_BASELINE_MIN_FLOWS", "1500")),
            learn_min_seconds=float(os.environ.get("LIVE_BASELINE_MIN_SECONDS", "600")),
            alpha=float(os.environ.get("LIVE_BASELINE_ALPHA", "0.001")),
            one_way=os.environ.get("LIVE_ONE_WAY", "0") == "1",
        )

        self._engines = {
            # allow_native=False in pool-worker mode: see the comment in
            # VolumetricDDoSDetector.__init__ -- its native path can't see
            # cross-worker fan-in for the dst_ip-keyed spoofed-flood check.
            "eng01": VolumetricDDoSDetector(redis_client=r, allow_native=self.worker_id is None),
            "eng02": C2BeaconingDetector(redis_client=r),
            "eng03": DGADetector(model_server=self._model_server),
            "eng04": EncryptedMalwareDetector(),
            "eng05": ReconDetector(),
            "eng06": ExfiltrationDetector(redis_client=r),
            "eng07": OTIndustrialAnomalyDetector(),
            "eng09": HTTPThreatDetector(),
            "eng11": KerberosAttackDetector(),
            "eng13": BruteForceDetector(redis_client=r),
        }

    def loaded_ml_families(self) -> list:
        return self._model_server.loaded_families() if self._model_server else []

    def baseline_status(self) -> Optional[dict]:
        return self._baseline.status() if self._baseline is not None else None

    def ml_family_for(self, log_type: str) -> Optional[str]:
        return IMMEDIATE_ML_FAMILY.get(log_type)

    async def score_immediate_rules(self, log_type: str, rec: dict) -> tuple[dict, list[dict]]:
        """Runs the cheap, non-ML rule engines for one immediate record.
        Returns (flow, alerts) -- the mapped flow is handed back so the
        caller can buffer it for BATCHED ML scoring (ml_batch_immediate)
        without re-mapping the same record twice."""
        flow = map_record(rec, log_type)
        out: list[dict] = []
        engines = DISPATCH_IMMEDIATE.get(log_type)
        if engines:
            for name in engines:
                eng = self._engines.get(name)
                if eng is None:
                    continue
                try:
                    alert = await eng.score(flow)
                except Exception:
                    continue
                if alert is not None:
                    out.append(alert.model_dump(mode="json"))
        return flow, out

    async def ml_batch_immediate(self, family: str, flows: list[dict]) -> list[Optional[dict]]:
        """Batched equivalent of scoring one ssl/modbus flow's ML family
        at a time -- ONE ONNX call for the whole buffer instead of one
        per record. Same pattern as ml_batch_conn below; model_server.py's
        own docstring already measured a 10.3x speedup from exactly this
        change (a 39,969-record Modbus capture: 30-40s unbatched). Before
        this, DNS/SSL/Modbus records hit score_flow() one at a time in
        the immediate-dispatch path -- ml_batch_conn's batching never
        covered them.

        Returns one entry per input flow, in order (None where nothing
        fired), so the caller can zip it against its own per-record
        bookkeeping (e.g. detection-latency t_arr) -- unlike ml_batch_conn,
        which doesn't need that since conn-expire alerts were never
        latency-tracked to begin with."""
        out: list[Optional[dict]] = [None] * len(flows)
        if not (flows and _ML_OK and self._model_server is not None):
            return out
        try:
            results = self._model_server.score_flows_batch(flows, family)
        except Exception:
            return out
        for i, (fl, res) in enumerate(zip(flows, results)):
            if not res:
                continue
            m = build_ml_alert(fl, family, res, min_confidence=standalone_threshold(family))
            if m:
                out[i] = m.model_dump(mode="json")
        return out

    async def score_conn(self, rec: dict, engine_keys: tuple) -> list[dict]:
        flow = map_record(rec, "conn")
        out: list[dict] = []
        for name in engine_keys:
            eng = self._engines.get(name)
            if eng is None:
                continue
            try:
                alert = await eng.score(flow)
            except Exception:
                continue
            if alert is not None:
                out.append(alert.model_dump(mode="json"))
        return out

    async def ml_batch_conn(self, conn_recs: list[dict]) -> list[dict]:
        """One batched ONNX call for the `flow` family over all conn flows
        that just expired -- never per-flow, so a flow-heavy capture stays
        cheap."""
        out: list[dict] = []
        if not (conn_recs and _ML_OK and self._model_server is not None):
            return out
        flows = [map_record(r, "conn") for r in conn_recs]
        try:
            results = self._model_server.score_flows_batch(flows, "flow")
        except Exception:
            return out
        for fl, res in zip(flows, results):
            if not res:
                continue
            # the flow model is a DDoS-shape detector: it may alert alone only
            # at very high confidence (src/inference/fusion.py)
            m = build_ml_alert(fl, "flow", res, min_confidence=standalone_threshold("flow"))
            if m:
                out.append(m.model_dump(mode="json"))
        return out

    def observe_baseline(self, rec: dict) -> Optional[dict]:
        if self._baseline is None:
            return None
        try:
            b_alert = self._baseline.observe(rec)
        except Exception:
            return None
        return b_alert.model_dump(mode="json") if b_alert is not None else None
