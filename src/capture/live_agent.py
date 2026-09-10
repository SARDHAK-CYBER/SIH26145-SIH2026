"""
LiveAgent -- one interface's live capture wired to the StealthTap engines.

    capture backend (kernel driver: AF_PACKET ring / Npcap ring, in-kernel BPF)
        |  arrival-stamped packets
        v
    bounded queue  (drops OLDEST on overflow -> bounded latency, `dropped` counter)
        v
    asyncio worker
        |-- FlowAssembler : conn/dns/ssl/modbus/dnp3 records, real JA4
        |-- every SNAPSHOT_INTERVAL s: re-score every active flow (near-real-time
        |                              DDoS/recon/exfil, not "wait for idle")
        |-- ENG01..13 (rule) + ENG03 hybrid ML (dns)
        |-- per-(class,src,dst) cooldown de-dupe
        +-- alert fan-out: callbacks / SSE / stdout / (sensor) Postgres

Telemetry surfaced in status(): pps, Mbit/s, peak, kernel recv/drop
(the "can't keep up" ground truth), active flows, queue depth, per-alert
detection latency p50/p95/p99/max, and a high_speed flag.

CLI:
    python -m src.capture.live_agent list
    python -m src.capture.live_agent caps
    python -m src.capture.live_agent run   --iface "Wi-Fi" --bpf "ip" --json
    python -m src.capture.live_agent run   --pcap capture.pcap                 # replay through the LIVE pipeline
    python -m src.capture.live_agent serve --port 8100                         # REST + SSE for the dashboard
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import queue
import sys
import threading
import time
from collections import deque
from typing import Callable, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.capture.backends import select_backend, capabilities, CaptureError
from src.capture.flow_assembler import FlowAssembler
from src.capture.interfaces import list_interfaces, resolve_capture_name
from src.flow_mapping import map_record

try:
    from src.inference.model_server import HybridModelServer, MIN_ML_CONFIDENCE
    from src.inference.ml_alerts import build_ml_alert
    _ML_OK = True
except Exception as _exc:  # onnxruntime missing etc.
    _ML_OK = False
    MIN_ML_CONFIDENCE = 0.6

AlertCB = Callable[[dict], None]

SNAPSHOT_INTERVAL_S = float(os.environ.get("LIVE_SNAPSHOT_INTERVAL", "2.0"))
ALERT_COOLDOWN_S = float(os.environ.get("LIVE_ALERT_COOLDOWN", "30.0"))
HIGHSPEED_PPS = float(os.environ.get("LIVE_HIGHSPEED_PPS", "50000"))
HIGHSPEED_MBPS = float(os.environ.get("LIVE_HIGHSPEED_MBPS", "200"))

# log_type -> engine keys (mirrors src/api/pcap_analysis.py). For `conn`
# the engine set depends on the phase: a mid-flight SNAPSHOT feeds only
# the rate/fan-out engines that genuinely benefit from an incremental
# view; the per-flow byte-ratio (ENG-06) and cross-flow periodicity
# (ENG-02) run when the flow is COMPLETE (expire), so a half-finished
# TLS handshake snapshot can't false-positive as exfiltration.
_DISPATCH_IMMEDIATE = {
    "dns": ("eng03",), "ssl": ("eng04",),
    "modbus": ("eng07",), "dnp3": ("eng07",),
    "http": ("eng09",), "kerberos": ("eng11",),
}
_DISPATCH_CONN_SNAPSHOT = ("eng01", "eng05", "eng13")
_DISPATCH_CONN_EXPIRE = ("eng01", "eng02", "eng05", "eng06", "eng13")
_IMMEDIATE = set(_DISPATCH_IMMEDIATE)   # latency measurable end-to-end


class _RateMonitor:
    def __init__(self):
        self.t = time.monotonic()
        self.pkts = 0
        self.bytes = 0
        self.kdrop = 0
        self.peak_pps = 0.0
        self.peak_mbps = 0.0
        self.pps = 0.0
        self.mbps = 0.0
        self.drop_delta = 0

    def sample(self, pkts: int, byts: int, kstats: Optional[dict]) -> dict:
        now = time.monotonic()
        dt = max(now - self.t, 1e-6)
        self.pps = (pkts - self.pkts) / dt
        self.mbps = ((byts - self.bytes) * 8) / dt / 1e6
        self.peak_pps = max(self.peak_pps, self.pps)
        self.peak_mbps = max(self.peak_mbps, self.mbps)
        self.drop_delta = 0
        if kstats is not None:
            self.drop_delta = max(0, kstats["drop"] - self.kdrop)
            self.kdrop = kstats["drop"]
        self.t, self.pkts, self.bytes = now, pkts, byts
        flags = []
        if self.pps >= HIGHSPEED_PPS:
            flags.append(f"pps>={HIGHSPEED_PPS:g}")
        if self.mbps >= HIGHSPEED_MBPS:
            flags.append(f"mbit/s>={HIGHSPEED_MBPS:g}")
        if self.drop_delta > 0:
            flags.append(f"KERNEL DROPPING (+{self.drop_delta})")
        return {"pps": round(self.pps, 1), "mbps": round(self.mbps, 3),
                "peak_pps": round(self.peak_pps, 1), "peak_mbps": round(self.peak_mbps, 3),
                "kernel_drop_total": self.kdrop, "kernel_drop_delta": self.drop_delta,
                "high_speed": bool(flags), "high_speed_flags": flags}


def _pctl(sorted_vals, q):
    if not sorted_vals:
        return None
    i = min(len(sorted_vals) - 1, int(q * len(sorted_vals)))
    return round(sorted_vals[i], 2)


class LiveAgent:
    def __init__(self, iface: str, bpf: Optional[str] = None, *,
                 prefer_kernel: bool = True, buffer_mb: int = 64, promisc: bool = True,
                 queue_size: int = 200_000, alert_sink: Optional[AlertCB] = None,
                 cooldown_s: float = ALERT_COOLDOWN_S):
        self.iface_req = iface
        self.iface = resolve_capture_name(iface)
        self.bpf = bpf
        self.prefer_kernel = prefer_kernel
        self.buffer_mb = buffer_mb
        self.promisc = promisc
        self.cooldown_s = cooldown_s
        self._q: "queue.Queue" = queue.Queue(maxsize=queue_size)
        self._assembler = FlowAssembler()
        self._sinks: list[AlertCB] = [alert_sink] if alert_sink else []
        self._recent = deque(maxlen=1000)
        self._subs: list[asyncio.Queue] = []
        self._latencies_ms: deque = deque(maxlen=2000)
        self._cooldown: dict[tuple, float] = {}
        self._rate = _RateMonitor()
        self._rate_view: dict = {}
        self._bytes = 0
        self._backend = None
        self._loop_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = threading.Event()
        self._started_at = 0.0
        self.stats = {"dropped": 0, "alerts": 0, "backend": None, "kernel_level": False,
                      "kernel_buffer_set": None}
        self._engines = None
        self._model_server = None

    # ---------------- engine wiring ----------------
    def _build_engines(self):
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
        from src.engines.eng13_bruteforce import BruteForceDetector

        try:
            r = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
                               socket_connect_timeout=1, socket_timeout=1)
            r.ping()
        except Exception:
            r = None  # engines fail open; LiveAgent's own cooldown de-dupes

        if _ML_OK:
            try:
                self._model_server = HybridModelServer()
            except Exception as exc:
                print(f"[live_agent] ML disabled: {exc}")
                self._model_server = None

        self._engines = {
            "eng01": VolumetricDDoSDetector(redis_client=r),
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

    # ---------------- lifecycle ----------------
    def _on_packet(self, pkt) -> None:
        t_arr = time.monotonic()
        try:
            wire = len(pkt)
        except Exception:
            wire = 0
        self._bytes += wire
        try:
            self._q.put_nowait((t_arr, pkt))
        except queue.Full:
            # bounded latency: drop the OLDEST, enqueue the newest
            try:
                self._q.get_nowait()
                self._q.put_nowait((t_arr, pkt))
            except queue.Empty:
                pass
            self.stats["dropped"] += 1

    def start(self, backend_factory=None) -> None:
        if self._running.is_set():
            return
        self._build_engines()
        self._running.set()
        self._started_at = time.time()

        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True, name="live-detect")
        self._loop_thread.start()

        factory = backend_factory or select_backend
        self._backend = factory(self.iface, self._on_packet, self.bpf,
                                self.prefer_kernel, self.buffer_mb, self.promisc)
        self.stats["backend"] = self._backend.name
        self.stats["kernel_level"] = self._backend.kernel_level
        self._backend.start()
        self.stats["kernel_buffer_set"] = getattr(self._backend, "kernel_buffer_set", None)
        print(f"[live_agent] capturing on {self.iface_req!r} via {self._backend.name} "
              f"(kernel_level={self._backend.kernel_level}, buffer={self.buffer_mb}MiB)")

    def replay_pcap(self, path: str, realtime: bool = False) -> None:
        """Drive the SAME live pipeline from a pcap file -- for demos/CI
        where kernel capture isn't available."""
        from scapy.all import PcapReader
        if not self._running.is_set():
            self._build_engines()
            self._running.set()
            self._started_at = time.time()
            self.stats["backend"] = "pcap-replay"
            self._loop_thread = threading.Thread(target=self._run_loop, daemon=True, name="live-detect")
            self._loop_thread.start()
        last = None
        with PcapReader(path) as rd:
            for pkt in rd:
                if realtime and last is not None:
                    dt = float(getattr(pkt, "time", 0)) - last
                    if 0 < dt < 5:
                        time.sleep(dt)
                last = float(getattr(pkt, "time", 0)) or last
                self._on_packet(pkt)
        for _ in range(50):
            if self._q.qsize() == 0:
                break
            time.sleep(0.1)

    def stop(self) -> None:
        self._running.clear()
        if self._backend is not None:
            self._backend.stop()
        if self._loop is not None:
            self._loop.call_soon_threadsafe(lambda: None)
        if self._loop_thread is not None:
            self._loop_thread.join(timeout=5)

    # ---------------- detection loop ----------------
    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._consume())

    _DRAIN_BATCH = 512   # packets pulled per loop pass before checking the cadence

    async def _consume(self) -> None:
        loop = asyncio.get_event_loop()
        last_tick = time.monotonic()
        while self._running.is_set():
            drained = 0
            while drained < self._DRAIN_BATCH:
                try:
                    item = self._q.get_nowait()
                except queue.Empty:
                    break
                drained += 1
                t_arr, pkt = item
                for log_type, rec in self._assembler.process(pkt):
                    await self._score_immediate(log_type, rec, t_arr)
            if drained == 0:
                try:
                    item = await loop.run_in_executor(None, self._q.get, True, 0.3)
                    t_arr, pkt = item
                    for log_type, rec in self._assembler.process(pkt):
                        await self._score_immediate(log_type, rec, t_arr)
                except queue.Empty:
                    pass

            now = time.monotonic()
            if now - last_tick >= SNAPSHOT_INTERVAL_S:
                last_tick = now
                for _lt, rec in self._assembler.snapshot():
                    await self._score_conn(rec, _DISPATCH_CONN_SNAPSHOT)
                expired = [r for lt, r in self._assembler.expire() if lt == "conn"]
                for rec in expired:
                    await self._score_conn(rec, _DISPATCH_CONN_EXPIRE)
                await self._ml_batch_conn(expired)
                kstats = self._backend.kernel_stats() if hasattr(self._backend, "kernel_stats") else None
                self._rate_view = self._rate.sample(self._assembler.stats["packets"], self._bytes, kstats)

        for _lt, rec in self._assembler.flush():
            await self._score_conn(rec, _DISPATCH_CONN_EXPIRE)

    async def _score_immediate(self, log_type: str, rec: dict, t_arr: Optional[float]) -> None:
        engines = _DISPATCH_IMMEDIATE.get(log_type)
        if not engines:
            return
        flow = map_record(rec, log_type)
        for name in engines:
            eng = self._engines.get(name)
            if eng is None:
                continue
            try:
                alert = await eng.score(flow)
            except Exception:
                continue
            if alert is not None:
                self._emit(alert.model_dump(mode="json"), t_arr)
        if _ML_OK and self._model_server is not None:
            fam = {"ssl": "tls", "modbus": "modbus"}.get(log_type)
            if fam:
                try:
                    res = self._model_server.score_flow(flow, fam)
                except Exception:
                    res = None
                if res:
                    m = build_ml_alert(flow, fam, res, min_confidence=MIN_ML_CONFIDENCE)
                    if m:
                        self._emit(m.model_dump(mode="json"), t_arr)

    async def _score_conn(self, rec: dict, engine_keys: tuple) -> None:
        flow = map_record(rec, "conn")
        for name in engine_keys:
            eng = self._engines.get(name)
            if eng is None:
                continue
            try:
                alert = await eng.score(flow)
            except Exception:
                continue
            if alert is not None:
                self._emit(alert.model_dump(mode="json"), None)

    async def _ml_batch_conn(self, conn_recs: list[dict]) -> None:
        """One batched ONNX call for the `flow` family over all conn flows
        that just expired -- never per-flow, so a flow-heavy capture stays
        cheap."""
        if not (conn_recs and _ML_OK and self._model_server is not None):
            return
        flows = [map_record(r, "conn") for r in conn_recs]
        try:
            results = self._model_server.score_flows_batch(flows, "flow")
        except Exception:
            return
        for fl, res in zip(flows, results):
            if not res:
                continue
            m = build_ml_alert(fl, "flow", res, min_confidence=MIN_ML_CONFIDENCE)
            if m:
                self._emit(m.model_dump(mode="json"), None)

    # evidence fields (in priority order) that make two same-class alerts
    # genuinely distinct -- so 13 different DGA domains -> 13 alerts, but
    # 39 identical C2 beacons -> 1.
    _DISCRIMINATORS = ("dns_query", "ja4_fingerprint", "function_code", "uri",
                       "krb_service", "bzar_note")

    def _emit(self, alert: dict, t_arr: Optional[float]) -> None:
        fi = alert.get("flow_identifier", {})
        ev = alert.get("evidence", {}) or {}
        disc = next((str(ev[k]) for k in self._DISCRIMINATORS if ev.get(k)), None)
        key = (alert["threat_class"], fi.get("src_ip"), fi.get("dst_ip"), disc)
        now = time.monotonic()
        if now - self._cooldown.get(key, 0.0) < self.cooldown_s:
            return
        self._cooldown[key] = now

        if t_arr is not None:
            lat_ms = (now - t_arr) * 1000.0
            self._latencies_ms.append(lat_ms)
            alert.setdefault("evidence", {})["detection_latency_ms"] = round(lat_ms, 2)

        self.stats["alerts"] += 1
        self._recent.append(alert)
        for sink in self._sinks:
            try:
                sink(alert)
            except Exception:
                pass
        for sub in list(self._subs):
            try:
                sub.put_nowait(alert)
            except Exception:
                pass

    # ---------------- introspection ----------------
    def latency_summary(self) -> dict:
        s = sorted(self._latencies_ms)
        return {"samples": len(s), "p50_ms": _pctl(s, 0.50), "p95_ms": _pctl(s, 0.95),
                "p99_ms": _pctl(s, 0.99), "max_ms": round(s[-1], 2) if s else None}

    def status(self) -> dict:
        return {
            "running": self._running.is_set(),
            "interface": self.iface_req,
            "capture_name": self.iface,
            "bpf": self.bpf,
            "buffer_mb": self.buffer_mb,
            "promisc": self.promisc,
            "uptime_s": round(time.time() - self._started_at, 1) if self._started_at else 0,
            "queue_depth": self._q.qsize(),
            "active_flows": self._assembler.active_flows(),
            "throughput": self._rate_view or {},
            "detection_latency": self.latency_summary(),
            "assembler": self._assembler.stats,
            "ml_families": (self._model_server.loaded_families() if self._model_server else []),
            "snapshot_interval_s": SNAPSHOT_INTERVAL_S,
            **self.stats,
        }

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        return list(self._recent)[-limit:]

    def add_sink(self, sink: AlertCB) -> None:
        self._sinks.append(sink)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        self._subs.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subs:
            self._subs.remove(q)


# ============================ CLI ============================
def _cmd_list(a):
    print(json.dumps([r.as_dict() for r in list_interfaces(include_down=True, include_loopback=a.all)], indent=2))


def _cmd_caps(_a):
    print(json.dumps(capabilities(), indent=2))


def _pretty(a: dict) -> None:
    fi = a.get("flow_identifier", {})
    lat = a.get("evidence", {}).get("detection_latency_ms")
    print(f"  [{a['severity']:8s}] {a['threat_class']:26s} "
          f"{fi.get('src_ip')}:{fi.get('src_port')} -> {fi.get('dst_ip')}:{fi.get('dst_port')} "
          f"conf={a['confidence_score']} {a.get('detection_mode')}"
          + (f" lat={lat}ms" if lat is not None else ""))


def _cmd_run(a):
    agent = LiveAgent(a.iface or "pcap-replay", a.bpf, prefer_kernel=not a.no_kernel,
                      buffer_mb=a.buffer_mb, promisc=not a.no_promisc,
                      alert_sink=(lambda x: print(json.dumps(x))) if a.json else _pretty)
    # headless sensor mode: also POST alerts to the shared API/DB when configured
    from src.capture.forwarder import make_forwarder
    _fwd = make_forwarder()
    if _fwd:
        agent.add_sink(_fwd)
        print(f"[live_agent] forwarding alerts to {_fwd.endpoint}", file=sys.stderr)
    if a.pcap:
        agent.replay_pcap(a.pcap, realtime=a.realtime)
        time.sleep(0.5)
        print(json.dumps(agent.status(), indent=2), file=sys.stderr)
        agent.stop()
        return
    try:
        agent.start()
    except CaptureError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    try:
        while True:
            time.sleep(a.status_every)
            s = agent.status()
            tp = s.get("throughput", {})
            print(f"[{time.strftime('%H:%M:%S')}] "
                  f"{tp.get('pps', 0):.0f} pps  {tp.get('mbps', 0):.2f} Mbit/s  "
                  f"flows={s['active_flows']} q={s['queue_depth']} "
                  f"kdrop={tp.get('kernel_drop_total', 'n/a')} udrop={s['dropped']} "
                  f"alerts={s['alerts']} "
                  f"lat_p95={s['detection_latency'].get('p95_ms')}ms", file=sys.stderr)
            if tp.get("high_speed"):
                print(f"    >> HIGH-SPEED STREAM: {', '.join(tp['high_speed_flags'])}", file=sys.stderr)
    except KeyboardInterrupt:
        agent.stop()
        print(json.dumps(agent.status(), indent=2), file=sys.stderr)


def _cmd_serve(a):
    try:
        import uvicorn
        from src.api.live_capture import build_app
    except Exception as exc:
        print(f"ERROR: serve needs fastapi+uvicorn ({exc})", file=sys.stderr)
        sys.exit(2)
    # Pre-warm scapy at startup so the first /capture/start isn't the one
    # that pays the (occasionally slow, on some Windows hosts) first-import
    # cost inside a request handler.
    try:
        os.environ.setdefault("SCAPY_USE_PCAPDNET", "1")
        from scapy.config import conf as _c
        _c.use_pcap = True
        _c.manufdb = None
        import scapy.sendrecv  # noqa: F401
        print("[live_agent] scapy pre-warmed")
    except Exception as exc:
        print(f"[live_agent] scapy pre-warm skipped: {exc}")
    uvicorn.run(build_app(), host=a.host, port=a.port, log_level="info")


def main() -> None:
    p = argparse.ArgumentParser(prog="live_agent", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="enumerate capturable interfaces (JSON)")
    pl.add_argument("--all", action="store_true")
    pl.set_defaults(func=_cmd_list)

    sub.add_parser("caps", help="report capture capabilities of this host").set_defaults(func=_cmd_caps)

    pr = sub.add_parser("run", help="capture+analyse an interface (or replay a pcap)")
    pr.add_argument("--iface", default=None)
    pr.add_argument("--pcap", default=None, help="replay this pcap through the LIVE pipeline")
    pr.add_argument("--realtime", action="store_true")
    pr.add_argument("--bpf", default="ip or ip6")
    pr.add_argument("--buffer-mb", type=int, default=64)
    pr.add_argument("--no-promisc", action="store_true")
    pr.add_argument("--no-kernel", action="store_true", help="force scapy L3 fallback (debug)")
    pr.add_argument("--json", action="store_true")
    pr.add_argument("--status-every", type=float, default=5.0)
    pr.set_defaults(func=_cmd_run)

    ps = sub.add_parser("serve", help="REST+SSE control server for the dashboard")
    ps.add_argument("--host", default="127.0.0.1")
    ps.add_argument("--port", type=int, default=8100)
    ps.set_defaults(func=_cmd_serve)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
