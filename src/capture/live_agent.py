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

try:
    # Native Rust flow assembler (native/stealthtap_core) -- byte-for-byte
    # validated against FlowAssembler on real captures via
    # scripts/validate_native_live_assembler.py (see native/README.md).
    # Same call-site interface (process/snapshot/expire/flush/.stats), so
    # nothing below this needs to know which one is in use.
    from src.capture.native_flow_assembler import NativeFlowAssemblerAdapter, NATIVE_LIVE_ASSEMBLER_AVAILABLE, RawFrame
except ImportError:
    NATIVE_LIVE_ASSEMBLER_AVAILABLE = False
    NativeFlowAssemblerAdapter = None  # type: ignore[assignment,misc]
    RawFrame = None  # type: ignore[assignment,misc]

_FORCE_PYTHON_LIVE_ASSEMBLER = os.environ.get("STEALTHTAP_FORCE_PYTHON_LIVE_ASSEMBLER") == "1"

try:
    # Whole-hot-path native capture (libpcap/Npcap read loop + flow assembly +
    # host inventory + packet ring, all in one GIL-free Rust thread) -- see
    # native/stealthtap_core/src/capture.rs. Python only sees batched records.
    from stealthtap_core import NativeCapture, PcapIndex  # noqa: F401
    NATIVE_CAPTURE_AVAILABLE = True
except ImportError:
    NativeCapture = None  # type: ignore[assignment,misc]
    PcapIndex = None  # type: ignore[assignment,misc]
    NATIVE_CAPTURE_AVAILABLE = False
_FORCE_PYTHON_CAPTURE = os.environ.get("STEALTHTAP_CAPTURE", "").lower() in ("python", "scapy", "afxdp", "afpacket")

from src.capture.scoring import (
    ScoringEngine, DISPATCH_IMMEDIATE as _DISPATCH_IMMEDIATE,
    DISPATCH_CONN_SNAPSHOT as _DISPATCH_CONN_SNAPSHOT,
    DISPATCH_CONN_EXPIRE as _DISPATCH_CONN_EXPIRE,
)
from src.capture.engine_pool import EngineWorkerPool

AlertCB = Callable[[dict], None]

SNAPSHOT_INTERVAL_S = float(os.environ.get("LIVE_SNAPSHOT_INTERVAL", "2.0"))
ALERT_COOLDOWN_S = float(os.environ.get("LIVE_ALERT_COOLDOWN", "30.0"))
HIGHSPEED_PPS = float(os.environ.get("LIVE_HIGHSPEED_PPS", "50000"))
HIGHSPEED_MBPS = float(os.environ.get("LIVE_HIGHSPEED_MBPS", "200"))
DEFAULT_ENGINE_WORKERS = int(os.environ.get("LIVE_ENGINE_WORKERS", "1"))
BASELINE_SAMPLE_MAX = int(os.environ.get("LIVE_BASELINE_MAX_PER_TICK", "2000"))   # flows/tick fed to the online baseline
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


class _NativeAssembler:
    """FlowAssembler-shaped view over a NativeCapture, so the scoring loop and
    status() don't care which assembler sits behind them."""

    def __init__(self, cap):
        self.cap = cap

    def snapshot(self):
        return self.cap.snapshot(4000)

    def expire(self, now=None):
        return self.cap.expire(now)

    def flush(self):
        return self.cap.flush()

    def active_flows(self):
        return self.cap.active_flows()

    @property
    def stats(self):
        return self.cap.stats()


class _NativeBackendInfo:
    name = "native-pcap"
    kernel_level = True


def _pctl(sorted_vals, q):
    if not sorted_vals:
        return None
    i = min(len(sorted_vals) - 1, int(q * len(sorted_vals)))
    return round(sorted_vals[i], 2)


class LiveAgent:
    def __init__(self, iface: str, bpf: Optional[str] = None, *,
                 prefer_kernel: bool = True, buffer_mb: int = 64, promisc: bool = True,
                 queue_size: int = 200_000, alert_sink: Optional[AlertCB] = None,
                 cooldown_s: float = ALERT_COOLDOWN_S, num_workers: int = DEFAULT_ENGINE_WORKERS,
                 warm_start_pcap: Optional[str] = None):
        self.iface_req = iface
        self.iface = resolve_capture_name(iface)
        self.bpf = bpf
        # Optional: a short historical pcap of THIS network, parsed once at
        # start and fed to the online behavioural baseline (see
        # src/inference/online_baseline.py's warm_start) so a fresh
        # deployment doesn't sit in "learning" phase for a fixed ~10
        # minutes with no anomaly detection at all. Single-process
        # (num_workers==1) only -- see _build_engines.
        self.warm_start_pcap = warm_start_pcap
        self.prefer_kernel = prefer_kernel
        self.buffer_mb = buffer_mb
        self.promisc = promisc
        self.cooldown_s = cooldown_s
        self.num_workers_req = max(1, num_workers)
        self._q: "queue.Queue" = queue.Queue(maxsize=queue_size)
        if NATIVE_LIVE_ASSEMBLER_AVAILABLE and not _FORCE_PYTHON_LIVE_ASSEMBLER:
            self._assembler = NativeFlowAssemblerAdapter()
        else:
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
        self._scoring: Optional[ScoringEngine] = None   # num_workers == 1: in-process
        self._pool: Optional[EngineWorkerPool] = None    # num_workers  > 1: multi-core
        self._ml_buf: dict[str, list] = {}    # family -> [(flow, t_arr), ...], batched by _flush_ml_immediate
        self._ncap = None                     # NativeCapture when the native hot path is in use
        self._replay_source = False           # True while a pcap file (not a NIC) feeds the pipeline
        self._series: deque = deque(maxlen=1800)   # per-second telemetry for the dashboard (30 min)
        self._series_last = (time.monotonic(), 0, 0)
        self._class_counts: dict[str, int] = {}
        self._sev_counts: dict[str, int] = {}
        self._replay_done = False
        self._native_flow_engines = False     # ENG-01/02/05/06/13 evaluated in Rust (flow_engines.rs)

    # ---------------- engine wiring ----------------
    def _build_engines(self):
        """num_workers==1: one ScoringEngine in-process, identical to the
        original single-core behaviour. num_workers>1: a pool of worker
        PROCESSES, each with its own ScoringEngine, fed by _consume() below
        -- see src/capture/engine_pool.py for why this is correct (native
        assembly stays single-process; only assembled records get sharded,
        by source IP, which is what ENG-05's in-process state and Redis's
        cross-worker sharing both need).

        Multi-worker mode requires a REAL Redis (not the in-process
        MemoryStore fallback) for ENG-01/02/06/13 to stay correct across
        worker processes -- if none is reachable this downgrades to
        num_workers=1 rather than run with silently-inconsistent state."""
        if self.num_workers_req > 1:
            from src.capture.scoring import make_redis_client
            _, redis_shared = make_redis_client()
            if not redis_shared:
                print(f"[live_agent] num_workers={self.num_workers_req} requested but no Redis "
                      f"reachable -- downgrading to num_workers=1 (multi-core state would be "
                      f"per-process-inconsistent otherwise)")
                self.num_workers_req = 1

        if self.num_workers_req > 1:
            self._pool = EngineWorkerPool(self.num_workers_req)
            self._pool.start()
            print(f"[live_agent] engine pool started: {self.num_workers_req} worker processes")
            if self.warm_start_pcap:
                print("[live_agent] warm_start_pcap is not supported with num_workers>1 "
                      "(each pool worker learns its own baseline independently) -- ignored")
        else:
            self._scoring = ScoringEngine()
            if self.warm_start_pcap:
                self._warm_start_baseline_from_pcap(self.warm_start_pcap)

    def _warm_start_baseline_from_pcap(self, path: str) -> None:
        try:
            from pcap_parser import parse_pcap
            result = parse_pcap(path)
            conn_records = result.get("conn", [])
            self._scoring.warm_start_baseline(conn_records)
            status = self._scoring.baseline_status()
            print(f"[live_agent] baseline warm-started from {path!r}: "
                  f"{len(conn_records)} flows -> phase={status.get('phase') if status else '?'}")
        except Exception as exc:
            print(f"[live_agent] baseline warm-start from {path!r} failed (continuing without it): {exc}")

    # ---------------- lifecycle ----------------
    @property
    def raw_capable(self) -> bool:
        """True when the assembler consumes raw Ethernet frames directly (the
        native Rust one). Backends then skip scapy dissection entirely -- see
        RawFrame for the measured 41x ingestion difference."""
        return NativeFlowAssemblerAdapter is not None and isinstance(self._assembler, NativeFlowAssemblerAdapter)

    def on_raw(self, ts: float, raw: bytes) -> None:
        """Ingest one raw Ethernet frame. With the native assembler it goes
        straight through as a RawFrame; with the Python fallback it is
        dissected once here (that assembler needs a scapy Packet)."""
        if self.raw_capable:
            self._enqueue(RawFrame(ts, raw), len(raw))
            return
        from scapy.layers.l2 import Ether
        pkt = Ether(raw)
        pkt.time = ts
        self._on_packet(pkt)

    def _on_packet(self, pkt) -> None:
        try:
            wire = len(pkt)
        except Exception:
            wire = 0
        self._enqueue(pkt, wire)

    def _enqueue(self, item, wire: int) -> None:
        t_arr = time.monotonic()
        self._bytes += wire
        try:
            self._q.put_nowait((t_arr, item))
        except queue.Full:
            # bounded latency: drop the OLDEST, enqueue the newest
            try:
                self._q.get_nowait()
                self._q.put_nowait((t_arr, item))
            except queue.Empty:
                pass
            self.stats["dropped"] += 1

    def start(self, backend_factory=None) -> None:
        if self._running.is_set():
            return
        from src.perf import boost_process
        boost_process()
        if backend_factory is None and NATIVE_CAPTURE_AVAILABLE and not _FORCE_PYTHON_CAPTURE:
            try:
                self._start_native()
                return
            except CaptureError as exc:
                print(f"[live_agent] native capture unavailable ({exc}); falling back to the Python backend")
                self._ncap = None
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
        if self.raw_capable and os.environ.get("STEALTHTAP_FORCE_SCAPY_INGEST") != "1":
            # backends that support it deliver raw frames and skip scapy
            self._backend.raw_sink = self.on_raw
        self._backend.start()
        self.stats["kernel_buffer_set"] = getattr(self._backend, "kernel_buffer_set", None)
        print(f"[live_agent] capturing on {self.iface_req!r} via {self._backend.name} "
              f"(kernel_level={self._backend.kernel_level}, buffer={self.buffer_mb}MiB)")

    def _start_native(self, pcap: Optional[str] = None, realtime: bool = False, loops: int = 1,
                      speed: Optional[float] = None) -> None:
        """Native hot path. `pcap` replays a classic pcap file through the IDENTICAL code
        (NIC read loop -> assembler -> records); otherwise it captures self.iface."""
        ring = int(os.environ.get("STEALTHTAP_RING_PACKETS", "50000"))
        try:
            if pcap:
                cap = NativeCapture(pcap=pcap, loops=loops,
                                    speed=(speed if speed is not None else (1.0 if realtime else 0.0)),
                                    ring_packets=ring, idle_timeout_s=60.0)
            else:
                cap = NativeCapture(iface=self.iface, bpf=self.bpf, buffer_mb=self.buffer_mb,
                                    promisc=self.promisc, ring_packets=ring, idle_timeout_s=60.0)
            self._build_engines()
            cap.start()
        except OSError as exc:
            raise CaptureError(str(exc))
        self._ncap = cap
        self._assembler = _NativeAssembler(cap)
        if (self._scoring is not None and hasattr(cap, "enable_flow_engines")
                and os.environ.get("STEALTHTAP_PY_FLOW_ENGINES") != "1"):
            from src.engines.eng06_exfiltration import MIN_SINGLE_FLOW_BYTES
            cap.enable_flow_engines(float(MIN_SINGLE_FLOW_BYTES))
            self._native_flow_engines = True
        self._replay_source = bool(pcap)
        self._backend = _NativeBackendInfo()
        self.stats["backend"] = "native-pcap-replay" if pcap else "native-pcap"
        self.stats["kernel_level"] = not pcap
        self._running.set()
        self._started_at = time.time()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True, name="live-detect")
        self._loop_thread.start()
        print(f"[live_agent] {'replaying ' + pcap if pcap else 'capturing on ' + repr(self.iface_req)} "
              f"via native pcap engine (GIL-free capture+assembly thread)")

    def start_replay(self, path: str, loops: int = 1, speed: float = 0.0) -> None:
        """Non-blocking replay of a classic pcap through the live pipeline (loops=0: forever;
        speed=0: as fast as possible, 1.0: original timing). Native engine only."""
        if not NATIVE_CAPTURE_AVAILABLE:
            raise CaptureError("pcap replay needs the native module (stealthtap_core) -- build it with maturin")
        from src.perf import boost_process
        boost_process()
        self._start_native(pcap=path, loops=loops, speed=speed)

    def replay_pcap(self, path: str, realtime: bool = False, loops: int = 1, speed: Optional[float] = None) -> None:
        """Drive the SAME live pipeline from a pcap file -- for demos/CI
        where kernel capture isn't available."""
        if NATIVE_CAPTURE_AVAILABLE and not self._running.is_set() and self._ncap is None:
            try:
                self._start_native(pcap=path, realtime=realtime, loops=loops, speed=speed)
                if loops == 0:
                    return          # endless soak replay: the caller drives and stops it
                self._loop_thread.join()    # consumer exits once the file is exhausted AND dispatched
                return
            except CaptureError as exc:     # e.g. pcapng -- fall through to the Python readers
                print(f"[live_agent] native replay unavailable ({exc}); using the Python reader")
                self._ncap = None
        from scapy.all import PcapReader
        if not self._running.is_set():
            self._build_engines()
            self._running.set()
            self._started_at = time.time()
            self.stats["backend"] = "pcap-replay"
            self._loop_thread = threading.Thread(target=self._run_loop, daemon=True, name="live-detect")
            self._loop_thread.start()
        from src.capture.rawpcap import iter_raw_pcap
        raw_iter = iter_raw_pcap(path) if self.raw_capable else None
        if raw_iter is not None:
            last = None
            for ts, raw in raw_iter:
                if realtime and last is not None:
                    dt = ts - last
                    if 0 < dt < 5:
                        time.sleep(dt)
                last = ts
                self.on_raw(ts, raw)
            for _ in range(50):
                if self._q.qsize() == 0:
                    break
                time.sleep(0.1)
            return
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
        if self._backend is not None and hasattr(self._backend, "stop"):
            self._backend.stop()
        if self._loop is not None:
            self._loop.call_soon_threadsafe(lambda: None)
        if self._ncap is not None:
            self._ncap.stop()       # capture thread first, so the consumer's final drain sees everything
        if self._loop_thread is not None:
            self._loop_thread.join(timeout=15)
        if self._pool is not None:
            self._pool.drain(timeout=10.0)   # score what the shutdown flush routed to workers
            for alert in self._pool.drain_alerts():
                self._emit(alert, alert.pop("_t_arr", None))
            self._pool.stop()

    # ---------------- detection loop ----------------
    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        coro = self._consume_native() if self._ncap is not None else self._consume()
        prof_path = os.environ.get("STEALTHTAP_PROFILE")
        if prof_path:            # profile the consumer thread (cProfile only sees its own thread)
            import cProfile
            pr = cProfile.Profile()
            pr.enable()
            try:
                self._loop.run_until_complete(coro)
            finally:
                pr.disable()
                pr.dump_stats(prof_path)
            return
        self._loop.run_until_complete(coro)

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
                    await self._dispatch_immediate(log_type, rec, t_arr)
            if drained == 0:
                try:
                    item = await loop.run_in_executor(None, self._q.get, True, 0.3)
                    t_arr, pkt = item
                    for log_type, rec in self._assembler.process(pkt):
                        await self._dispatch_immediate(log_type, rec, t_arr)
                except queue.Empty:
                    pass

            await self._flush_ml_immediate()
            if self._pool is not None:
                self._pool.flush()
                for alert in self._pool.drain_alerts():
                    self._emit(alert, alert.pop("_t_arr", None))

            self._sample_series()
            now = time.monotonic()
            if now - last_tick >= SNAPSHOT_INTERVAL_S:
                last_tick = now
                await self._tick()

        for _lt, rec in self._assembler.flush():
            await self._dispatch_conn("conn_flush", rec, _DISPATCH_CONN_EXPIRE)
        await self._flush_ml_immediate()
        if self._pool is not None:
            for alert in self._pool.drain_alerts():
                self._emit(alert, alert.pop("_t_arr", None))


    async def _tick(self, expire_now: Optional[float] = None) -> None:
        """Every SNAPSHOT_INTERVAL_S: re-score active flows, expire idle ones, sample rates."""
        if self._native_flow_engines:
            cap = self._ncap
            for a in self._scoring.alerts_from_native_hits(cap.snapshot_scored(200_000)):
                self._emit(a, None)
            hits, sample, _total = cap.expire_scored(expire_now, BASELINE_SAMPLE_MAX)
            for a in self._scoring.alerts_from_native_hits(hits):
                self._emit(a, None)
            await self._handle_sample(sample)
        else:
            for _lt, rec in self._assembler.snapshot():
                await self._dispatch_conn("conn_snapshot", rec, _DISPATCH_CONN_SNAPSHOT)
            expire_kw = {} if expire_now is None else {"now": expire_now}
            await self._handle_expired([r for lt, r in self._assembler.expire(**expire_kw) if lt == "conn"])
        # pool mode: each worker batches its own shard's ML call and
        # observes its own shard's baseline, draining every loop
        # iteration -- no extra drain needed here.
        if self._ncap is not None:
            st = self._ncap.stats()
            self._rate_view = self._rate.sample(st["recv"], st["bytes"], {"drop": st["kernel_drop"]})
        else:
            kstats = self._backend.kernel_stats() if hasattr(self._backend, "kernel_stats") else None
            self._rate_view = self._rate.sample(self._assembler.stats["packets"], self._bytes, kstats)

    async def _handle_sample(self, sample: list) -> None:
        """Flows the native engines already scored (only hits crossed into Python): what is left
        for Python is the online baseline -- fed an evenly-strided sample when flow rates are
        extreme -- and the flow ML model, which the fusion policy only lets alert above a
        confidence it can't reach alone (so it is skipped unless configured otherwise)."""
        if self._scoring is None or not sample:
            return
        if self._scoring.flow_ml_can_alert:
            for alert in await self._scoring.ml_batch_conn(sample):
                self._emit(alert, None)
        for rec in sample:
            b_alert = self._scoring.observe_baseline(rec)
            if b_alert is not None:
                self._emit(b_alert, None)

    async def _handle_expired(self, expired: list) -> None:
        """Flows that ended: final conn-scoring, batched ML, live baseline."""
        for rec in expired:
            await self._dispatch_conn("conn_expire", rec, _DISPATCH_CONN_EXPIRE)
        if self._scoring is not None:
            # in-process mode: batch the ONNX call here, same as before.
            for alert in await self._scoring.ml_batch_conn(expired):
                self._emit(alert, None)
            for rec in expired:
                b_alert = self._scoring.observe_baseline(rec)
                if b_alert is not None:
                    self._emit(b_alert, None)

    def _sample_series(self, force: bool = False) -> None:
        """One telemetry point per second for the live dashboard's charts."""
        now = time.monotonic()
        t0, p0, b0 = self._series_last
        if not force and now - t0 < 1.0:
            return
        if self._ncap is not None:
            st = self._ncap.stats()
            pk, by, kd = st["recv"], st["bytes"], st["kernel_drop"]
            flows, pending = st["active_flows"], st["pending_records"]
        else:
            pk, by, kd = self._assembler.stats["packets"], self._bytes, 0
            flows, pending = self._assembler.active_flows(), self._q.qsize()
        dt = max(now - t0, 1e-6)
        self._series.append({"t": round(time.time(), 2), "pps": round((pk - p0) / dt), "mbps": round((by - b0) * 8 / dt / 1e6, 3),
                             "flows": flows, "pending": pending, "kdrop": kd, "alerts": self.stats["alerts"],
                             "udrop": self.stats["dropped"]})
        self._series_last = (now, pk, by)

    async def _consume_native(self) -> None:
        """Consumer for the native hot path: capture + assembly already happened in the
        Rust thread; this only dispatches the records it produced."""
        cap = self._ncap
        loop = asyncio.get_running_loop()
        last_tick = time.monotonic()
        while self._running.is_set():
            recs = cap.poll(0, 4000)
            if not recs and not cap.finished():
                recs = await loop.run_in_executor(None, cap.poll, 100, 4000)
            if recs:
                mono, wall = time.monotonic(), time.time()
                ended = []
                hits = []
                for log_type, rec in recs:
                    if log_type == "hit":           # native engine hit on a replayed loop's ended flow
                        hits.append((rec["engine"], rec["rec"], rec["hit"]))
                        continue
                    if log_type == "conn":          # a replayed loop's flows ended
                        ended.append(rec)
                        continue
                    arr = rec.pop("_arr", None)
                    t_arr = mono - (wall - arr) if arr else None
                    await self._dispatch_immediate(log_type, rec, t_arr)
                if hits and self._scoring is not None:
                    for a in self._scoring.alerts_from_native_hits(hits):
                        self._emit(a, None)
                if ended:
                    await (self._handle_sample(ended) if self._native_flow_engines else self._handle_expired(ended))
            await self._flush_ml_immediate()
            if self._pool is not None:
                self._pool.flush()
                for alert in self._pool.drain_alerts():
                    self._emit(alert, alert.pop("_t_arr", None))
            self._sample_series()
            now = time.monotonic()
            if now - last_tick >= SNAPSHOT_INTERVAL_S:
                last_tick = now
                await self._tick(cap.stats()["last_ts"] if self._replay_source else None)
            if self._replay_source and cap.finished() and cap.pending() == 0 and not recs:
                break            # a replayed file is exhausted and fully dispatched
        drain_deadline = time.monotonic() + float(os.environ.get("LIVE_STOP_DRAIN_S", "5"))
        while time.monotonic() < drain_deadline:   # bounded final drain (stop() halts capture first)
            recs = cap.poll(0, 4000)
            if not recs:
                break
            ended = []
            hits = []
            for log_type, rec in recs:
                if log_type == "hit":
                    hits.append((rec["engine"], rec["rec"], rec["hit"]))
                    continue
                if log_type == "conn":
                    ended.append(rec)
                    continue
                rec.pop("_arr", None)
                await self._dispatch_immediate(log_type, rec, None)
            if hits and self._scoring is not None:
                for a in self._scoring.alerts_from_native_hits(hits):
                    self._emit(a, None)
            if ended:
                await (self._handle_sample(ended) if self._native_flow_engines else self._handle_expired(ended))
        if self._native_flow_engines:
            hits, sample, _t = cap.expire_scored(None, BASELINE_SAMPLE_MAX, True)
            for a in self._scoring.alerts_from_native_hits(hits):
                self._emit(a, None)
            await self._handle_sample(sample)
        for _lt, rec in ([] if self._native_flow_engines else self._assembler.flush()):
            await self._dispatch_conn("conn_flush", rec, _DISPATCH_CONN_EXPIRE)
        await self._flush_ml_immediate()
        if self._pool is not None:
            for alert in self._pool.drain_alerts():
                self._emit(alert, alert.pop("_t_arr", None))
        self._replay_done = True

    async def _dispatch_immediate(self, log_type: str, rec: dict, t_arr: Optional[float]) -> None:
        if self._pool is not None:
            self._pool.route_immediate(log_type, rec, t_arr)
            return
        flow, alerts = await self._scoring.score_immediate_rules(log_type, rec)
        for alert in alerts:
            self._emit(alert, t_arr)
        fam = self._scoring.ml_family_for(log_type)
        if fam:
            self._ml_buf.setdefault(fam, []).append((flow, t_arr))

    async def _flush_ml_immediate(self) -> None:
        """Batched ONNX call per ML family, covering everything buffered
        since the last flush -- one InferenceSession.run() for the whole
        buffer instead of one per DNS/SSL/Modbus record. Called once per
        drain-loop pass (below), so added latency is bounded to about one
        pass, same tradeoff the existing SNAPSHOT_INTERVAL_S batching
        already makes for conn/flow scoring."""
        if self._scoring is None or not self._ml_buf:
            return
        for fam, items in self._ml_buf.items():
            if not items:
                continue
            flows = [f for f, _ in items]
            results = await self._scoring.ml_batch_immediate(fam, flows)
            for (_flow, t_arr), alert in zip(items, results):
                if alert is not None:
                    self._emit(alert, t_arr)
            items.clear()

    async def _dispatch_conn(self, phase: str, rec: dict, engine_keys: tuple) -> None:
        if self._pool is not None:
            self._pool.route_conn(phase, rec)
            return
        for alert in await self._scoring.score_conn(rec, engine_keys):
            self._emit(alert, None)

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
        tc, sev = alert.get("threat_class", "?"), alert.get("severity", "?")
        self._class_counts[tc] = self._class_counts.get(tc, 0) + 1
        self._sev_counts[sev] = self._sev_counts.get(sev, 0) + 1
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
            "running": self._running.is_set() and not self._replay_done,
            "finished": self._replay_done,
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
            "ml_families": (self._scoring.loaded_ml_families() if self._scoring else []),
            "baseline": (self._scoring.baseline_status() if self._scoring else None),
            "num_workers": self.num_workers_req,
            "engine_pool_dropped": (self._pool.dropped if self._pool else 0),
            "snapshot_interval_s": SNAPSHOT_INTERVAL_S,
            "native": self._ncap is not None,
            "source": "pcap-replay" if self._replay_source else ("interface" if self._ncap is not None else "python"),
            "capture": (self._ncap.stats() if self._ncap is not None else None),
            "capture_error": (self._ncap.error() if self._ncap is not None else None),
            **self.stats,
        }

    # ---- dashboard introspection (native hot path only; empty otherwise) ----
    @property
    def native(self) -> bool:
        return self._ncap is not None

    def series(self, seconds: int = 300) -> list[dict]:
        return list(self._series)[-max(1, seconds):]

    def summary(self) -> dict:
        return {"alerts_by_class": dict(self._class_counts), "alerts_by_severity": dict(self._sev_counts)}

    def hosts(self, limit: int = 500) -> list[dict]:
        return self._ncap.hosts(limit) if self._ncap else []

    def protocols(self) -> list[dict]:
        return self._ncap.protocols() if self._ncap else []

    def top_flows(self, n: int = 50) -> list[dict]:
        return [r for _t, r in self._ncap.top_flows(n)] if self._ncap else []

    def packets(self, after_id: int = 0, limit: int = 200, flt: str = "") -> list[dict]:
        return self._ncap.packets(after_id, limit, flt) if self._ncap else []

    def packet(self, pid: int):
        return self._ncap.packet(pid) if self._ncap else None

    def pending_work(self) -> int:
        """Packet queue depth PLUS anything still queued in the engine pool
        (if active). "packet queue empty" alone under-counts once records
        have been routed to worker processes -- their queues drain on their
        own schedule."""
        return (self._q.qsize() + (self._ncap.pending() if self._ncap else 0)
                + (self._pool.pending() if self._pool else 0))

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
                      buffer_mb=a.buffer_mb, promisc=not a.no_promisc, num_workers=a.workers,
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
    pr.add_argument("--workers", type=int, default=DEFAULT_ENGINE_WORKERS,
                    help="engine-scoring worker processes (multi-core); needs real Redis "
                         "for values > 1, else auto-downgrades to 1")
    pr.set_defaults(func=_cmd_run)

    ps = sub.add_parser("serve", help="REST+SSE control server for the dashboard")
    ps.add_argument("--host", default="127.0.0.1")
    ps.add_argument("--port", type=int, default=8100)
    ps.set_defaults(func=_cmd_serve)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()  # no-op unless frozen (PyInstaller .exe) with num_workers>1
    main()
