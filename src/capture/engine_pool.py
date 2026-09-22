"""
EngineWorkerPool -- multi-core scaling for the LIVE detection stack.

Priority-1 (native Rust LiveFlowAssembler, see native/stealthtap_core)
measured 393k pps for parsing alone vs 1,580 pps for the full pipeline on
the same capture -- parsing stopped being the bottleneck; ENG01..13 +
ML scoring (pure Python, GIL-bound) is now ~250x slower than parsing and
is the only thing standing between this pipeline and the 1-5 Gbps target.
That only scales across CORES via separate processes, not threads.

What does NOT get sharded: flow assembly. Packets belonging to one flow
arrive from BOTH endpoints (client->server AND server->client), i.e. two
different source IPs for the same flow -- sharding raw packets by source
IP would split a single flow's two directions across two workers and
corrupt the assembler's per-flow state. So assembly stays single-process
(comfortably fast enough alone -- see above) and only the ALREADY-
ASSEMBLED records (conn/dns/ssl/modbus/dnp3, one record per flow-lifetime
event, orders of magnitude fewer than raw packets) get sharded out to
worker processes for engine scoring.

What DOES get sharded, and how: every assembled record carries a single
canonical `id.orig_h` (the flow's true originator, resolved once by
flow_orientation.sender_is_originator -- SYN/SYN-ACK or port-rank, never
"whichever side sent this particular packet"), so routing by
hash(id.orig_h) sends ALL of one source's flows to the SAME worker
consistently. That is exactly what ENG-05 (recon: fan-out count per
source) needs -- it holds pure in-process Python state
(src/engines/eng05_recon.py's self._seen dict), so correctness for it
depends entirely on source-IP-stable routing, not on any shared store.

ENG-01/02/06/13 are Redis-backed (src_ip- AND, for ENG-01's victim-side
HLL/count, dst_ip-keyed). Redis is a real networked service shared by
every worker process regardless of which one writes a given key, so
those stay correct under ANY routing scheme -- but only when a real
Redis is reachable. The in-process MemoryStore fallback is per-process
local state, so multi-worker mode requires real Redis; if none is
reachable, the caller (LiveAgent) downgrades to num_workers=1 rather
than run workers with silently-inconsistent state.
"""
from __future__ import annotations

import multiprocessing as mp
import queue
import time
import zlib
from typing import Optional


def _shard_key(rec: dict) -> str:
    return str(rec.get("id.orig_h", ""))


def _worker_main(worker_id: int, in_q: "mp.Queue", out_q: "mp.Queue", stop_evt) -> None:
    import asyncio
    from src.capture.scoring import ScoringEngine, DISPATCH_CONN_SNAPSHOT, DISPATCH_CONN_EXPIRE

    scoring = ScoringEngine(worker_id=worker_id)
    print(f"[live_agent worker={worker_id}] ready "
          f"(redis_shared={scoring.redis_is_shared})")
    out_q.put({"__ready__": True, "worker_id": worker_id})

    _BATCH_MAX = 256

    async def _run() -> None:
        expire_batch: list[dict] = []

        async def _flush_ml_batch() -> None:
            if not expire_batch:
                return
            for alert in await scoring.ml_batch_conn(expire_batch):
                out_q.put(alert)
            expire_batch.clear()

        loop = asyncio.get_event_loop()
        while not stop_evt.is_set():
            try:
                batch = await loop.run_in_executor(None, in_q.get, True, 0.5)
            except Exception:
                continue
            if batch is None:
                break

            for item in batch:
                kind = item[0]
                if kind == "immediate":
                    _, log_type, rec, t_arr = item
                    for alert in await scoring.score_immediate(log_type, rec):
                        alert["_t_arr"] = t_arr
                        out_q.put(alert)
                elif kind == "conn_snapshot":
                    _, rec = item
                    for alert in await scoring.score_conn(rec, DISPATCH_CONN_SNAPSHOT):
                        out_q.put(alert)
                elif kind in ("conn_expire", "conn_flush"):
                    _, rec = item
                    for alert in await scoring.score_conn(rec, DISPATCH_CONN_EXPIRE):
                        out_q.put(alert)
                    b_alert = scoring.observe_baseline(rec)
                    if b_alert is not None:
                        out_q.put(b_alert)
                    expire_batch.append(rec)
            if len(expire_batch) >= _BATCH_MAX or in_q.empty():
                await _flush_ml_batch()

        await _flush_ml_batch()

    asyncio.run(_run())
    print(f"[live_agent worker={worker_id}] stopped")


class EngineWorkerPool:
    """Spawns `num_workers` engine-scoring processes and routes assembled
    records to them by source-IP-stable hashing. Flow assembly (the
    packet-rate-heavy part) is NOT touched by this pool -- it stays
    single-process, in the caller, and only hands this pool the much
    lower-rate per-flow-event records."""

    # Records are buffered per-shard and sent as one multiprocessing.Queue
    # message per batch, not one message per record: pickling+OS-pipe
    # round-trips have real fixed overhead per call, and at typical
    # per-flow-event record rates (thousands/sec, not packets/sec -- the
    # packet rate the native assembler already handles alone) doing that
    # per record cost MORE than the parallelism this pool exists to buy.
    # Measured: 4 workers, per-record routing -- 847 pps (SLOWER than the
    # 1,580 pps single-process baseline). Batches of _BATCH_MAX bound
    # added latency to one drain-loop pass while cutting IPC call count by
    # up to _BATCH_MAX x.
    _BATCH_MAX = 128

    def __init__(self, num_workers: int, queue_size: int = 2_000):
        if num_workers < 2:
            raise ValueError("EngineWorkerPool requires num_workers >= 2")
        self.num_workers = num_workers
        self._in_qs: list = [mp.Queue(maxsize=queue_size) for _ in range(num_workers)]
        self._out_q: "mp.Queue" = mp.Queue(maxsize=queue_size * num_workers * self._BATCH_MAX)
        self._stop_evt = mp.Event()
        self._procs: list = []
        self._buf: list = [[] for _ in range(num_workers)]
        self.dropped = 0

    def start(self, ready_timeout: float = 60.0) -> None:
        """Blocks until every worker has finished building its ScoringEngine
        (Redis connect + ONNX model load -- measured 20s+ per worker under
        contention) or ready_timeout elapses. Without this, callers that
        start a wall-clock timer right after start() returns would fold
        that one-time cold-start cost into a "steady state throughput"
        number, understating it -- exactly what happened measuring this
        pool with scripts/bench_throughput.py before this fix."""
        for i in range(self.num_workers):
            p = mp.Process(target=_worker_main, args=(i, self._in_qs[i], self._out_q, self._stop_evt),
                           daemon=True, name=f"stealthtap-engine-{i}")
            p.start()
            self._procs.append(p)

        deadline = time.time() + ready_timeout
        ready = set()
        while len(ready) < self.num_workers and time.time() < deadline:
            try:
                item = self._out_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if isinstance(item, dict) and item.get("__ready__"):
                ready.add(item["worker_id"])
            else:
                self._out_q.put(item)  # a real alert raced ahead of readiness -- put it back
        if len(ready) < self.num_workers:
            print(f"[live_agent] WARNING: only {len(ready)}/{self.num_workers} engine "
                  f"workers signaled ready within {ready_timeout}s")

    def stop(self, timeout: float = 5.0) -> None:
        self.flush()
        self._stop_evt.set()
        for q in self._in_qs:
            try:
                q.put_nowait(None)
            except Exception:
                pass
        for p in self._procs:
            p.join(timeout=timeout)
            if p.is_alive():
                p.terminate()

    def _shard(self, rec: dict) -> int:
        return zlib.crc32(_shard_key(rec).encode()) % self.num_workers

    def _enqueue(self, i: int, item: tuple) -> None:
        buf = self._buf[i]
        buf.append(item)
        if len(buf) >= self._BATCH_MAX:
            self._flush_shard(i)

    def _flush_shard(self, i: int) -> None:
        buf = self._buf[i]
        if not buf:
            return
        try:
            self._in_qs[i].put_nowait(buf)
        except queue.Full:
            self.dropped += len(buf)
        self._buf[i] = []

    def flush(self) -> None:
        """Send any partially-filled batches now -- call once per drain-loop
        pass so buffered records never wait longer than that for scoring."""
        for i in range(self.num_workers):
            self._flush_shard(i)

    def route_immediate(self, log_type: str, rec: dict, t_arr: Optional[float]) -> None:
        self._enqueue(self._shard(rec), ("immediate", log_type, rec, t_arr))

    def route_conn(self, phase: str, rec: dict) -> None:
        self._enqueue(self._shard(rec), (phase, rec))

    def pending(self) -> int:
        """Records still queued for workers (buffered here + sent but not
        yet consumed) -- NOT reflected in the caller's own packet queue
        once routed here, so anything waiting on "processing is done"
        (e.g. scripts/bench_throughput.py) must check this too, not just
        the packet queue depth."""
        buffered = sum(len(b) for b in self._buf)
        # qsize() counts BATCHES, not records, but is >0 iff work remains --
        # good enough for a "still draining" check without per-record cost.
        return buffered + sum(q.qsize() for q in self._in_qs)

    def drain_alerts(self, max_items: int = 10_000) -> list[dict]:
        out = []
        for _ in range(max_items):
            try:
                out.append(self._out_q.get_nowait())
            except queue.Empty:
                break
        return out
