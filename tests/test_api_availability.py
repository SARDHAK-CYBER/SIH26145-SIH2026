"""
The API must stay available under load: one huge upload previously froze
/health and every other endpoint for minutes because CPU-heavy analysis ran
ON the asyncio event loop with no cap and no deadline.
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("STEALTHTAP_STANDALONE", "1")
httpx = pytest.importorskip("httpx")
from fastapi import FastAPI

from src.api import pcap_analysis as pa
from src.memstore import MemoryStore

ROOT = Path(__file__).resolve().parent.parent
SMALL = ROOT / "samples" / "test.pcap"
BIG = ROOT / "samples" / "netbios_ssn2.pcap"


def _app() -> FastAPI:
    app = FastAPI()

    @app.get("/health")
    async def health():
        return {"status": "ok"}
    app.include_router(pa.router)
    app.state.model_server = None
    app.state.yara_scanner = None
    app.state.redis = MemoryStore()
    return app


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", timeout=120)


def _reset(monkeypatch, **over):
    monkeypatch.setattr(pa, "_inflight", 0)
    for k, v in over.items():
        monkeypatch.setattr(pa, k, v)


def test_sync_analysis_still_works(monkeypatch):
    _reset(monkeypatch)

    async def go():
        async with _client(_app()) as c:
            with open(SMALL, "rb") as f:
                r = await c.post("/analyze/pcap", files={"file": ("test.pcap", f, "application/octet-stream")})
        return r
    r = asyncio.run(go())
    assert r.status_code == 200, r.text
    assert r.json()["packet_summary"]["conn_flows"] > 0


def test_health_stays_responsive_while_a_cpu_bound_analysis_runs(monkeypatch):
    """Inject a genuinely CPU-bound 1.5s engine stage (busy loop, holds the GIL
    in bursts). If it ran ON the event loop -- the old behaviour -- /health
    would stall for the whole 1.5s; in the worker thread it must not."""
    _reset(monkeypatch)
    real = pa._run_engines_blocking

    def busy(parsed, model_server, redis_client):
        end = time.perf_counter() + 1.5
        while time.perf_counter() < end:
            sum(i * i for i in range(2000))
        return real(parsed, model_server, redis_client)
    monkeypatch.setattr(pa, "_run_engines_blocking", busy)

    async def go():
        app = _app()
        async with _client(app) as c:
            with open(SMALL, "rb") as f:
                data = f.read()
            job = asyncio.create_task(c.post("/analyze/pcap", files={"file": ("t.pcap", data, "application/octet-stream")}))
            await asyncio.sleep(0.3)  # into the busy stage
            worst, samples = 0.0, 0
            while not job.done():
                t = time.perf_counter()
                r = await c.get("/health")
                worst = max(worst, time.perf_counter() - t)
                samples += 1
                assert r.status_code == 200
                await asyncio.sleep(0.05)
            return worst, samples, await job
    worst, samples, resp = asyncio.run(go())
    assert resp.status_code == 200
    assert samples >= 5, f"only {samples} health probes landed during a 1.5s analysis -- loop starved"
    assert worst < 0.5, f"/health blocked for {worst:.2f}s during analysis (event loop starved?)"


def test_backpressure_returns_429_when_queue_full(monkeypatch):
    _reset(monkeypatch, MAX_CONCURRENT_ANALYSES=1, MAX_QUEUED_ANALYSES=0)
    monkeypatch.setattr(pa, "_inflight", 1)  # one analysis already in flight

    async def go():
        async with _client(_app()) as c:
            with open(SMALL, "rb") as f:
                return await c.post("/analyze/pcap", files={"file": ("test.pcap", f, "application/octet-stream")})
    r = asyncio.run(go())
    assert r.status_code == 429 and r.headers.get("retry-after")


def test_deadline_returns_504_not_an_open_socket(monkeypatch):
    _reset(monkeypatch, ANALYSIS_TIMEOUT_SECONDS=0.2)

    async def slow(*a, **k):
        await asyncio.sleep(5)
    monkeypatch.setattr(pa, "_analyze_contents", slow)

    async def go():
        async with _client(_app()) as c:
            with open(SMALL, "rb") as f:
                return await c.post("/analyze/pcap", files={"file": ("test.pcap", f, "application/octet-stream")})
    r = asyncio.run(go())
    assert r.status_code == 504
    assert pa._inflight == 0, "in-flight slot must be released after a timeout"


def test_async_job_submit_and_poll(monkeypatch):
    _reset(monkeypatch)

    async def go():
        async with _client(_app()) as c:
            with open(SMALL, "rb") as f:
                sub = await c.post("/analyze/pcap/async", files={"file": ("test.pcap", f, "application/octet-stream")})
            assert sub.status_code == 202
            jid = sub.json()["job_id"]
            for _ in range(200):
                r = await c.get(f"/analyze/jobs/{jid}")
                if r.json()["status"] != "running":
                    return r
                await asyncio.sleep(0.1)
            raise AssertionError("job never finished")
    r = asyncio.run(go())
    assert r.status_code == 200 and r.json()["status"] == "done"
    assert r.json()["result"]["packet_summary"]["conn_flows"] > 0
    assert pa._inflight == 0


def test_unknown_job_is_404(monkeypatch):
    _reset(monkeypatch)

    async def go():
        async with _client(_app()) as c:
            return await c.get("/analyze/jobs/doesnotexist")
    assert asyncio.run(go()).status_code == 404


def test_oversize_suricata_is_skipped_not_queued(monkeypatch):
    monkeypatch.setattr(pa, "STANDALONE", False)
    monkeypatch.setattr(pa, "SURICATA_MAX_BYTES", 10)
    out = asyncio.run(pa._run_suricata(b"x" * 100))
    assert out == []
