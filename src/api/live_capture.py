"""
FastAPI router for live-capture control + a Server-Sent-Events alert
stream, backing the dashboard's "Live Capture" mode.

One capture session per process. Mount this on the main API when it runs
on the host (uvicorn in the venv, or a Linux host-network container), or
run it standalone via `python -m src.capture.live_agent serve`.

    GET  /capture/interfaces      list NICs (the Wireshark-style picker)
    GET  /capture/capabilities    kernel/npcap/raw-socket support on this host
    POST /capture/start           {interface, bpf?, prefer_kernel?}
    POST /capture/stop
    GET  /capture/status          live counters (packets, flows, alerts, drops)
    GET  /capture/alerts?limit=   recent alerts (poll fallback)
    GET  /capture/stream          text/event-stream of alerts as they fire
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.capture.backends import CaptureError, capabilities
from src.capture.interfaces import list_interfaces
from src.capture.live_agent import LiveAgent
from src.capture.forwarder import make_forwarder

router = APIRouter(prefix="/capture", tags=["live-capture"])

_agent: Optional[LiveAgent] = None


class StartRequest(BaseModel):
    interface: str
    bpf: Optional[str] = None
    prefer_kernel: bool = True
    buffer_mb: int = 64
    promisc: bool = True


@router.get("/interfaces")
def interfaces(include_down: bool = True, include_loopback: bool = False):
    return [i.as_dict() for i in list_interfaces(include_down=include_down,
                                                include_loopback=include_loopback)]


@router.get("/capabilities")
def caps():
    return capabilities()


@router.post("/start")
def start(req: StartRequest):
    global _agent
    if _agent is not None and _agent.status()["running"]:
        raise HTTPException(409, f"capture already running on {_agent.iface_req!r}; stop it first")
    fwd = make_forwarder()   # POSTs alerts to STEALTHTAP_API_URL/alerts/ingest when set
    agent = LiveAgent(req.interface, req.bpf, prefer_kernel=req.prefer_kernel,
                      buffer_mb=req.buffer_mb, promisc=req.promisc, alert_sink=fwd)
    agent._forwarder = fwd
    try:
        agent.start()
    except CaptureError as exc:
        if fwd:
            fwd.stop()
        raise HTTPException(422, str(exc))
    _agent = agent
    return _agent.status()


@router.post("/stop")
def stop():
    global _agent
    if _agent is None:
        return {"running": False}
    status = _agent.status()
    _agent.stop()
    fwd = getattr(_agent, "_forwarder", None)
    if fwd:
        fwd.stop()
    _agent = None
    return {**status, "running": False}


@router.get("/status")
def status():
    if _agent is None:
        return {"running": False}
    return _agent.status()


@router.get("/alerts")
def alerts(limit: int = 100):
    if _agent is None:
        return []
    return _agent.recent_alerts(limit)


@router.get("/stream")
async def stream():
    if _agent is None:
        raise HTTPException(409, "no capture running")
    agent = _agent
    q = agent.subscribe()

    async def _gen():
        # replay only a few recent alerts so a late/reconnecting subscriber
        # isn't blank -- the client de-dupes by alert_id.
        for a in agent.recent_alerts(5):
            yield f"data: {json.dumps(a)}\n\n"
        try:
            while True:
                try:
                    a = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {json.dumps(a)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            agent.unsubscribe(q)

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def build_app():
    """Standalone app for `live_agent serve` -- just this router + CORS."""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI(title="StealthTap Live Capture", version="1.0.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    app.include_router(router)

    @app.get("/health")
    def health():
        return {"status": "ok", "capture": status()}

    return app
