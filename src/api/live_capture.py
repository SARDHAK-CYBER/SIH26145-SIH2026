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

  Live dashboard data (native capture engine):
    POST /capture/replay          {path, loops, speed} replay a real pcap through the SAME live pipeline
    GET  /capture/series?seconds= per-second pps / Mbit/s / flows / drops / alerts
    GET  /capture/summary         alerts by class + severity
    GET  /capture/hosts           every host seen (bytes, packets, MAC, local/remote, gateway guess)
    GET  /capture/protocols       protocol mix (packets + bytes)
    GET  /capture/flows           heaviest active flows
    GET  /capture/packets         packet list from the in-memory ring (after=, limit=, filter=)
    GET  /capture/packet/{id}     Wireshark-style layer tree + hex for one packet
    GET  /capture/export.pcap     download ring packets (ids= or filter=) as a pcap
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

import ipaddress
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
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
    # Optional: path to a short historical pcap of THIS network (already on
    # the server -- e.g. one previously uploaded via /analyze/pcap) to seed
    # the online behavioural baseline's ~10-minute learning window, instead
    # of it only ever learning from live traffic one flow at a time. See
    # OnlineBaseline.warm_start -- doesn't skip the real-time-diversity
    # requirement, just lets a historical capture that genuinely spans it
    # satisfy it immediately instead of waiting live.
    warm_start_pcap: Optional[str] = None


@router.get("/interfaces")
def interfaces(include_down: bool = True, include_loopback: bool = False):
    return [i.as_dict() for i in list_interfaces(include_down=include_down,
                                                include_loopback=include_loopback)]


@router.get("/capabilities")
def caps():
    c = capabilities()
    try:
        import ctypes
        c["elevated"] = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else os.geteuid() == 0
    except Exception:
        c["elevated"] = None
    try:
        from src.capture.live_agent import NATIVE_CAPTURE_AVAILABLE
        c["native_engine"] = NATIVE_CAPTURE_AVAILABLE
    except Exception:
        c["native_engine"] = False
    return c


@router.post("/start")
def start(req: StartRequest):
    global _agent
    if _agent is not None and _agent.status()["running"]:
        raise HTTPException(409, f"capture already running on {_agent.iface_req!r}; stop it first")
    fwd = make_forwarder()   # POSTs alerts to STEALTHTAP_API_URL/alerts/ingest when set
    agent = LiveAgent(req.interface, req.bpf, prefer_kernel=req.prefer_kernel,
                      buffer_mb=req.buffer_mb, promisc=req.promisc, alert_sink=fwd,
                      warm_start_pcap=req.warm_start_pcap)
    agent._forwarder = fwd
    try:
        agent.start()
    except CaptureError as exc:
        if fwd:
            fwd.stop()
        raise HTTPException(422, str(exc))
    _agent = agent
    return _agent.status()


class ReplayRequest(BaseModel):
    path: str
    loops: int = 1          # 0 = forever (soak)
    speed: float = 0.0      # 0 = as fast as possible, 1.0 = original timing


def _allowed_replay_path(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    if p.suffix.lower() != ".pcap" or not p.is_file():
        raise HTTPException(422, f"{path!r} is not an existing classic .pcap file")
    extra = [Path(x).resolve() for x in os.environ.get("STEALTHTAP_REPLAY_DIRS", "").split(os.pathsep) if x]
    roots = [Path.cwd().resolve(), Path.home().resolve(), *extra]
    if not any(r == p or r in p.parents for r in roots):
        raise HTTPException(403, "replay files must live under the working directory, the home directory or "
                                 "STEALTHTAP_REPLAY_DIRS")
    return p


@router.get("/replay-files")
def replay_files():
    """Classic .pcap files the replay endpoint may read: samples/, the extra dirs, and (if set) uploads."""
    roots = [Path("samples").resolve()]
    roots += [Path(x).resolve() for x in os.environ.get("STEALTHTAP_REPLAY_DIRS", "").split(os.pathsep) if x]
    out = []
    for r in roots:
        if r.is_dir():
            for f in sorted(r.glob("*.pcap")):
                out.append({"path": str(f), "name": f.name, "mb": round(f.stat().st_size / 1e6, 1)})
    return out


@router.post("/replay")
def replay(req: ReplayRequest):
    global _agent
    if _agent is not None and _agent.status()["running"]:
        raise HTTPException(409, "a capture/replay is already running; stop it first")
    path = _allowed_replay_path(req.path)
    agent = LiveAgent("pcap-replay", None, alert_sink=make_forwarder())
    try:
        agent.start_replay(str(path), loops=req.loops, speed=req.speed)
    except CaptureError as exc:
        raise HTTPException(422, str(exc))
    _agent = agent
    return _agent.status()


def _need_agent():
    if _agent is None:
        raise HTTPException(409, "no capture running -- start one first")
    return _agent


@router.get("/series")
def series(seconds: int = 300):
    return _need_agent().series(seconds)


@router.get("/summary")
def summary():
    return _need_agent().summary()


def _is_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local or a.is_loopback
    except ValueError:
        return False


@router.get("/hosts")
def hosts(limit: int = 500, scope: str = "all"):
    rows = _need_agent().hosts(limit)
    # A MAC that fronts many remote IPs is the first-hop gateway, not those hosts.
    remote_by_mac: dict[str, int] = {}
    for h in rows:
        if h["mac"] and not _is_local(h["ip"]):
            remote_by_mac[h["mac"]] = remote_by_mac.get(h["mac"], 0) + 1
    out = []
    for h in rows:
        local = _is_local(h["ip"])
        h["local"] = local
        h["gateway_for_remote"] = bool(h["mac"] and local and remote_by_mac.get(h["mac"], 0) >= 3)
        if h["mac"] and not local:
            h["mac"] = None      # a remote host's L2 source is the gateway's MAC, not its own
        if scope == "local" and not local:
            continue
        if scope == "remote" and local:
            continue
        out.append(h)
    return out


@router.get("/protocols")
def protocols():
    return sorted(_need_agent().protocols(), key=lambda r: -r["bytes"])


@router.get("/flows")
def flows(n: int = 50):
    return _need_agent().top_flows(n)


@router.get("/packets")
def packets(after: int = 0, limit: int = Query(200, le=2000), filter: str = ""):
    return _need_agent().packets(after, limit, filter)


@router.get("/packet/{pid}")
def packet(pid: int):
    got = _need_agent().packet(pid)
    if got is None:
        raise HTTPException(404, "packet has scrolled out of the ring (or never existed)")
    ts, wire, raw = got
    from src.api.packet_detail import dissect
    d = dissect(bytes(raw), ts, wire)
    d["id"] = pid
    return d


@router.get("/export.pcap")
def export_pcap(ids: str = "", filter: str = "", limit: int = 5000):
    agent = _need_agent()
    if ids:
        wanted = [int(x) for x in ids.split(",") if x.strip().isdigit()][:limit]
    else:
        wanted = [r["id"] for r in agent.packets(0, limit, filter)]
    pk = []
    for i in wanted:
        got = agent.packet(i)
        if got:
            pk.append((got[0], bytes(got[2])))
    from src.api.packet_detail import to_pcap_bytes
    return Response(to_pcap_bytes(pk), media_type="application/vnd.tcpdump.pcap",
                    headers={"Content-Disposition": 'attachment; filename="stealthtap-selection.pcap"'})


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
    from src.api.discovery import router as discovery_router
    app.include_router(discovery_router)

    @app.get("/health")
    def health():
        return {"status": "ok", "capture": status()}

    return app
