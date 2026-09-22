#!/usr/bin/env python3
"""
StealthTap desktop application -- one executable, no Docker / Redis / Postgres.

    stealthtap.exe                 # Windows (run as Administrator for live capture)
    sudo ./stealthtap              # Linux   (or: setcap cap_net_raw,cap_net_admin+eip)

Starts a local server on 127.0.0.1:8100 and opens the dashboard: pick a
network interface on the Live Capture tab (Wireshark-style) to analyse live
traffic, or drop a .pcap on the PCAP Ingest tab. The same rule engines and
ONNX models as the Docker deployment run in-process; the stateful engines
(flood / C2 beaconing / exfiltration / brute force) use an in-memory store
instead of Redis.

Capture path: Linux -> AF_PACKET mmap ring + in-kernel BPF; Windows ->
Npcap's kernel driver (install Npcap from https://npcap.com -- its licence
does not allow redistribution, so it is deliberately NOT bundled).

Binds to loopback only. Nothing is transmitted off the machine.
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path


def resource_root() -> Path:
    """Directory holding models/, samples/, ui/ -- the PyInstaller bundle when frozen."""
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def build_desktop_app(root: Path):
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles

    from src.api.dashboard import router as dashboard_router
    from src.api.live_capture import router as live_router, status as capture_status
    from src.api.pcap_analysis import router as pcap_router
    from src.memstore import MemoryStore

    app = FastAPI(title="StealthTap", version="1.0.0")
    app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:8100", "http://localhost:8100"],
                       allow_methods=["*"], allow_headers=["*"])

    @app.on_event("startup")
    async def _startup() -> None:
        app.state.redis = MemoryStore()
        app.state.db_pool = None
        app.state.yara_scanner = None
        app.state.model_server = None
        try:
            from src.inference.model_server import HybridModelServer
            app.state.model_server = HybridModelServer()
        except Exception as exc:  # ML stays optional; rule engines still run
            print(f"[stealthtap] ML disabled: {exc}")

    @app.get("/health")
    def health():
        ms = getattr(app.state, "model_server", None)
        return {"status": "ok", "mode": "standalone",
                "models_loaded": ms.loaded_families() if ms else [],
                "capture": capture_status()}

    @app.get("/models/manifest")
    def manifest():
        from fastapi import HTTPException
        ms = getattr(app.state, "model_server", None)
        if ms is None or not ms.manifest:
            raise HTTPException(404, "no model manifest available")
        return ms.manifest

    app.include_router(live_router)
    app.include_router(pcap_router)
    app.include_router(dashboard_router)

    ui = root / "ui"
    if not ui.is_dir():
        ui = root / "build" / "ui"      # running from a source checkout
    if ui.is_dir():
        app.mount("/", StaticFiles(directory=str(ui), html=True), name="ui")   # must be last
    return app


def _is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def main() -> None:
    ap = argparse.ArgumentParser(prog="stealthtap", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8100)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    root = resource_root()
    os.chdir(root)                                   # samples/ etc. resolve relative to the bundle
    sys.path.insert(0, str(root))
    os.environ["STEALTHTAP_STANDALONE"] = "1"
    os.environ.setdefault("MODELS_DIR", str(root / "models"))
    os.environ.setdefault("SCAPY_USE_PCAPDNET", "1")  # avoids a ~120 s Windows route-discovery hang

    if not _is_admin():
        print("[stealthtap] NOTE: not running as Administrator/root -- the dashboard and PCAP analysis work, "
              "but live capture needs raw-socket privileges.", file=sys.stderr)

    try:
        from scapy.config import conf as _c
        _c.use_pcap = True
        _c.manufdb = None
    except Exception:
        pass

    import uvicorn
    app = build_desktop_app(root)
    url = f"http://{args.host}:{args.port}/"
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    print(f"[stealthtap] dashboard: {url}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
