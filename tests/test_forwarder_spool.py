"""Alerts survive an API outage: spooled to disk, re-sent in order once the API is back, bounded on disk."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from src.capture.forwarder import HttpAlertForwarder


class _Api:
    def __init__(self):
        self.received = []
        self.up = False
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if not outer.up:
                    self.send_response(503); self.end_headers(); return
                outer.received += json.loads(body)
                self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

            def log_message(self, *a):
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


def _wait(cond, t=15.0):
    end = time.time() + t
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_outage_spools_then_replays_in_order(tmp_path):
    api = _Api()
    f = HttpAlertForwarder(api.url, batch=2, flush_s=0.1, spool_dir=str(tmp_path))
    for i in range(6):
        f({"alert_id": f"a{i}"})
    assert _wait(lambda: f.spooled == 6)
    assert api.received == [] and f.dropped == 0
    api.up = True
    f({"alert_id": "a6"})                                 # new alert must not overtake the spooled ones
    assert _wait(lambda: len(api.received) == 7)
    assert [a["alert_id"] for a in api.received] == [f"a{i}" for i in range(7)]
    assert not list(tmp_path.glob("alerts-*.jsonl"))
    f.stop(); api.srv.shutdown()


def test_spool_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("STEALTHTAP_SPOOL_MAX_MB", "0.001")   # ~1 KB
    api = _Api()
    f = HttpAlertForwarder(api.url, batch=1, flush_s=0.05, spool_dir=str(tmp_path))
    for i in range(60):
        f({"alert_id": f"x{i}", "pad": "p" * 100})
    assert _wait(lambda: f.spooled == 60)
    assert sum(p.stat().st_size for p in tmp_path.glob("alerts-*.jsonl")) <= 1200
    assert f.dropped > 0
    f.stop(); api.srv.shutdown()
