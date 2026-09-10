"""
HttpAlertForwarder -- batches live-capture alerts and POSTs them to the
main API's /alerts/ingest, so sensor alerts land in the same PostgreSQL
`alerts` table the PCAP-upload path writes to. Stdlib only (urllib),
non-blocking (background thread), drops on overflow rather than stalling
the detection loop.

Enabled when STEALTHTAP_API_URL is set (the docker-compose `sensor`
service sets it to http://api:8000).
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
import urllib.request
from typing import Optional


class HttpAlertForwarder:
    def __init__(self, api_url: str, batch: int = 25, flush_s: float = 2.0, maxq: int = 20_000):
        self.endpoint = api_url.rstrip("/") + "/alerts/ingest"
        self.batch = batch
        self.flush_s = flush_s
        self._q: "queue.Queue" = queue.Queue(maxsize=maxq)
        self._stop = threading.Event()
        self.sent = 0
        self.dropped = 0
        self._t = threading.Thread(target=self._run, daemon=True, name="alert-forwarder")
        self._t.start()

    def __call__(self, alert: dict) -> None:
        try:
            self._q.put_nowait(alert)
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        pending: list[dict] = []
        last = time.monotonic()
        while not self._stop.is_set():
            try:
                pending.append(self._q.get(timeout=0.5))
            except queue.Empty:
                pass
            now = time.monotonic()
            if pending and (len(pending) >= self.batch or now - last >= self.flush_s):
                self._post(pending)
                pending = []
                last = now
        if pending:
            self._post(pending)

    def _post(self, alerts: list[dict]) -> None:
        try:
            req = urllib.request.Request(
                self.endpoint, data=json.dumps(alerts).encode(),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            urllib.request.urlopen(req, timeout=5).read()
            self.sent += len(alerts)
        except Exception as exc:
            self.dropped += len(alerts)
            print(f"[forwarder] POST {self.endpoint} failed ({exc}) -- {len(alerts)} alert(s) dropped")

    def stop(self) -> None:
        self._stop.set()
        self._t.join(timeout=3)


def make_forwarder() -> Optional[HttpAlertForwarder]:
    url = os.environ.get("STEALTHTAP_API_URL")
    return HttpAlertForwarder(url) if url else None
