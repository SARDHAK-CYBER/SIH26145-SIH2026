"""
HttpAlertForwarder -- batches live-capture alerts and POSTs them to the
main API's /alerts/ingest, so sensor alerts land in the same PostgreSQL
`alerts` table the PCAP-upload path writes to. Stdlib only (urllib),
non-blocking (background thread), drops on overflow rather than stalling
the detection loop.

Durable: a batch the API cannot take (API/DB restart, network cut) is written to
an on-disk spool (STEALTHTAP_SPOOL_DIR, default data/spool, capped by
STEALTHTAP_SPOOL_MAX_MB, oldest evicted first) and re-sent in order once the
API answers again, so an outage of the central store does not lose alerts.

Enabled when STEALTHTAP_API_URL is set (the docker-compose `sensor`
service sets it to http://api:8000).
"""
from __future__ import annotations

import json
import os
import queue
from pathlib import Path
import threading
import time
import urllib.request
from typing import Optional


class HttpAlertForwarder:
    def __init__(self, api_url: str, batch: int = 25, flush_s: float = 2.0, maxq: int = 20_000, spool_dir: Optional[str] = None):
        self.endpoint = api_url.rstrip("/") + "/alerts/ingest"
        self.batch = batch
        self.flush_s = flush_s
        self._q: "queue.Queue" = queue.Queue(maxsize=maxq)
        self.spool_dir = Path(spool_dir or os.environ.get("STEALTHTAP_SPOOL_DIR", "data/spool"))
        self.spool_max = int(float(os.environ.get("STEALTHTAP_SPOOL_MAX_MB", "200")) * 1024 * 1024)
        self.spooled = 0
        self.replayed = 0
        self._next_replay = 0.0
        self._seq = 0
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
            if now >= self._next_replay:
                self._replay()
        if pending:
            self._post(pending)

    def _send(self, alerts: list[dict]) -> bool:
        headers = {"Content-Type": "application/json"}
        key = os.environ.get("STEALTHTAP_API_KEY", "").strip()
        if key:
            headers["X-API-Key"] = key
        try:
            req = urllib.request.Request(self.endpoint, data=json.dumps(alerts).encode(), headers=headers, method="POST")
            urllib.request.urlopen(req, timeout=5).read()
            return True
        except Exception as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"
            return False

    def _post(self, alerts: list[dict]) -> None:
        # never jump the queue ahead of older spooled alerts: order matters to anyone reading the history
        if not self._spool_files() and self._send(alerts):
            self.sent += len(alerts)
            return
        self._spool(alerts)

    def _spool_files(self) -> list[Path]:
        try:
            return sorted(self.spool_dir.glob("alerts-*.jsonl"))
        except OSError:
            return []

    def _spool(self, alerts: list[dict]) -> None:
        try:
            self.spool_dir.mkdir(parents=True, exist_ok=True)
            self._seq += 1
            f = self.spool_dir / f"alerts-{time.time_ns():020d}-{self._seq:06d}.jsonl"
            tmp = f.with_suffix(".tmp")
            tmp.write_text("\n".join(json.dumps(a) for a in alerts), encoding="utf-8")
            tmp.replace(f)
            self.spooled += len(alerts)
            files = self._spool_files()
            total = sum(x.stat().st_size for x in files)
            while files and total > self.spool_max:                    # bounded disk: evict the oldest batch
                victim = files.pop(0)
                total -= victim.stat().st_size
                self.dropped += sum(1 for _ in victim.open("rb"))
                victim.unlink(missing_ok=True)
            print(f"[forwarder] API unreachable ({getattr(self, '_last_error', '?')}) -- {len(alerts)} alert(s) spooled to disk")
        except OSError as exc:
            self.dropped += len(alerts)
            print(f"[forwarder] POST {self.endpoint} failed and the spool is unwritable ({exc}) -- {len(alerts)} alert(s) dropped")

    def _replay(self) -> None:
        files = self._spool_files()
        if not files:
            return
        for f in files[:20]:
            try:
                alerts = [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
            except (OSError, ValueError):
                f.unlink(missing_ok=True)
                continue
            if not self._send(alerts):
                self._next_replay = time.monotonic() + 5.0             # API still down: back off
                return
            self.sent += len(alerts)
            self.replayed += len(alerts)
            f.unlink(missing_ok=True)
        self._next_replay = time.monotonic() + 0.5

    def stop(self) -> None:
        self._stop.set()
        self._t.join(timeout=3)


def make_forwarder() -> Optional[HttpAlertForwarder]:
    url = os.environ.get("STEALTHTAP_API_URL")
    return HttpAlertForwarder(url) if url else None
