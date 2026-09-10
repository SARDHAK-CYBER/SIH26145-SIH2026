"""
Zeek log shipper.

Reads newly-appended lines from Zeek's JSON-formatted log files
(conn.log, dns.log, ssl.log, modbus.log) and publishes each record onto
the matching Redpanda topic. This is the piece that makes the streaming
path actually work.

Zeek itself never touches the network by design (see
scripts/setup_netns.sh -- it runs with zero IP in the "capture"
namespace) and doesn't speak Kafka. This process is the deliberate
opposite: it never touches a raw packet, only reads already-parsed JSON
log lines off a shared read-only volume, and its only network activity
is producing to Redpanda on the normal Docker network.

This is the resolution to the earlier design gap where streaming_engine.py
was documented as needing to run inside the IP-less capture namespace --
it doesn't, and never should have. Only the packet-sniffing process needs
to be air-gapped.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from aiokafka import AIOKafkaProducer

LOG_DIR = Path(os.environ.get("ZEEK_LOG_DIR", "logs/pcap_run"))
BROKER = os.environ.get("REDPANDA_BROKER", "redpanda:9092")
POLL_INTERVAL_SECONDS = float(os.environ.get("SHIPPER_POLL_INTERVAL", "1.0"))

# Zeek log filename -> Redpanda topic. Keep in sync with streaming_engine.py.
# Covers every log type the streaming engines consume, so live-path
# coverage matches the upload path (ENG09/HTTP, ENG11/Kerberos, ENG12/BZAR
# were previously unreachable live because their logs were never shipped).
LOG_TOPIC_MAP = {
    "conn.log": "stealthtap.flows.conn",
    "dns.log": "stealthtap.flows.dns",
    "ssl.log": "stealthtap.flows.ssl",
    "modbus.log": "stealthtap.flows.modbus",
    "http.log": "stealthtap.flows.http",
    "kerberos.log": "stealthtap.flows.kerberos",
    "notice.log": "stealthtap.flows.notice",
}


class LogTailer:
    """Tracks a byte offset per file and yields only newly-appended,
    complete lines. Handles the file not existing yet, and does a
    best-effort restart-from-top if the file shrinks (likely rotation)."""

    def __init__(self, path: Path):
        self.path = path
        self._offset = 0

    def read_new_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        size = self.path.stat().st_size
        if size < self._offset:
            self._offset = 0  # file shrank -- likely rotated/truncated
        lines: list[str] = []
        with open(self.path, "r") as f:
            f.seek(self._offset)
            for line in f:
                if line.endswith("\n"):
                    stripped = line.strip()
                    if stripped:
                        lines.append(stripped)
                    self._offset = f.tell()
                # else: partial line at EOF -- wait for the rest next poll
        return lines


async def ship_logs() -> None:
    producer = AIOKafkaProducer(
        bootstrap_servers=BROKER,
        value_serializer=lambda v: json.dumps(v).encode(),
    )
    await producer.start()
    print(f"[log_shipper] connected to Redpanda at {BROKER}")

    tailers = {name: LogTailer(LOG_DIR / name) for name in LOG_TOPIC_MAP}
    print(f"[log_shipper] tailing {LOG_DIR} for {list(LOG_TOPIC_MAP)}")

    shipped = 0
    try:
        while True:
            for name, tailer in tailers.items():
                topic = LOG_TOPIC_MAP[name]
                for line in tailer.read_new_lines():
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    await producer.send_and_wait(topic, record)
                    shipped += 1
                    if shipped % 100 == 0:
                        print(f"[log_shipper] shipped {shipped} records so far")
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(ship_logs())
