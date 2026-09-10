"""
One-way alert relay.

This process is the ONLY thing that crosses the isolation boundary set
up by scripts/setup_netns.sh -- there is deliberately no veth pair
between the "capture" and "soc" namespaces. Every record is validated
against the Alert schema before being forwarded; anything malformed,
or containing a field the schema doesn't recognize, is dropped rather
than passed on. That's the actual security control here, not the
Unix socket transport itself.

STATUS: sink now writes to OpenSearch via OpenSearchStorage.index_alert.
Run this on the "soc" side, where OpenSearch is actually reachable.
"""
from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

from pydantic import ValidationError

from src.alert_schema import Alert
from src.storage.opensearch_client import OpenSearchStorage

SOCKET_PATH = Path(os.environ.get("RELAY_SOCKET", "/var/run/stealthtap/alerts.sock"))


def validate_and_forward(raw: bytes, sink) -> bool:
    try:
        alert = Alert.model_validate_json(raw)
    except ValidationError as exc:
        print(f"[relay] rejected malformed alert: {exc}", file=sys.stderr)
        return False
    sink(alert)
    return True


def make_opensearch_sink(storage: OpenSearchStorage):
    def _sink(alert: Alert) -> None:
        try:
            storage.index_alert(alert)
            print(f"[relay] indexed alert {alert.alert_id} ({alert.threat_class})")
        except Exception as exc:
            # A storage outage should never crash the relay's accept loop --
            # log and drop rather than block on a queue that could
            # back-pressure into the isolation boundary.
            print(f"[relay] failed to index alert {alert.alert_id}: {exc}", file=sys.stderr)
    return _sink


def main() -> None:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    # Host/port/password are read from the environment -- see the updated
    # OpenSearchStorage, which now requires OPENSEARCH_ADMIN_PASSWORD rather
    # than hardcoding a literal that could silently drift from docker-compose's
    # .env-supplied value.
    storage = OpenSearchStorage(
        host=os.environ.get("OPENSEARCH_HOST", "localhost"),
        port=int(os.environ.get("OPENSEARCH_PORT", "9200")),
    )
    sink = make_opensearch_sink(storage)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(str(SOCKET_PATH))
        srv.listen(8)
        print(f"[relay] listening on {SOCKET_PATH}")
        while True:
            conn, _ = srv.accept()
            with conn:
                raw = conn.recv(65536)
                if raw:
                    validate_and_forward(raw, sink=sink)


if __name__ == "__main__":
    main()
