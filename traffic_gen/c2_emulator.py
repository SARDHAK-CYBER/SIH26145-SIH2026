"""
Benign C2 beacon emulator, for testing ENG02 (C2 beaconing) and ENG04
(encrypted malware / JA4 anomaly) against realistic-looking traffic
patterns.

IMPORTANT: this has NO actual command-and-control capability. The
"server" never sends back anything except a fixed acknowledgment, and the
"client" never executes anything it receives. It exists purely to
generate the network PATTERN a real C2 beacon produces (periodic
check-ins with jitter, small consistent payload sizes) so the detection
pipeline can be tested against it -- exactly the same idea as your own
README's "Sandboxed C2 emulator, jittered check-ins, real-time replay"
description. Run both ends inside your own lab network, never against a
host you don't control.

Usage:
    python3 c2_emulator.py server --port 4444
    python3 c2_emulator.py client --target 127.0.0.1 --port 4444 \
        --interval 30 --jitter 2 --count 40
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import threading
import time
from datetime import datetime, timezone


def run_server(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    print(f"[c2_emulator:server] listening on 0.0.0.0:{port}")
    checkins = 0
    while True:
        conn, addr = srv.accept()
        with conn:
            data = conn.recv(1024)
            checkins += 1
            conn.sendall(b'{"status":"ack"}')  # fixed, harmless response -- never executed by anything
            print(f"[c2_emulator:server] check-in #{checkins} from {addr[0]}:{addr[1]}, {len(data)} bytes")


def run_client(target: str, port: int, interval: float, jitter: float, count: int) -> None:
    print(f"[c2_emulator:client] beaconing to {target}:{port} every ~{interval}s (jitter ±{jitter}s), {count} check-ins")
    log = []
    for i in range(count):
        ts_sent = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((target, port))
                payload = json.dumps({"beacon_id": i, "ts": ts_sent}).encode()
                sock.sendall(payload)
                sock.recv(1024)
            print(f"[c2_emulator:client] check-in {i+1}/{count} sent at "
                  f"{datetime.fromtimestamp(ts_sent, tz=timezone.utc).isoformat()}")
            log.append({"seq": i, "ts": ts_sent})
        except OSError as exc:
            print(f"[c2_emulator:client] check-in {i+1} failed: {exc}")
        sleep_for = max(0.1, interval + random.uniform(-jitter, jitter))
        time.sleep(sleep_for)

    with open("c2_emulator_ground_truth.json", "w") as f:
        json.dump({"target": target, "port": port, "interval": interval, "jitter": jitter, "checkins": log}, f, indent=2)
    print(f"[c2_emulator:client] done. Ground truth log written to c2_emulator_ground_truth.json "
          f"-- feed this into benchmark_harness.py to measure detection latency against real alerts.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benign C2 beacon pattern emulator (no real C2 capability).")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_server = sub.add_parser("server")
    p_server.add_argument("--port", type=int, default=4444)

    p_client = sub.add_parser("client")
    p_client.add_argument("--target", required=True)
    p_client.add_argument("--port", type=int, default=4444)
    p_client.add_argument("--interval", type=float, default=30.0, help="seconds between check-ins")
    p_client.add_argument("--jitter", type=float, default=2.0, help="+/- random seconds added to interval")
    p_client.add_argument("--count", type=int, default=40, help="matches eng02's WINDOW_SIZE=32 buffer requirement")

    args = parser.parse_args()
    if args.mode == "server":
        run_server(args.port)
    else:
        run_client(args.target, args.port, args.interval, args.jitter, args.count)


if __name__ == "__main__":
    main()
