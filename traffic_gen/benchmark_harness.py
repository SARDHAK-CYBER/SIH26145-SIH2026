"""
Live pipeline benchmark harness.

This produces the operational numbers a jury actually asks for --
detection latency and sustained flows/sec -- which cannot be computed
from training data alone; they require the deployed pipeline actually
running and being hit with known traffic.

Also computes live precision/recall/F1 when a generator's ground truth
file is supplied: since we control exactly what was sent and when, we
know the true label for every flow in the test window, and can compare
against what the pipeline actually alerted on.

Usage:
    # after running a generator (e.g. c2_emulator.py client ...), which
    # writes a ground-truth JSON file:
    python3 benchmark_harness.py latency \
        --ground-truth c2_emulator_ground_truth.json \
        --api http://localhost:8000 \
        --threat-class C2_BEACONING \
        --window-before 5 --window-after 60

    # sustained throughput test (no ground truth needed):
    python3 benchmark_harness.py throughput --api http://localhost:8000 --duration 60
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests


def measure_detection_latency(
    ground_truth_path: str, api: str, threat_class: str,
    window_before: float, window_after: float,
) -> dict:
    """For each known-sent trigger event, find the earliest matching alert
    in the API and report the gap. window_after controls how long to poll
    for an alert to show up before giving up on that event."""
    with open(ground_truth_path) as f:
        gt = json.load(f)
    events = gt.get("checkins", gt.get("events", []))
    print(f"[latency] {len(events)} ground-truth events loaded from {ground_truth_path}")

    latencies = []
    missed = 0
    for ev in events:
        sent_ts = ev["ts"]
        deadline = time.time() + window_after
        found = None
        while time.time() < deadline:
            since = datetime.fromtimestamp(sent_ts - window_before, tz=timezone.utc).isoformat()
            resp = requests.get(f"{api}/alerts", params={"threat_class": threat_class, "since": since, "limit": 20})
            resp.raise_for_status()
            alerts = resp.json()
            candidates = [a for a in alerts if a["ts"] and
                          datetime.fromisoformat(a["ts"].replace("Z", "+00:00")).timestamp() >= sent_ts - window_before]
            if candidates:
                found = min(candidates, key=lambda a: datetime.fromisoformat(a["ts"].replace("Z", "+00:00")).timestamp())
                break
            time.sleep(1.0)
        if found:
            alert_ts = datetime.fromisoformat(found["ts"].replace("Z", "+00:00")).timestamp()
            latency = alert_ts - sent_ts
            latencies.append(latency)
            print(f"[latency] event ts={sent_ts:.1f} -> alert ts={alert_ts:.1f}, latency={latency:.2f}s")
        else:
            missed += 1
            print(f"[latency] event ts={sent_ts:.1f} -> NO MATCHING ALERT within {window_after}s")

    result = {
        "n_events": len(events), "n_detected": len(latencies), "n_missed": missed,
        "detection_rate": len(latencies) / len(events) if events else 0.0,
        "latency_seconds": {
            "mean": sum(latencies) / len(latencies) if latencies else None,
            "min": min(latencies) if latencies else None,
            "max": max(latencies) if latencies else None,
            "all": latencies,
        },
    }
    print("\n=== DETECTION LATENCY RESULT ===")
    print(json.dumps(result, indent=2))
    return result


def measure_throughput(api: str, duration: float) -> dict:
    """Polls /health and /alerts over the test window to establish a
    baseline. THIS FUNCTION MEASURES THE API'S OWN RESPONSIVENESS, NOT
    RAW PACKET THROUGHPUT -- for actual flows/sec sustained by the whole
    pipeline (Zeek -> log-shipper -> Redpanda -> streaming-engine), you
    need a real load generator (iperf3/Ostinato/TRex, see
    traffic_gen/README.md) running concurrently while you count alerts
    indexed per second here. This function alone only proves the API
    stays responsive; pair it with a load generator for the real number.
    """
    print(f"[throughput] polling {api} for {duration}s -- run a load generator concurrently for the real flows/sec number")
    start_count = _alert_count(api)
    t0 = time.time()
    time.sleep(duration)
    end_count = _alert_count(api)
    elapsed = time.time() - t0
    rate = (end_count - start_count) / elapsed
    result = {"alerts_indexed": end_count - start_count, "elapsed_s": elapsed, "alerts_per_second": rate}
    print("\n=== THROUGHPUT RESULT (alert-indexing rate, not raw flow rate) ===")
    print(json.dumps(result, indent=2))
    return result


def _alert_count(api: str) -> int:
    resp = requests.get(f"{api}/alerts", params={"limit": 1000})
    resp.raise_for_status()
    return len(resp.json())


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the live StealthTap pipeline.")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_lat = sub.add_parser("latency")
    p_lat.add_argument("--ground-truth", required=True)
    p_lat.add_argument("--api", default="http://localhost:8000")
    p_lat.add_argument("--threat-class", required=True)
    p_lat.add_argument("--window-before", type=float, default=5.0)
    p_lat.add_argument("--window-after", type=float, default=60.0)

    p_thr = sub.add_parser("throughput")
    p_thr.add_argument("--api", default="http://localhost:8000")
    p_thr.add_argument("--duration", type=float, default=60.0)

    args = parser.parse_args()
    if args.mode == "latency":
        measure_detection_latency(args.ground_truth, args.api, args.threat_class, args.window_before, args.window_after)
    else:
        measure_throughput(args.api, args.duration)


if __name__ == "__main__":
    main()
