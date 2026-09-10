#!/usr/bin/env python3
"""
Run a pcap through the full StealthTap detection pipeline LOCALLY -- no
Docker, no Postgres, no Redis, no OpenSearch. Uses the pure-Python scapy
parser + every rule engine + whatever ONNX models are in models/.

    python scripts/analyze_local.py samples/simulated_attack_traffic.pcap
    python scripts/analyze_local.py my.pcap --json > alerts.json

This is the "can I see it work right now" path. The Docker stack
(docker compose up) adds real Zeek/ICSNPP parsing, Suricata's 20k
signatures, YARA file scanning, and alert persistence -- none of which
this offline runner does.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class _NoRedis:
    """Stands in for a Redis client when none is running. Every engine
    already treats Redis errors as 'fail open', so the stateful checks
    (flood rate, beacon history, low-and-slow exfil) simply don't
    contribute -- the per-record rule + ML checks all still run."""
    def __getattr__(self, _name):
        def _raise(*_a, **_k):
            raise RuntimeError("no redis (offline runner)")
        return _raise
    def pipeline(self):
        return self


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("pcap")
    p.add_argument("--json", action="store_true", help="print the full alert list as JSON")
    args = p.parse_args()

    if not Path(args.pcap).is_file():
        raise SystemExit(f"no such file: {args.pcap}")

    from pcap_parser import parse_pcap
    from src.api.pcap_analysis import _run_engines
    try:
        from src.inference.model_server import HybridModelServer
        model_server = HybridModelServer()
    except Exception as exc:
        print(f"[analyze_local] ML disabled ({exc}) -- rule engines only")
        model_server = None

    t0 = time.time()
    parsed = parse_pcap(args.pcap)
    parse_s = time.time() - t0
    print(f"[parse] {parse_s:.2f}s  " + "  ".join(f"{k}={len(v)}" for k, v in parsed.items()))

    t0 = time.time()
    alerts, coverage = asyncio.new_event_loop().run_until_complete(
        _run_engines(parsed, model_server, _NoRedis())
    )
    detect_s = time.time() - t0

    print(f"\n[detect] {detect_s:.2f}s   {len(alerts)} alert(s)")
    print("\nby threat class:")
    for cls, n in Counter(a["threat_class"] for a in alerts).most_common():
        print(f"  {n:4d}  {cls}")
    print("\nby detection mode:")
    for mode, n in Counter(a["detection_mode"] for a in alerts).most_common():
        print(f"  {n:4d}  {mode}")
    print("\nper-engine coverage (records processed / alerts fired):")
    for name, c in coverage.items():
        if c["records_processed"] or c["alerts_fired"]:
            print(f"  {name:14s} {c['records_processed']:6d} / {c['alerts_fired']}")

    if args.json:
        print("\n" + json.dumps(alerts, indent=2))


if __name__ == "__main__":
    main()
