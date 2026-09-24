#!/usr/bin/env python3
"""
Same evaluation as scripts/eval_real_traffic.py, but through the REAL
Docker stack's /analyze/pcap endpoint instead of the in-process parser
-- i.e. real Zeek + real Suricata (20,829 ET Open rules) + real YARA,
not just the rule engines + ONNX models. This is what
eval_real_traffic.py's own docstring flags as a known limitation
("no Zeek/Suricata here") and what docs/PRD.md §8 item 4 has been
carrying as an open item.

Reuses eval_real_traffic.py's scoring/report logic exactly (same
BENIGN/UNLABELLED sets, same CONFIGS, same Wilson CI, same report
format) so the two reports are directly comparable -- only the
ingestion path (real Docker pipeline vs. in-process parser) differs.

    python scripts/eval_real_traffic_docker.py "C:/path/to/pcaps" --out eval_results_docker
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.eval_real_traffic import BENIGN, UNLABELLED, CONFIGS, report  # noqa: E402

API_URL = "http://localhost:8000/analyze/pcap"
TIMEOUT_S = 600.0  # mirai.pcap (93.8MB) needs longer than 300s even running alone


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_file(path: Path) -> dict:
    t0 = time.time()
    with open(path, "rb") as f:
        resp = requests.post(API_URL, files={"file": (path.name, f, "application/octet-stream")}, timeout=TIMEOUT_S)
    wall_s = time.time() - t0
    resp.raise_for_status()
    d = resp.json()
    return {
        "file": path.name,
        "flows": d["packet_summary"]["conn_flows"],
        "dns": d["packet_summary"]["dns_queries"],
        "ssl": d["packet_summary"]["tls_sessions"],
        "parse_s": d["timing"]["parse_seconds"],
        "detect_s": d["timing"]["detection_seconds"],
        "wall_s": round(wall_s, 2),
        "parser_used": d["parser_used"],
        "suricata_ran": d["pipeline_coverage"]["suricata"]["ran"],
        "suricata_alert_count": d["suricata_alert_count"],
        "yara_active": d["yara_active"],
        "alerts": d["alerts"],
        "coverage": d["pipeline_coverage"],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap_dir")
    ap.add_argument("--out", default="eval_results_docker")
    ap.add_argument("--only", default=None, help="run a single file name (debug)")
    ap.add_argument("--reuse", action="store_true", help="reuse cached per-file results")
    args = ap.parse_args()

    out = ROOT / args.out
    (out / "per_file").mkdir(parents=True, exist_ok=True)

    try:
        requests.get("http://localhost:8000/health", timeout=5).raise_for_status()
    except Exception as exc:
        print(f"[eval] Docker API not reachable at {API_URL}: {exc}")
        sys.exit(1)

    files = sorted(p for p in Path(args.pcap_dir).iterdir() if p.suffix in (".pcap", ".pcapng"))
    if args.only:
        files = [p for p in files if p.name == args.only]

    seen: dict[str, str] = {}
    results = []
    zeek_ran, suricata_ran = 0, 0
    for p in files:
        digest = sha256(p)
        if digest in seen:
            print(f"[skip] {p.name}: byte-identical duplicate of {seen[digest]}")
            continue
        seen[digest] = p.name
        cache = out / "per_file" / f"{p.name}.json"
        if args.reuse and cache.exists():
            r = json.loads(cache.read_text())
        else:
            print(f"[run ] {p.name} ({p.stat().st_size / 1e6:.1f} MB) ...", flush=True)
            try:
                r = run_file(p)
            except Exception as exc:
                print(f"       ERROR: {exc}")
                continue
            r["sha256"] = digest
            cache.write_text(json.dumps(r))
        n = len(r["alerts"])
        zeek_ran += r["parser_used"] == "zeek"
        suricata_ran += bool(r["suricata_ran"])
        print(f"       parser={r['parser_used']:14s} suricata_ran={str(r['suricata_ran']):5s} "
              f"suricata_alerts={r['suricata_alert_count']:3d} yara={str(r['yara_active']):5s} "
              f"flows={r['flows']:>6} alerts={n:>4} wall={r['wall_s']}s", flush=True)
        results.append(r)

    print(f"\n[eval] Zeek actually ran on {zeek_ran}/{len(results)} files, "
          f"Suricata job accepted on {suricata_ran}/{len(results)} files")
    if zeek_ran < len(results):
        print("[eval] WARNING: some files fell back to the scapy parser -- Docker path "
              "wasn't used for those, results aren't fully comparable for them")

    report(results, out)


if __name__ == "__main__":
    main()
