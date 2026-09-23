#!/usr/bin/env python3
"""
Equivalence test for the native ENG-01 fast-path (stealthtap_core.NativeEng01)
against src/engines/eng01_ddos.py's Redis/MemoryStore-backed reference --
same trust-before-use bar as every other native module in this project
(see native/README.md).

Replays every conn record from a real capture through BOTH implementations
identically -- same flow order, same fields -- and compares every alert
(threat_class, confidence, evidence) exactly.

    python scripts/validate_native_eng01.py "<pcap folder>"
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def compare_one(path: Path) -> tuple[bool, str]:
    from pcap_parser import parse_pcap
    from src.memstore import MemoryStore
    from src.engines.eng01_ddos import VolumetricDDoSDetector
    import stealthtap_core

    parsed = parse_pcap(str(path))
    conn_records = parsed.get("conn", [])
    if not conn_records:
        return None, "SKIP (no conn records)"

    py_eng = VolumetricDDoSDetector(redis_client=MemoryStore())
    py_eng._native = None  # force the Redis/MemoryStore reference path
    native_eng = VolumetricDDoSDetector(redis_client=MemoryStore())
    assert native_eng._native is not None, "native module not available -- nothing to validate"

    async def run(eng):
        out = []
        for rec in conn_records:
            flow = {
                "flow_uid": rec.get("uid", "unknown"), "ts": rec.get("ts", 0.0),
                "src_ip": rec.get("id.orig_h", ""), "src_port": rec.get("id.orig_p", 0),
                "dst_ip": rec.get("id.resp_h", ""), "dst_port": rec.get("id.resp_p", 0),
                "proto": (rec.get("proto") or "tcp").upper(),
                "duration_s": rec.get("duration", 0.0),
                "orig_bytes": rec.get("orig_bytes", 0), "resp_bytes": rec.get("resp_bytes", 0),
                "segment_hash": rec.get("segment_hash", ""),
            }
            alert = await eng.score(flow)
            if alert is not None:
                out.append((alert.threat_class, round(alert.confidence_score, 1), dict(alert.evidence)))
        return out

    py_alerts = asyncio.run(run(py_eng))
    native_alerts = asyncio.run(run(native_eng))

    if py_alerts != native_alerts:
        msg = [f"MISMATCH {path.name}: {len(py_alerts)} python alerts vs {len(native_alerts)} native alerts"]
        for i, (p, n) in enumerate(zip(py_alerts, native_alerts)):
            if p != n:
                msg.append(f"  [{i}] python={p}")
                msg.append(f"  [{i}] native={n}")
        if len(py_alerts) != len(native_alerts):
            longer = py_alerts if len(py_alerts) > len(native_alerts) else native_alerts
            label = "python" if len(py_alerts) > len(native_alerts) else "native"
            for i in range(min(len(py_alerts), len(native_alerts)), len(longer)):
                msg.append(f"  [{i}] {label}-only={longer[i]}")
        return False, "\n".join(msg)

    return True, f"OK   {path.name:35s} conn={len(conn_records):6d} eng01_alerts={len(py_alerts)}"


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    folder = Path(sys.argv[1])
    files = sorted(p for p in folder.iterdir() if p.suffix in (".pcap", ".pcapng"))
    if not files:
        print(f"no .pcap/.pcapng files in {folder}")
        sys.exit(1)

    ok_count, fail_count, skip_count = 0, 0, 0
    for f in files:
        try:
            ok, msg = compare_one(f)
        except Exception as exc:
            print(f"ERROR {f.name}: {exc}")
            fail_count += 1
            continue
        print(msg)
        if ok is None:
            skip_count += 1
        elif ok:
            ok_count += 1
        else:
            fail_count += 1

    print()
    if fail_count == 0:
        print(f"ALL EQUIVALENT ({ok_count} compared, {skip_count} skipped)")
    else:
        print(f"MISMATCHES FOUND: {fail_count} of {ok_count + fail_count}")
        sys.exit(1)


if __name__ == "__main__":
    main()
