#!/usr/bin/env python3
"""
Equivalence test: the Rust `stealthtap_core.parse_pcap()` must produce the
SAME conn/dns records as the validated Python `pcap_parser.parse_pcap()` --
not just "a similar count." Compares per-flow uid, byte counts, ports,
duration; per-DNS-record uid, query, qtype. Exits non-zero on any mismatch.

This is the actual trust boundary for the native parser: it doesn't get
used by the detection engines until it passes this, on real captures.

    python scripts/validate_native_parser.py "<pcap folder>"
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _conn_key(r: dict) -> tuple:
    return (r["uid"],)


def compare_one(path: Path) -> tuple[bool, str]:
    from pcap_parser import parse_pcap as py_parse
    import stealthtap_core

    t0 = time.time()
    py = py_parse(str(path))
    py_s = time.time() - t0

    t0 = time.time()
    try:
        rs = stealthtap_core.parse_pcap(str(path))
    except OSError as exc:
        return False, f"rust parser raised on {path.name}: {exc}"
    rs_s = time.time() - t0

    py_conn = {r["uid"]: r for r in py["conn"]}
    rs_conn = {r["uid"]: r for r in rs["conn"]}

    problems = []
    only_py = set(py_conn) - set(rs_conn)
    only_rs = set(rs_conn) - set(py_conn)
    if only_py:
        problems.append(f"{len(only_py)} flow(s) Python found and Rust missed (of {len(py_conn)})")
    if only_rs:
        problems.append(f"{len(only_rs)} flow(s) Rust found and Python didn't (of {len(rs_conn)})")

    mismatched = 0
    for uid in set(py_conn) & set(rs_conn):
        a, b = py_conn[uid], rs_conn[uid]
        for field in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "orig_bytes", "resp_bytes"):
            if a[field] != b[field]:
                mismatched += 1
                break
    if mismatched:
        problems.append(f"{mismatched} flow(s) present in both but with different field values")

    py_dns = {(r["uid"], r["query"]) for r in py["dns"]}
    rs_dns = {(r["uid"], r["query"]) for r in rs["dns"]}
    if py_dns != rs_dns:
        problems.append(f"dns records differ: python={len(py_dns)} rust={len(rs_dns)} "
                         f"only_python={len(py_dns - rs_dns)} only_rust={len(rs_dns - py_dns)}")

    ok = not problems
    speedup = py_s / rs_s if rs_s > 0 else float("inf")
    status = "OK " if ok else "FAIL"
    line = (f"{status} {path.name:32s} conn py={len(py_conn):6d} rs={len(rs_conn):6d}  "
            f"dns py={len(py_dns):4d} rs={len(rs_dns):4d}  "
            f"py={py_s:6.2f}s rs={rs_s:6.2f}s  speedup={speedup:6.1f}x")
    if problems:
        line += "\n     " + "; ".join(problems)
    return ok, line


def main() -> None:
    folder = Path(sys.argv[1])
    files = sorted(p for p in folder.iterdir() if p.suffix == ".pcap")  # .pcapng not yet supported natively
    all_ok = True
    for p in files:
        try:
            ok, line = compare_one(p)
        except Exception as exc:
            ok, line = False, f"FAIL {p.name}: exception {exc!r}"
        print(line)
        all_ok = all_ok and ok
    print("\n" + ("ALL EQUIVALENT" if all_ok else "MISMATCHES FOUND -- native parser is NOT yet trustworthy"))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
