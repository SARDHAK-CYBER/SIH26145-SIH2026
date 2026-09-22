#!/usr/bin/env python3
"""
Equivalence test for the LIVE-capture path's native flow assembler
(stealthtap_core.LiveFlowAssembler) against src/capture/flow_assembler.py's
pure-Python FlowAssembler -- the same trust-before-use bar applied to the
upload-path parser (scripts/validate_native_parser.py).

Replays each real capture's packets through BOTH assemblers identically:
process() per packet, snapshot() partway through, expire() at intervals,
flush() at the end -- comparing every immediate record (dns/ssl/modbus/
dnp3) and every conn record's fields.

SCOPE NOTE: the native live assembler assumes Ethernet-framed input
(genuinely true for real NIC capture -- Npcap and AF_PACKET both hand
Ethernet frames), unlike the upload-path parser which also understands
Linux-cooked-capture. Pcap files captured with a different linktype (e.g.
0day.pcap, tcpdump on "any") are not representative of live-capture's real
input and are skipped here, reported explicitly, not silently.

    python scripts/validate_native_live_assembler.py "<pcap folder>"
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SNAPSHOT_EVERY = 500   # packets between snapshot() calls, mirrors live_agent.py's cadence
EXPIRE_EVERY = 2000


def compare_one(path: Path) -> tuple[bool | None, str]:
    from scapy.all import PcapReader, Ether
    import stealthtap_core
    from src.capture.flow_assembler import FlowAssembler

    # Peek the link type via the same 24-byte global header stealthtap_core reads.
    with open(path, "rb") as f:
        hdr = f.read(24)
    if len(hdr) < 24:
        return None, f"SKIP {path.name}: too short to be a pcap"
    import struct
    magic = struct.unpack("<I", hdr[:4])[0]
    le = magic in (0xa1b2c3d4, 0xa1b23c4d)
    linktype = struct.unpack("<I" if le else ">I", hdr[20:24])[0]
    if linktype != 1:  # LINKTYPE_ETHERNET
        return None, f"SKIP {path.name}: linktype={linktype} (not Ethernet -- not representative of live NIC capture)"

    py_asm = FlowAssembler(idle_timeout_s=60.0)
    rs_asm = stealthtap_core.LiveFlowAssembler(60.0)

    py_immediate: list[tuple[str, dict]] = []
    rs_immediate: list[tuple[str, dict]] = []
    py_conn: dict[str, dict] = {}
    rs_conn: dict[str, dict] = {}

    def merge_conn(store: dict, items):
        for log_type, rec in items:
            if log_type == "conn":
                store[rec["uid"]] = rec  # last write wins, matches "current cumulative state" semantics

    t0 = time.time()
    n = 0
    with PcapReader(str(path)) as rd:
        for pkt in rd:
            n += 1
            ts = float(getattr(pkt, "time", 0.0) or 0.0)
            raw = bytes(pkt)

            for item in py_asm.process(pkt):
                if item[0] == "conn":
                    continue
                py_immediate.append(item)
            for log_type, rec in rs_asm.process(ts, raw):
                if log_type == "conn":
                    continue
                rs_immediate.append((log_type, rec))

            if n % SNAPSHOT_EVERY == 0:
                merge_conn(py_conn, py_asm.snapshot())
                merge_conn(rs_conn, rs_asm.snapshot(4000))
            if n % EXPIRE_EVERY == 0:
                merge_conn(py_conn, py_asm.expire(now=ts + 9999))  # force-expire deterministically by packet time, not wall clock
                merge_conn(rs_conn, rs_asm.expire(ts + 9999))

    merge_conn(py_conn, py_asm.flush())
    merge_conn(rs_conn, rs_asm.flush())
    dt = time.time() - t0

    problems = []

    def imm_key(log_type, rec):
        if log_type == "dns":
            return (log_type, rec["uid"], rec["query"])
        if log_type == "ssl":
            return (log_type, rec["uid"], rec["ja4"])
        if log_type == "modbus":
            return (log_type, rec["uid"], rec["func"], rec["register"])
        if log_type == "dnp3":
            return (log_type, rec["uid"], rec["fc_request"])
        return (log_type, rec.get("uid"))

    py_imm_keys = sorted(imm_key(*i) for i in py_immediate)
    rs_imm_keys = sorted(imm_key(*i) for i in rs_immediate)
    if py_imm_keys != rs_imm_keys:
        only_py = set(py_imm_keys) - set(rs_imm_keys)
        only_rs = set(rs_imm_keys) - set(py_imm_keys)
        problems.append(f"immediate records differ: py={len(py_imm_keys)} rs={len(rs_imm_keys)} "
                         f"only_py={len(only_py)} only_rs={len(only_rs)}"
                         + (f" e.g. py-only={list(only_py)[:2]}" if only_py else "")
                         + (f" e.g. rs-only={list(only_rs)[:2]}" if only_rs else ""))

    only_py_conn = set(py_conn) - set(rs_conn)
    only_rs_conn = set(rs_conn) - set(py_conn)
    if only_py_conn:
        problems.append(f"{len(only_py_conn)} conn flow(s) python found and rust missed")
    if only_rs_conn:
        problems.append(f"{len(only_rs_conn)} conn flow(s) rust found and python missed")
    mismatched = 0
    for uid in set(py_conn) & set(rs_conn):
        a, b = py_conn[uid], rs_conn[uid]
        for field in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
            if a[field] != b[field]:
                mismatched += 1
                if mismatched <= 2:
                    problems.append(f"conn {uid} field {field}: py={a[field]} rs={b[field]}")
                break

    ok = not problems
    status = "OK  " if ok else "FAIL"
    line = f"{status} {path.name:32s} packets={n:7d} conn py={len(py_conn):5d} rs={len(rs_conn):5d} time={dt:.2f}s"
    if problems:
        line += "\n     " + "\n     ".join(problems)
    return ok, line


def main() -> None:
    folder = Path(sys.argv[1])
    files = sorted(p for p in folder.iterdir() if p.suffix == ".pcap")
    all_ok = True
    skipped = 0
    for p in files:
        try:
            ok, line = compare_one(p)
        except Exception as exc:
            ok, line = False, f"FAIL {p.name}: exception {exc!r}"
        print(line)
        if ok is None:
            skipped += 1
        else:
            all_ok = all_ok and ok
    print(f"\n{'ALL EQUIVALENT' if all_ok else 'MISMATCHES FOUND'} ({skipped} file(s) skipped -- non-Ethernet linktype)")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
