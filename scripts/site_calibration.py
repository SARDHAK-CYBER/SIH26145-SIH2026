"""
Site calibration / false-positive triage: replay captures from a site (or any set of real captures) through the full live
pipeline and report WHICH alerts fire and WHY, grouped so that a false-positive pattern shows up as one row instead of a
thousand alerts.

    python scripts/site_calibration.py <pcap files or folders> [--name mysite] [--recursive] [--allowlist-out allowlist.suggested.json]

What it produces (docs/reports/site_calibration_<name>.{json,md}):
  * flows / packets / alerts per capture and alerts per 1,000 flows
  * alert GROUPS: (threat class, detection mode, destination port, evidence signature) with count, number of captures/hosts
    affected and one example -- the unit an analyst triages
  * a SUGGESTED allowlist (never applied automatically): one entry per group, each needing a human decision. Entries use the
    format of src/allowlist.py, so accepted ones can be pasted into config/allowlist.json.

Only classic pcap files are replayed (the native replay engine); pcapng files are counted and skipped.
Run this on the first day of a deployment (a few hours of capture from the real segment), triage the groups, allowlist what is
verified benign, and keep the rest as real findings.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import src  # noqa: E402,F401
from src.capture.live_agent import LiveAgent  # noqa: E402

CLASSIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}


def collect(paths: list[str], recursive: bool) -> tuple[list[Path], int]:
    files, skipped = [], 0
    for p in map(Path, paths):
        cands = [p] if p.is_file() else sorted(p.rglob("*") if recursive else p.glob("*"))
        for f in cands:
            if not f.is_file() or f.suffix.lower() not in (".pcap", ".cap", ".pcapng") or f.stat().st_size < 64:
                continue
            with f.open("rb") as fh:
                magic = fh.read(4)
            if magic in CLASSIC:
                files.append(f)
            else:
                skipped += 1
    return files, skipped


def signature(a: dict) -> tuple:
    """What makes two alerts 'the same kind of thing' for triage: class, mode, service port, and the discriminating evidence."""
    ev = a.get("evidence", {}) or {}
    disc = ev.get("detection_type") or ev.get("why") or ev.get("finding") or ev.get("function_code") or ev.get("service") \
        or (ev.get("method") and "http_request") or ev.get("protocol") or ""
    return (a["threat_class"], a.get("detection_mode", "rule"), int(a["flow_identifier"]["dst_port"]), str(disc)[:48])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--name", default="site")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--allowlist-out", default=None)
    a = ap.parse_args()

    files, skipped = collect(a.paths, a.recursive)
    print(f"{len(files)} classic pcap files to replay ({skipped} pcapng skipped)")
    rows, groups = [], collections.defaultdict(lambda: {"count": 0, "files": set(), "srcs": set(), "dsts": set(), "example": None})
    class_totals: collections.Counter = collections.Counter()
    t0 = time.time()
    for i, f in enumerate(files, 1):
        try:
            agent = LiveAgent("pcap-replay", None)
            agent.start_replay(str(f), loops=1, speed=0.0)
            agent._loop_thread.join()
            st = agent.status()
            alerts = agent.recent_alerts(5000)
            cap = st["capture"]
            agent.stop()
        except Exception as exc:                        # one unreadable capture must not end the survey
            rows.append({"file": str(f), "error": f"{type(exc).__name__}: {exc}"})
            continue
        for al in alerts:
            g = groups[signature(al)]
            g["count"] += 1
            g["files"].add(f.name)
            g["srcs"].add(al["flow_identifier"]["src_ip"])
            g["dsts"].add(al["flow_identifier"]["dst_ip"])
            g["example"] = g["example"] or {"file": f.name, "flow": al["flow_identifier"], "severity": al["severity"],
                                              "confidence": al["confidence_score"], "evidence": {k: v for k, v in (al.get("evidence") or {}).items()
                                                                                                  if not isinstance(v, (list, dict))}}
            class_totals[al["threat_class"]] += 1
        rows.append({"file": str(f), "packets": cap["recv"], "flows": cap["flows_seen"], "alerts": len(alerts)})
        if i % 50 == 0:
            print(f"  {i}/{len(files)} ({time.time() - t0:.0f}s)", flush=True)

    ok = [r for r in rows if "error" not in r]
    flows, alerts_n = sum(r["flows"] for r in ok), sum(r["alerts"] for r in ok)
    out_groups = sorted(({"threat_class": k[0], "detection_mode": k[1], "dst_port": k[2], "signature": k[3], "alerts": v["count"],
                          "captures": len(v["files"]), "src_hosts": len(v["srcs"]), "dst_hosts": len(v["dsts"]), "example": v["example"]}
                         for k, v in groups.items()), key=lambda g: -g["alerts"])
    summary = {"name": a.name, "captures_replayed": len(ok), "captures_failed": len(rows) - len(ok), "pcapng_skipped": skipped,
               "flows": flows, "alerts": alerts_n, "alerts_per_1000_flows": round(1000 * alerts_n / max(1, flows), 2),
               "captures_with_alerts": sum(1 for r in ok if r["alerts"]), "alerts_by_class": dict(class_totals.most_common())}
    Path("docs/reports").mkdir(parents=True, exist_ok=True)
    Path(f"docs/reports/site_calibration_{a.name}.json").write_text(json.dumps({"summary": summary, "groups": out_groups, "captures": rows}, indent=1))

    md = [f"# Site calibration: {a.name}", "", f"{summary['captures_replayed']} captures, {flows:,} flows, **{alerts_n} alerts "
          f"({summary['alerts_per_1000_flows']} per 1,000 flows)**; alerts by class: {summary['alerts_by_class']}", "",
          "| # | class | mode | dst port | signature | alerts | captures | src / dst hosts |", "|---|---|---|---|---|---:|---:|---|"]
    for n, g in enumerate(out_groups[:40], 1):
        md.append(f"| {n} | {g['threat_class']} | {g['detection_mode']} | {g['dst_port']} | {g['signature']} | {g['alerts']} | {g['captures']} | {g['src_hosts']} / {g['dst_hosts']} |")
    Path(f"docs/reports/site_calibration_{a.name}.md").write_text("\n".join(md) + "\n")

    if a.allowlist_out:
        sug = [{"reason": "TRIAGE REQUIRED -- delete this entry unless verified benign", "threat_class": g["threat_class"], "dst_port": g["dst_port"],
                "match_count_in_survey": g["alerts"], "enabled": False} for g in out_groups]
        Path(a.allowlist_out).write_text(json.dumps({"rules": sug}, indent=1))
    print(json.dumps(summary, indent=1))
    for g in out_groups[:15]:
        print(f"{g['alerts']:>6} alerts  {g['captures']:>3} captures  {g['threat_class']:<34} {g['detection_mode']:<6} port {g['dst_port']:<6} {g['signature']}")


if __name__ == "__main__":
    main()
