#!/usr/bin/env python3
"""
Refresh the auto-generated status block in docs/PRIORITIES.md from a real
system check, and append one row to docs/reports/history.csv so trends
(throughput, accuracy, pass/fail counts) are visible over time.

The human-maintained priority list in docs/PRIORITIES.md is NEVER rewritten --
only the region between the AUTO-STATUS markers -- so a scheduled run cannot
clobber judgement calls. Anything a check flags as FAIL/WARN shows up in the
block automatically; promote it into the list by hand (or say so and it gets
added in the next review).

    python scripts/update_priorities.py            # run the quick system check, then update
    python scripts/update_priorities.py --full     # include the slow checks
    python scripts/update_priorities.py --no-run   # just re-render from docs/reports/LATEST.json

Schedule it (Windows, daily 07:00):
    schtasks /Create /SC DAILY /ST 07:00 /TN StealthTapCheck /TR "cmd /c cd /d <repo> && venv\\Scripts\\python scripts\\update_priorities.py"
Linux/macOS (cron):
    0 7 * * *  cd <repo> && venv/bin/python scripts/update_priorities.py
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRIO = ROOT / "docs" / "PRIORITIES.md"
LATEST = ROOT / "docs" / "reports" / "LATEST.json"
HISTORY = ROOT / "docs" / "reports" / "history.csv"
BEGIN, END = "<!-- AUTO-STATUS:BEGIN -->", "<!-- AUTO-STATUS:END -->"


def metric(results: list[dict], name_part: str, pattern: str, cast=float):
    for r in results:
        if name_part in r["name"]:
            m = re.search(pattern, r["detail"])
            if m:
                return cast(m.group(1).replace(",", ""))
    return None


def render(data: dict) -> tuple[str, dict]:
    res = data["results"]
    c = data["counts"]
    pps = metric(res, "live pipeline throughput", r"([\d,]+) pps", int)
    recall = metric(res, "real-traffic accuracy", r"recall=(\d+)%")
    fpr = metric(res, "real-traffic accuracy", r"flow-FPR=([\d.]+)%")
    tests = None
    for r in res:
        if r["name"].startswith("pytest"):
            m = re.search(r"(\d+) passed", r["detail"])
            tests = int(m.group(1)) if m else None
    bad = [r for r in res if r["status"] in ("FAIL", "WARN")]
    stamp = data["timestamp"]
    pretty = f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]} {stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}"
    lines = [
        BEGIN,
        f"_Last automated check: **{pretty}** · PASS {c['PASS']} · WARN {c['WARN']} · FAIL {c['FAIL']} "
        f"· tests {tests if tests is not None else '?'} · live pipeline {pps:,} pps · "
        f"hybrid recall {recall}% · flow FPR {fpr}%_" if pps and recall is not None and fpr is not None else
        f"_Last automated check: **{pretty}** · PASS {c['PASS']} · WARN {c['WARN']} · FAIL {c['FAIL']}_",
        "",
    ]
    if bad:
        lines += ["| status | section | check | detail |", "|---|---|---|---|"]
        for r in bad:
            lines.append(f"| {r['status']} | {r['section']} | {r['name']} | {r['detail'].replace('|', '/')[:200]} |")
    else:
        lines.append("No FAIL or WARN in the latest run.")
    lines += ["", f"Full report: `docs/reports/LATEST.md` (history: `docs/reports/history.csv`)", END]
    row = {"timestamp": stamp, "pass": c["PASS"], "warn": c["WARN"], "fail": c["FAIL"],
           "tests": tests, "pipeline_pps": pps, "hybrid_recall_pct": recall, "flow_fpr_pct": fpr}
    return "\n".join(lines), row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-run", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    if not a.no_run:
        cmd = [sys.executable, "scripts/system_check.py"] + ([] if a.full else ["--quick"])
        subprocess.run(cmd, cwd=ROOT)  # non-zero exit just means a check failed -- still worth recording
    data = json.loads(LATEST.read_text())
    block, row = render(data)
    text = PRIO.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        print(f"markers {BEGIN} / {END} not found in {PRIO}", file=sys.stderr)
        return 2
    new = re.sub(re.escape(BEGIN) + r".*?" + re.escape(END), block.replace("\\", "\\\\"), text, flags=re.S)
    PRIO.write_text(new, encoding="utf-8")
    new_file = not HISTORY.exists()
    with open(HISTORY, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(row))
        if new_file:
            w.writeheader()
        w.writerow(row)
    print(f"updated {PRIO.relative_to(ROOT)}: PASS {row['pass']} WARN {row['warn']} FAIL {row['fail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
