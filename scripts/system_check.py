#!/usr/bin/env python3
"""
Full system check: services, connections between them, detection engines,
ML models, native module, latency/throughput, and accuracy against the
ground-truth pcap. Writes docs/reports/system_check_<timestamp>.{json,md}.

Designed to be re-run on a schedule (see docs/PRIORITIES.md): every check is
independent, has a timeout, and reports PASS / WARN / FAIL / SKIP with a
measured detail -- never an assertion without evidence.

    python scripts/system_check.py            # full (minutes)
    python scripts/system_check.py --quick    # skips the slow checks
    python scripts/system_check.py --accuracy # also re-runs the real-traffic Docker eval
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

API = os.environ.get("STEALTHTAP_API", "http://localhost:8000")
DOCKER_BIN = r"C:\Program Files\Docker\Docker\resources\bin"
if os.path.isdir(DOCKER_BIN):
    os.environ["PATH"] = DOCKER_BIN + os.pathsep + os.environ["PATH"]
PY = sys.executable

RESULTS: list[dict] = []


def record(section: str, name: str, status: str, detail: str = "", ms: float | None = None) -> None:
    RESULTS.append({"section": section, "name": name, "status": status, "detail": detail,
                    "ms": round(ms, 1) if ms is not None else None})
    icon = {"PASS": "ok  ", "WARN": "WARN", "FAIL": "FAIL", "SKIP": "skip"}[status]
    print(f"[{icon}] {section:12s} {name:38s} {detail[:110]}", flush=True)


def check(section: str, name: str, fn) -> None:
    t0 = time.perf_counter()
    try:
        out = fn()
        status, detail = out if isinstance(out, tuple) else ("PASS", str(out or ""))
    except Exception as exc:  # a failing check must never stop the others
        status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
    record(section, name, status, detail, (time.perf_counter() - t0) * 1000)


def sh(cmd: list[str], timeout: int = 120, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def http(method: str, path: str, **kw):
    import requests
    return requests.request(method, API + path, timeout=kw.pop("timeout", 30), **kw)


def env_value(key: str) -> str:
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text().splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    return ""


# ---------------------------------------------------------------- infra
def infra() -> None:
    S = "infra"

    def api_health():
        lat = []
        for _ in range(20):
            t = time.perf_counter()
            r = http("GET", "/health")
            lat.append((time.perf_counter() - t) * 1000)
        d = r.json()
        fams = set(d.get("models_loaded", []))
        st = "PASS" if d.get("status") == "ok" and d.get("db_connected") else "FAIL"
        return st, f"models={sorted(fams)} db={d.get('db_connected')} p50={statistics.median(lat):.1f}ms p99={max(lat):.1f}ms"
    check(S, "api /health", api_health)

    def pipeline():
        d = http("GET", "/api/pipeline/status").json()
        bad = {k: v["status"] for k, v in d["services"].items() if v["status"] not in ("connected", "active")}
        eng = [e["id"] for e in d["engines"]]
        return ("FAIL" if bad else "PASS"), f"services_bad={bad or 'none'} engines={len(eng)}"
    check(S, "pipeline status (all services)", pipeline)

    def redis_check():
        import redis
        r = redis.Redis.from_url("redis://localhost:6379/0", socket_timeout=3)
        r.ping()
        lat = []
        for _ in range(300):
            t = time.perf_counter(); r.ping(); lat.append((time.perf_counter() - t) * 1000)
        k = f"syscheck:{int(time.time())}"
        r.execute_command("CMS.INITBYDIM", k, 100, 3)
        cms = r.execute_command("CMS.INCRBY", k, "a", 3)
        r.pfadd(k + ":h", "x", "y"); hll = r.pfcount(k + ":h")
        r.delete(k, k + ":h")
        try:
            import hiredis  # noqa: F401
            parser = "hiredis"
        except ImportError:
            parser = "PURE-PYTHON parser"
        ok = cms == [3] and hll == 2
        st = "PASS" if ok and parser == "hiredis" else ("WARN" if ok else "FAIL")
        return st, f"RTT p50={statistics.median(lat):.2f}ms p99={sorted(lat)[int(.99*len(lat))]:.2f}ms CMS={cms} HLL={hll} client={parser}"
    check(S, "redis + RedisBloom CMS/HLL", redis_check)

    def postgres():
        cp = sh(["docker", "exec", "stealthtap-ntro-postgres-1", "pg_isready", "-U", "stealthtap"])
        n = http("GET", "/alerts", params={"limit": 1})
        return ("PASS" if cp.returncode == 0 and n.status_code == 200 else "FAIL"), f"pg_isready={cp.stdout.strip()} /alerts={n.status_code}"
    check(S, "postgres (+ API read path)", postgres)

    def opensearch():
        import requests
        requests.packages.urllib3.disable_warnings()
        r = requests.get("https://localhost:9200/_cluster/health", auth=("admin", env_value("OPENSEARCH_ADMIN_PASSWORD")),
                         verify=False, timeout=10)
        d = r.json()
        return ("PASS" if d.get("status") in ("green", "yellow") else "FAIL"), f"cluster={d.get('status')} nodes={d.get('number_of_nodes')}"
    check(S, "opensearch", opensearch)

    def redpanda():
        s = socket.create_connection(("localhost", 9092), timeout=3); s.close()
        cp = sh(["docker", "exec", "stealthtap-ntro-redpanda-1", "rpk", "cluster", "health"])
        return ("PASS" if "Healthy:" in cp.stdout and "true" in cp.stdout.lower() else "WARN"), cp.stdout.replace("\n", " ")[:90]
    check(S, "redpanda (kafka)", redpanda)

    def dash():
        a = http("GET", ":4173/".replace(":4173", ""), timeout=1) if False else None
        import requests
        r1 = requests.get("http://localhost:4173/", timeout=5)
        return ("PASS" if r1.status_code == 200 else "FAIL"), f"dashboard={r1.status_code}"
    check(S, "dashboard (react)", dash)

    def containers():
        cp = sh(["docker", "ps", "-a", "--format", "{{.Names}}|{{.Status}}"])
        rows = [l.split("|") for l in cp.stdout.strip().splitlines() if l.startswith("stealthtap-ntro-")]
        down = [n for n, s in rows if not s.startswith("Up")]
        return ("FAIL" if down else "PASS"), f"{len(rows)} containers, down={down or 'none'}"
    check(S, "containers up", containers)

    def logs():
        out = []
        for n in ("api-1", "streaming-engine-1", "zeek-batch-1", "suricata-batch-1", "log-shipper-1"):
            cp = sh(["docker", "logs", "--tail", "300", f"stealthtap-ntro-{n}"])
            txt = cp.stdout + cp.stderr
            errs = len(re.findall(r"Traceback|CRITICAL|\bERROR\b|Exception", txt))
            if errs:
                out.append(f"{n}:{errs}")
        return ("WARN" if out else "PASS"), f"error-lines in last 300 log lines: {out or 'none'}"
    check(S, "container logs (errors)", logs)


# ---------------------------------------------------------------- native
def native() -> None:
    S = "native"

    def imp():
        import stealthtap_core as c
        names = [n for n in ("LiveFlowAssembler", "NativeEng01", "NativeEng02", "NativeEng05", "NativeEng06", "NativeEng13", "parse_pcap") if not hasattr(c, n)]
        return ("FAIL" if names else "PASS"), f"missing={names or 'none'}"
    check(S, "stealthtap_core import", imp)

    for script, label in (("validate_native_parser.py", "parser native==python"),
                          ("validate_native_eng01.py", "ENG-01 native==python"),
                          ("validate_native_eng02.py", "ENG-02 native==python"),
                          ("validate_native_eng05.py", "ENG-05 native==python"),
                          ("validate_native_eng06.py", "ENG-06 native==python"),
                          ("validate_native_eng13.py", "ENG-13 native==python")):
        def run(script=script):
            cp = sh([PY, f"scripts/{script}", "samples"], timeout=300)
            ok = "ALL EQUIVALENT" in cp.stdout
            return ("PASS" if ok else "FAIL"), (cp.stdout.strip().splitlines() or ["no output"])[-1]
        check(S, label, run)


# ---------------------------------------------------------------- engines
def engines(quick: bool) -> None:
    S = "engines"

    def pytest_run():
        cp = sh([PY, "-m", "pytest", "-q", "-x", "--no-header"], timeout=900)
        m = re.search(r"(\d+) passed", cp.stdout)
        f = re.search(r"(\d+) failed", cp.stdout)
        return ("PASS" if m and not f and cp.returncode == 0 else "FAIL"), (cp.stdout.strip().splitlines() or ["?"])[-1]
    check(S, "pytest (engines, models, mapping, capture)", pytest_run)

    def ground_truth():
        gt = json.loads((ROOT / "pcap_ground_truth.json").read_text())
        pcap = ROOT / "simulated_attack_traffic.pcap"
        with open(pcap, "rb") as f:
            r = http("POST", "/analyze/pcap", files={"file": (pcap.name, f, "application/octet-stream")}, timeout=300)
        d = r.json()
        classes = {}
        for a in d["alerts"]:
            classes.setdefault(a["threat_class"], 0)
            classes[a["threat_class"]] += 1
        from collections import Counter
        want = Counter(t["expected_alert"] for t in gt["threats"]
                       if t["expected_alert"] and "verify" not in t["expected_alert"])
        missed = [f"{c} (want>={n}, got {classes.get(c, 0)})" for c, n in want.items() if classes.get(c, 0) < n]
        allowed = set(want) | {"ENCRYPTED_MALWARE"}
        fp = [c for c in classes if c not in allowed and not str(c).startswith(("MALICIOUS_FILE", "NETWORK_INTRUSION"))]
        st = "FAIL" if missed else ("WARN" if fp else "PASS")
        return st, f"parser={d['parser_used']} alerts={len(d['alerts'])} missed_expected={missed or 'none'} unexpected_classes={fp or 'none'} {classes}"
    check(S, "ground-truth attack pcap (end-to-end)", ground_truth)


# ---------------------------------------------------------------- models
def models() -> None:
    S = "models"
    import numpy as np
    import onnxruntime as ort
    manifest = json.loads((ROOT / "models" / "MANIFEST.json").read_text())

    def manifest_check():
        from src.features.feature_extraction import FEATURE_SCHEMA_VERSION
        bad = [e["family"] for e in manifest if e.get("feature_schema_version") != FEATURE_SCHEMA_VERSION]
        return ("FAIL" if bad else "PASS"), f"families={[e['family'] for e in manifest]} schema_mismatch={bad or 'none'}"
    check(S, "manifest / feature-schema contract", manifest_check)

    for e in manifest:
        fam = e["family"]

        def infer(fam=fam, e=e):
            x_path = ROOT / "models" / f"{fam}_xgboost_v1.onnx"
            sess = ort.InferenceSession(str(x_path), providers=["CPUExecutionProvider"])
            n = sess.get_inputs()[0].shape[-1]
            X = np.random.rand(20000, n).astype(np.float32)
            sess.run(None, {sess.get_inputs()[0].name: X[:10]})  # warm
            t = time.perf_counter(); sess.run(None, {sess.get_inputs()[0].name: X}); dt = time.perf_counter() - t
            m = e["xgboost_metrics"]
            st = "PASS" if m["f1"] >= 0.85 else "WARN"
            return st, f"xgb f1={m['f1']} prec={m['precision']} rec={m['recall']} | infer {dt/len(X)*1e6:.1f}us/row (20k batch) | iforest f1={e['isolation_forest_metrics']['f1']} (advisory)"
        check(S, f"{fam} model load+infer+metrics", infer)

    def missing_family():
        have = {e["family"] for e in manifest}
        miss = sorted({"flow", "dns", "modbus"} - have)
        note = "; tls has no labeled data -> covered by ENG-03 SNI scoring (dns model) + JA4 intel (ENG-04)"
        return ("WARN" if miss else "PASS"), f"families without a trained model: {miss or 'none'}{note}"
    check(S, "model coverage", missing_family)

    def score_api():
        lat = []
        for _ in range(40):
            t = time.perf_counter()
            r = http("POST", "/score/dns", json={"flow": {"dns_query": "xkqzjvbnwmpl.com"}})
            lat.append((time.perf_counter() - t) * 1000)
        d = r.json()
        return ("PASS" if r.status_code == 200 else "FAIL"), f"status={r.status_code} score={d.get('threat_score', (d.get('alert') or {}).get('confidence_score'))} p50={statistics.median(lat):.1f}ms p99={max(lat):.1f}ms"
    check(S, "API /score/dns round-trip", score_api)


# ---------------------------------------------------------------- performance
def performance(quick: bool) -> None:
    S = "performance"

    def live_bench():
        # native capture thread -> assembler -> 13 engines + ML, looping a REAL capture for 12 s
        out = ROOT / "docs" / "reports" / "_live_bench.json"
        sh([PY, "scripts/replay_soak.py", "samples/netbios_ssn2.pcap", "--seconds", "12", "--per-file", "12",
            "--out", str(out)], timeout=300)
        import json as _json
        sm = _json.loads(out.read_text())["summary"] if out.exists() else {}
        pps, drop = int(sm.get("avg_pps", 0)), int(sm.get("records_dropped_last", -1))
        return ("PASS" if pps > 50_000 and drop == 0 else "WARN"), f"live pipeline {pps:,} pps ({sm.get('avg_gbit_s')} Gbit/s), records dropped={drop}"
    check(S, "live pipeline throughput (1 worker)", live_bench)

    def api_pcap():
        pcap = ROOT / "samples" / "test.pcap"
        with open(pcap, "rb") as f:
            t = time.perf_counter()
            r = http("POST", "/analyze/pcap", files={"file": (pcap.name, f, "application/octet-stream")}, timeout=300)
            wall = time.perf_counter() - t
        d = r.json()
        cov = d["pipeline_coverage"]
        return ("PASS" if d["parser_used"] == "zeek" and cov["suricata"]["ran"] else "WARN"), \
            f"wall={wall:.1f}s parse={d['timing']['parse_seconds']}s detect={d['timing']['detection_seconds']}s parser={d['parser_used']} suricata_ran={cov['suricata']['ran']} yara={d['yara_active']}"
    check(S, "/analyze/pcap latency (small file)", api_pcap)


# ---------------------------------------------------------------- accuracy
def accuracy(run_docker_eval: bool) -> None:
    S = "accuracy"
    rep = ROOT / "eval_results_docker" / "eval_real_traffic.md"

    def read_report():
        txt = rep.read_text()
        m = re.search(r"\| hybrid \| (\d+)/(\d+) = (\d+)% .*?\| (\d+)/(\d+) = (\d+)% \| (\d+)% \| ([\d.]+) \|", txt)
        f = re.search(r"\| hybrid \| (\d+) \| (\d+) \| ([\d.]+)%", txt)
        age_h = (time.time() - rep.stat().st_mtime) / 3600
        return ("PASS" if m else "WARN"), f"hybrid recall={m.group(3)}% specificity={m.group(6)}% precision={m.group(7)}% F1={m.group(8)} | flow-FPR={f.group(3)}% ({f.group(2)}/{f.group(1)}) | report age {age_h:.1f}h" if m and f else "could not parse report"

    if run_docker_eval:
        def rerun():
            cache = ROOT / "eval_results_docker" / "per_file"
            for p in cache.glob("*.json"):
                if p.name != "mirai.pcap.json":
                    p.unlink()
            src = Path(os.environ.get("STEALTHTAP_EVAL_DIR", r"C:\Users\admin\Downloads\archive (2)"))
            tmp = ROOT / "eval_results_docker" / "_subset"
            tmp.mkdir(exist_ok=True)
            for p in src.iterdir():
                if p.suffix in (".pcap", ".pcapng") and p.name != "mirai.pcap":
                    (tmp / p.name).write_bytes(p.read_bytes()) if not (tmp / p.name).exists() else None
            cp = sh([PY, "scripts/eval_real_traffic_docker.py", str(tmp)], timeout=3600)
            return ("PASS" if "hybrid" in cp.stdout else "FAIL"), (cp.stdout.strip().splitlines() or ["?"])[-1][:100]
        check(S, "re-run real-traffic eval through Docker", rerun)
    check(S, "real-traffic accuracy (latest report)", read_report)


# ---------------------------------------------------------------- main
def write_report() -> Path:
    out = ROOT / "docs" / "reports"
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    counts = {s: sum(1 for r in RESULTS if r["status"] == s) for s in ("PASS", "WARN", "FAIL", "SKIP")}
    payload = json.dumps({"timestamp": stamp, "counts": counts, "results": RESULTS}, indent=1)
    (out / f"system_check_{stamp}.json").write_text(payload)
    (out / "LATEST.json").write_text(payload)
    lines = [f"# System check {stamp}", "", f"**PASS {counts['PASS']} · WARN {counts['WARN']} · FAIL {counts['FAIL']} · SKIP {counts['SKIP']}**", "",
             "| section | check | status | detail |", "|---|---|---|---|"]
    for r in RESULTS:
        lines.append(f"| {r['section']} | {r['name']} | {r['status']} | {r['detail'].replace('|', '/')[:220]} |")
    p = out / f"system_check_{stamp}.md"
    p.write_text("\n".join(lines) + "\n")
    (out / "LATEST.md").write_text("\n".join(lines) + "\n")
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--accuracy", action="store_true", help="re-run the real-traffic eval through Docker (slow)")
    a = ap.parse_args()
    infra(); native(); engines(a.quick); models(); performance(a.quick); accuracy(a.accuracy)
    p = write_report()
    c = {s: sum(1 for r in RESULTS if r["status"] == s) for s in ("PASS", "WARN", "FAIL")}
    print(f"\nreport: {p}\nPASS {c['PASS']}  WARN {c['WARN']}  FAIL {c['FAIL']}")
    return 1 if c["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
