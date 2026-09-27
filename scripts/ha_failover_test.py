"""
Proves the API tier survives losing a replica, and that alerts reach the PostgreSQL standby. Needs the HA profile running:

    STEALTHTAP_API_UPSTREAMS="api:8000 api2:8000" docker compose --profile ha up -d
    python scripts/ha_failover_test.py [--ca path/to/caddy_root.crt]

1. ingests an alert through the TLS proxy and finds it on the standby (replication lag),
2. polls an authenticated API route through the proxy every 0.25 s while it stops each API replica in turn (and starts it again),
   counting failed requests and the longest gap -- the user-visible cost of a replica loss.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
import uuid

import requests

DOCKER = r"C:\Program Files\Docker\Docker\resources\bin\docker.exe" if os.name == "nt" else "docker"


def dc(*args: str) -> str:
    return subprocess.run([DOCKER, "compose", "--profile", "ha", *args], capture_output=True, text=True, timeout=120).stdout.strip()


def env_value(key: str) -> str:
    for line in open(".env", encoding="utf-8"):
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ca", default=os.path.join(os.environ.get("TEMP", "/tmp"), "caddy_root.crt"))
    ap.add_argument("--api", default="https://localhost:8443")
    a = ap.parse_args()
    S = requests.Session()
    S.verify = a.ca
    S.headers["X-API-Key"] = env_value("STEALTHTAP_API_KEY")
    ok = True

    # 1. replication
    aid = "ha-" + uuid.uuid4().hex[:10]
    alert = {"alert_id": aid, "timestamp": time.time(), "severity": "LOW", "confidence_score": 50.0, "threat_class": "RECONNAISSANCE",
             "flow_identifier": {"src_ip": "10.9.9.1", "src_port": 1, "dst_ip": "10.9.9.2", "dst_port": 2, "protocol": "TCP"},
             "mitre_attack": {"tactic": "Discovery", "technique_id": "T1046", "technique_name": "x"}, "evidence": {}, "forensics": {}}
    r = S.post(a.api + "/alerts/ingest", json=[alert], timeout=30)
    t0 = time.time()
    on_standby = None
    while time.time() - t0 < 10:
        out = dc("exec", "-T", "postgres-replica", "psql", "-U", "stealthtap", "-d", "stealthtap", "-Atc", f"select count(*) from alerts where alert_id='{aid}'")
        if out == "1":
            on_standby = time.time() - t0
            break
        time.sleep(0.2)
    print(f"[{'ok' if r.ok and on_standby is not None else 'FAIL'}] alert ingested ({r.status_code}) and visible on the standby after "
          f"{on_standby if on_standby is None else round(on_standby, 2)} s")
    ok &= bool(r.ok and on_standby is not None)

    # 2. replica loss under continuous load
    stats = {"n": 0, "fail": 0, "last_ok": time.time(), "max_gap": 0.0}
    stop = threading.Event()

    def poll():
        while not stop.is_set():
            try:
                good = S.get(a.api + "/alerts?limit=1", timeout=8).status_code == 200
            except requests.RequestException:
                good = False
            now = time.time()
            stats["n"] += 1
            if good:
                stats["max_gap"] = max(stats["max_gap"], now - stats["last_ok"])
                stats["last_ok"] = now
            else:
                stats["fail"] += 1
            time.sleep(0.25)

    th = threading.Thread(target=poll, daemon=True)
    th.start()
    time.sleep(5)
    for victim in ("api", "api2"):
        base_fail = stats["fail"]
        dc("stop", victim)
        print(f"  stopped {victim}: polling continues ...")
        time.sleep(14)
        print(f"  while {victim} was down: {stats['fail'] - base_fail} failed requests so far")
        dc("start", victim)
        time.sleep(12)
    stop.set()
    th.join(timeout=15)
    good = stats["n"] - stats["fail"]
    verdict = stats["fail"] <= max(3, stats["n"] * 0.03)
    print(f"[{'ok' if verdict else 'FAIL'}] {stats['n']} requests through the proxy while each API replica was stopped in turn: "
          f"{good} succeeded, {stats['fail']} failed, longest gap between successes {stats['max_gap']:.1f} s")
    ok &= verdict
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
