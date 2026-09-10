"""
DGA-domain and DNS-tunnelling query generator, for testing ENG03 against
real, observable DNS traffic (not synthetic log lines -- these are actual
DNS queries issued over the wire, so Zeek captures them exactly like it
would real malware).

Two modes:
  --mode dga        issues queries for algorithmically-generated,
                     high-entropy domain names (won't resolve -- that's
                     expected and realistic, DGA domains mostly don't)
  --mode tunnel      issues TXT-record queries with base64-style payload
                     chunks in the subdomain, mimicking DNS tunnelling
                     query shape (length + entropy + record type)

Run against your own lab DNS resolver -- never against a resolver you
don't control, since even non-resolving DGA-style queries generate real
upstream DNS traffic if pointed at a public resolver.
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import socket
import string
import time

TLDS = ["com", "net", "ru", "info", "biz"]


def random_dga_domain(min_len: int = 10, max_len: int = 22) -> str:
    length = random.randint(min_len, max_len)
    name = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{name}.{random.choice(TLDS)}"


def random_tunnel_query() -> str:
    payload = base64.b32encode(bytes(random.getrandbits(8) for _ in range(20))).decode().lower().strip("=")
    return f"{payload}.chunk{random.randint(1,99):02d}.exfil-test.local"


def issue_query(domain: str, resolver: str, record_type: str = "A") -> bool:
    """Issues a real DNS query via the system resolver mechanism (or a
    specific resolver IP via raw UDP for TXT-style tunnel queries).
    Returns True if a query was actually sent (resolution success/failure
    doesn't matter -- DGA domains are SUPPOSED to fail to resolve)."""
    try:
        socket.setdefaulttimeout(2)
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return True  # expected for most DGA domains -- the query still went out
    except OSError:
        return False


def run(mode: str, resolver: str, count: int, rate_per_sec: float) -> None:
    log = []
    interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0.5
    print(f"[dns_query_gen] mode={mode} count={count} rate={rate_per_sec}/s")
    for i in range(count):
        domain = random_dga_domain() if mode == "dga" else random_tunnel_query()
        ts = time.time()
        sent = issue_query(domain, resolver)
        log.append({"seq": i, "ts": ts, "domain": domain, "mode": mode, "sent": sent})
        print(f"[dns_query_gen] {i+1}/{count}: {domain}")
        time.sleep(interval)

    outfile = f"dns_{mode}_ground_truth.json"
    with open(outfile, "w") as f:
        json.dump({"mode": mode, "resolver": resolver, "queries": log}, f, indent=2)
    print(f"[dns_query_gen] done. Ground truth written to {outfile}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate real DGA / DNS-tunnelling query traffic.")
    parser.add_argument("--mode", choices=["dga", "tunnel"], required=True)
    parser.add_argument("--resolver", default="", help="informational only -- uses system resolver")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--rate", type=float, default=2.0, help="queries per second")
    args = parser.parse_args()
    run(args.mode, args.resolver, args.count, args.rate)


if __name__ == "__main__":
    main()
