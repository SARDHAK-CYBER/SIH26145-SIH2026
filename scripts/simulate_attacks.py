import os
import json
import time
import random

# Fixed seed so the generated fixtures are reproducible run to run --
# useful for demos and for anyone re-running this to verify engine behavior.
random.seed(42)


def generate_simulation_logs():
    log_dir = "logs/pcap_run"
    os.makedirs(log_dir, exist_ok=True)

    current_ts = time.time()
    conn_records = []

    # ------------------------------------------------------------------
    # 1a. Volumetric DDoS burst (ENG-01)
    # eng01's flood check is a per-source flow count within a 10s bucket.
    # All these share `current_ts`, so they land in the same bucket
    # (bucket id is derived from the flow's own ts, not wall-clock time
    # at processing, so this works regardless of how long generation +
    # processing takes).
    # ------------------------------------------------------------------
    for i in range(220):
        conn_records.append({
            "uid": f"C_DDOS_{i:04d}",
            "ts": current_ts,
            "id.orig_h": "192.168.100.50",
            "id.orig_p": 40000 + i,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 80,
            "proto": "tcp",
            "duration": 0.05,
            "orig_bytes": 300,
            "resp_bytes": 40,
        })

    # ------------------------------------------------------------------
    # 1b. Slowloris (ENG-01, existing behavior, kept as-is)
    # ------------------------------------------------------------------
    conn_records.append({
        "uid": "C_SLOWLORIS_01", "ts": current_ts,
        "id.orig_h": "192.168.100.51", "id.orig_p": 45999,
        "id.resp_h": "10.0.0.5", "id.resp_p": 80, "proto": "tcp",
        "duration": 150.0, "orig_bytes": 20, "resp_bytes": 0,
    })

    # ------------------------------------------------------------------
    # 2. C2 beaconing (ENG-02)
    # Needs >=32 buffered inter-arrival times for the same
    # (src_ip, dst_ip, dst_port, proto) key before it evaluates anything.
    # Generate 40 flows at a near-constant 30s interval, ending at
    # current_ts, so real elapsed time doesn't matter -- only the
    # relative spacing embedded in `ts` does.
    # ------------------------------------------------------------------
    BEACON_INTERVAL = 30.0
    BEACON_COUNT = 40
    beacon_start = current_ts - BEACON_INTERVAL * BEACON_COUNT
    for i in range(BEACON_COUNT):
        jitter = random.uniform(-0.5, 0.5)  # small jitter, still clearly periodic
        conn_records.append({
            "uid": f"C_C2_{i:03d}",
            "ts": beacon_start + i * BEACON_INTERVAL + jitter,
            "id.orig_h": "192.168.100.30",
            "id.orig_p": 51000 + (i % 5),
            "id.resp_h": "203.0.113.99",
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": 0.2,
            "orig_bytes": 250,
            "resp_bytes": 180,
        })

    # ------------------------------------------------------------------
    # 3. Reconnaissance (ENG-05)
    # Threshold is 25 distinct (dst_ip, dst_port) pairs within a 300s
    # window from one source. Generate 30 to clear it with margin.
    # ------------------------------------------------------------------
    for i in range(30):
        conn_records.append({
            "uid": f"C_RECON_{i:03d}",
            "ts": current_ts,
            "id.orig_h": "192.168.100.99",
            "id.orig_p": 52310 + i,
            "id.resp_h": "10.0.0.10",
            "id.resp_p": 1000 + i,
            "proto": "tcp",
            "duration": 0.05,
            "orig_bytes": 60,
            "resp_bytes": 0,
        })

    # ------------------------------------------------------------------
    # 4. Data exfiltration (ENG-06) -- unchanged, already passes
    # ------------------------------------------------------------------
    conn_records.append({
        "uid": "C_EXFIL_01", "ts": current_ts,
        "id.orig_h": "192.168.100.15", "id.orig_p": 61200,
        "id.resp_h": "203.0.113.50", "id.resp_p": 443, "proto": "tcp",
        "duration": 120.0, "orig_bytes": 85000000, "resp_bytes": 1200,
    })

    with open(f"{log_dir}/conn.log", "w") as f:
        for r in conn_records:
            f.write(json.dumps(r) + "\n")

    # ------------------------------------------------------------------
    # 5. DGA & DNS tunnelling (ENG-03) -- unchanged, tunnelling branch
    # already passes; the DGA-CNN branch is separately flagged as
    # unreliable pending trained model weights (not a test-data issue).
    # ------------------------------------------------------------------
    dns_records = [
        {"uid": "D_DGA_01", "ts": current_ts, "id.orig_h": "192.168.100.20", "id.orig_p": 54321, "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp", "query": "xkjdhf9834kjhdfuytr9834hjfdiu.ru", "qtype_name": "A"},
        {"uid": "D_TUNNEL_01", "ts": current_ts, "id.orig_h": "192.168.100.20", "id.orig_p": 54322, "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp", "query": "aG9tZWNvbnRyb2xsZXJhdHRhY2tzZWFsdGh0YXAuc2VjdXJlLmNvbQ==", "qtype_name": "TXT"},
    ]
    with open(f"{log_dir}/dns.log", "w") as f:
        for r in dns_records:
            f.write(json.dumps(r) + "\n")

    # ------------------------------------------------------------------
    # 6. Encrypted malware / JA4 (ENG-04)
    # FIX: previous fixture's JA4 didn't match any hash in the detector's
    # hardcoded allow-list, so ENG-04 never fired and its schema bug
    # (see eng04_encrypted_malware.py) stayed hidden. Now uses a hash
    # taken directly from that allow-list.
    # ------------------------------------------------------------------
    ssl_records = [
        {"uid": "S_MALWARE_01", "ts": current_ts, "id.orig_h": "192.168.100.25", "id.orig_p": 58900, "id.resp_h": "198.51.100.45", "id.resp_p": 443, "proto": "tcp", "ja4": "t13d1516h2_8daaf6152771_026612f520fd"},
    ]
    with open(f"{log_dir}/ssl.log", "w") as f:
        for r in ssl_records:
            f.write(json.dumps(r) + "\n")

    # ------------------------------------------------------------------
    # 7. Unauthorized OT/ICS command (ENG-07) -- unchanged, already passes
    # ------------------------------------------------------------------
    modbus_records = [
        {"uid": "M_OT_01", "ts": current_ts, "id.orig_h": "192.168.200.10", "id.orig_p": 44818, "id.resp_h": "192.168.200.50", "id.resp_p": 502, "proto": "tcp", "func_name": "WRITE_SINGLE_REGISTER", "register": 40001},
    ]
    with open(f"{log_dir}/modbus.log", "w") as f:
        for r in modbus_records:
            f.write(json.dumps(r) + "\n")

    print("[+] Synthetic attack logs generated successfully in logs/pcap_run/")
    print(f"    conn.log: {len(conn_records)} records (DDoS burst, Slowloris, "
          f"{BEACON_COUNT}-flow beacon sequence, 30-target recon, exfil)")
    print("    dns.log:  2 records (DGA, DNS tunnelling)")
    print("    ssl.log:  1 record (JA4 match against ENG-04's allow-list)")
    print("    modbus.log: 1 record (unauthorized write)")


if __name__ == "__main__":
    generate_simulation_logs()
