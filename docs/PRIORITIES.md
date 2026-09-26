# StealthTap — Priority list (living document)

How this file works:

* The **status block** below is regenerated from a real system check by
  `python scripts/update_priorities.py` (it never touches anything outside the
  markers). Every FAIL/WARN a check raises appears there automatically.
* The **priority list** is maintained by hand and reviewed on each update: an
  item moves to *Done* only with a linked measurement or test, never on
  assertion. New FAIL/WARN rows in the status block get promoted into the list.
* Trend data (pass/warn/fail, pipeline pps, hybrid recall, flow FPR) accumulates in
  `docs/reports/history.csv`; the full latest report is `docs/reports/LATEST.md`.
* Schedule the refresh: Windows `schtasks /Create /SC DAILY /ST 07:00 /TN StealthTapCheck /TR "cmd /c cd /d <repo> && venv\Scripts\python scripts\update_priorities.py"`;
  Linux/macOS cron `0 7 * * * cd <repo> && venv/bin/python scripts/update_priorities.py`.

## Automated status

<!-- AUTO-STATUS:BEGIN -->
_Last automated check: **2026-09-26 22:50:05** · PASS 27 · WARN 0 · FAIL 0 · tests 148 · live pipeline 364,413 pps · hybrid recall 83.0% · flow FPR 0.167%_

No FAIL or WARN in the latest run.

Full report: `docs/reports/LATEST.md` (history: `docs/reports/history.csv`)
<!-- AUTO-STATUS:END -->

## P0 — blockers for a live deployment

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | One large upload froze the whole API (`/health` included) | **Done** | Heavy stages moved off the event loop, concurrency cap + 429 backpressure, 600 s deadline, async job endpoints, Suricata size-skip. `mirai.pcap` (93.8 MB, 565k flows): was a >10-minute freeze → **HTTP 200 in 33 s**, worst `/health` during it 58 ms. `tests/test_api_availability.py` |
| 2 | Docker image had no native Rust module (every upload ran pure-Python engines against Redis) | **Done** | Multi-stage `Dockerfile` builds the wheel; verified `stealthtap_core` + `hiredis` inside the API container; ENG-01 runs native there |
| 3 | Live capture ceiling ≈ 10k pps (scapy dissection, 100 µs/packet) | **Done** | Raw-frame ingestion (`RawFrame`, `iter_raw_pcap`, `raw_sink` on all backends): **6,467 → ~45k pps end-to-end** through final flush (raw feed alone 408k pps), identical unique detections (7 = 7). `tests/test_raw_ingest.py`. Real-NIC `ScapyBackend` raw loop not yet validated on live Wi-Fi (open) |
| 4 | Updates not pushed / images stale | **Done** 2026-09-26 | Images rebuilt from HEAD, full `system_check --accuracy`: 27 PASS / 0 WARN / 0 FAIL; pushed to `origin/main` |

## P1 — accuracy, latency, false positives

| # | Item | Status | Notes |
|---|---|---|---|
| 5 | TLS traffic had rule-only detection (no `tls` model, no training data) | **Done** (small-sample evidence) | ENG-03 scores the TLS **SNI** with the trained DGA model, floor `TLS_SNI_MIN_CONFIDENCE`=90. SNI extracted in native+Python (equal, fail-closed on truncation). 0 alerts on 33 real SNIs + 25 CDN-style names; 6/6 DGA-style fire. `tests/test_tls_sni.py`, `scripts/eval_tls_sni.py`. Needs a larger real-TLS corpus to firm up the FPR |
| 6 | RECONNAISSANCE alert flood (22,588 alerts from one scanner) | **Done** | One alert per scanning campaign + 10× escalation. `tests/test_regressions_2026_09.py` |
| 7 | Native `expire()` O(k·n) | **Done** | 942.8 ms → 38.8 ms (24×), order preserved (tested) |
| 8 | ENG-01 pure-Python Redis path | **Done** | Merged 2 pipelines → 1, `hiredis` C parser: 24.3 s → 13.9 s / 12,300 flows (now at the Redis RTT floor, ~1.1 ms/flow) |
| 9 | Multi-core engine pool | Measured, **not recommended** | Corrected harness (waits for drain), real Redis: 1 worker **44.9k pps**, 2 workers 3.2k, 4 workers 5.6k. Cost = one ENG-01 Redis round trip per flow across processes; fix path = batch ENG-01 commands per worker batch (or shard state natively). Single-process meets current needs |
| 10 | Ground-truth fixtures drifted from deliberate tuning | **Done** | Generator emits a real Slowloris handshake, a public-style tunnel domain, an exfil over the 256 KB floor, advancing TCP seq, and floods aligned to ENG-01's 10 s window (a flood straddling a bucket boundary was split 172+78 and silently never fired — found by the Docker/Zeek check). Both paths detect every expected class |
| 11 | Treelite / faster tree inference | **Decided: not integrating** | Measured on the real models: Treelite GTIL is *slower* than onnxruntime (1.4–4×); XGBoost-native is ~5× faster but per-row cost is already ~2 µs (<1% of the pipeline). `scripts/bench_inference_backends.py` |
| 12 | Live-path alert noise / cadence for replayed captures | Open | Snapshot cadence is wall-clock (2 s); fast replays score most flows only at final flush |

## P2 — coverage and hardening

| # | Item | Status | Notes |
|---|---|---|---|
| 13 | ENG-11 (Kerberoasting) dormant on live capture | **Done** | Rust+Python KDC-reply parsers agree on the real `krb-816` capture; machine-SPN classes excluded. `tests/test_ot_kerberos.py` |
| 14 | IPv6 validated on a constructed packet, not a captured live one | Open (low) | Needs the elevated sensor on the real Wi-Fi |
| 20 | Multi-core scale-out beyond one process | Open | Needs batched/native ENG-01 state or a shared-memory design; see #9 |
| 15 | Hard-negative retraining (dns/flow), long-run live-baseline evaluation | Open | Needs more real benign data |
| 16 | OT breadth | **Done** | Live decoders + ENG-07 rules: Modbus, DNP3, S7comm, IEC-104, EtherNet/IP, BACnet, OPC UA, **PROFINET-DCP** (layer 2; real captures: DCP Set → alert, Identify polling quiet). All decoded identically by Rust and Python on real captures. BACnet/OPC UA write/command alerts and DCP factory-reset severity are unit-tested on constructed data only (no real capture contains them); OPC UA SignAndEncrypt bodies can't be inspected |
| 17 | Packet-level (Wireshark-style) inspector in the dashboard | **Done** | Live ring + uploaded-PCAP index, layer tree/hex/filter/export |
| 18 | ENG-05 fan-out threshold borderline FP | **Closed — not a FP** | The `normal.pcap` alert is a real nmap-style SYN scan of the router (fixed sport 54920, ~80 ports) |
| 19 | Windows kernel-bypass | Not planned | XDP for Windows is Server-only |

## Deployment direction

The product ships as a **service**, not a frozen executable: `docker compose up -d`
(full stack) or `pip install -r requirements.txt` + `maturin develop --release` +
`uvicorn` (bare service) on Linux or Windows. The PyInstaller single-exe path is
retired — the native module is per-platform anyway, and a service works identically
on both OSes. Linux capture sensors can add `--features afxdp` (AF_XDP).

## Added 2026-09-26 (second pass)

| # | Item | Status | Notes |
|---|---|---|---|
| 21 | Live NIC capture on the native engine, real Wi-Fi, incl. IPv6 | **Done** | Elevated sensor, real Wi-Fi + real internet downloads: 148 Mbit/s, 0 kernel drops, agent saw 296,070 packets vs NIC counter 292,804 over 30 s, 179 local devices learned passively (ARP/broadcast), real link-local IPv6 (ICMPv6 ND) parsed. This network has no global IPv6 (`curl -6` fails); global-v6 flows remain covered by tests only. Real-traffic FP found and fixed: periodic LLMNR multicast flagged as C2 (ENG-02 now ignores multicast/broadcast) |
| 22 | Multi-threaded capture/assembly sharding | **Done** | Flow-hash sharded assembler threads (default min(4, cores/4); `STEALTHTAP_SHARDS`). Flood capture (mirai) 228k → 395k → 486k pps at 1/2/4 shards; real mix (normal2) **1.58M pps ≈ 10 Gbit/s**. Output identical to 1 shard on all 26 real captures (`tests/test_native_capture.py`) |
| 23 | Live-baseline sampling under flood | Open | Baseline is fed ≤ 2,000 flows/tick when flow rates are extreme |
| 24 | Hard-negative retraining (dns/flow) | **Not needed on current evidence** | 2.7M real live packets on Wi-Fi produced 0 ML alerts (dns model 0/25 CDN-style names, 0/33 real SNIs; flow model is corroboration-only). Retraining also needs the original 675k-row/CICIDS datasets, which are not in this repo — revisit only if a real ML false positive appears |
| 25 | Network discovery (active, own subnet) | **Done** | `POST /network/discover`: unprivileged ARP-cache sweep (forces ARP with a UDP datagram, reads the OS neighbour table; accurate, no firewall dependence) or elevated `nmap -sn`. Real runs: Wi-Fi /24 → 39 devices with MACs (D-Link etc.); VMnet1 (no VMs) → 0, correctly. Scope rules tested (`tests/test_discovery.py`) |
