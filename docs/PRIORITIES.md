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
_Last automated check: **2026-09-27 02:30:46** · PASS 27 · WARN 0 · FAIL 0 · tests 266 · live pipeline 364,825 pps · hybrid recall 83.0% · flow FPR 0.167%_

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
| 24 | Hard-negative retraining (dns/flow) | **Done for flow** (dns not needed) | Earlier conclusion "cannot be fixed" came from only 484 benign flows. With 8.9k real benign flows (20-min live Wi-Fi capture): shipped model was 23.7% FPR @0.6 (8.8% @0.99); retrained (`scripts/retrain_flow_real_benign.py`) is 0.00% on 4,276 time-held-out benign flows and 0.8% on 237 flows from other networks at DDoS recall 99.9% (`docs/reports/flow_retrain_real_benign.json`). Still corroboration-only by default: same-network hold-out is optimistic and the cross-network sample is small (PRD §14.4). DNS model: 0/33 real SNIs, 0/25 CDN names fire |
| 25 | Network discovery (active, own subnet) | **Done** | `POST /network/discover`: unprivileged ARP-cache sweep (forces ARP with a UDP datagram, reads the OS neighbour table; accurate, no firewall dependence) or elevated `nmap -sn`. Real runs: Wi-Fi /24 → 39 devices with MACs (D-Link etc.); VMnet1 (no VMs) → 0, correctly. Scope rules tested (`tests/test_discovery.py`) |

## Follow-ups closed 2026-09-26 (third pass)

| Item | Status | Evidence |
|---|---|---|
| Tests only on hand-built packets (BACnet/OPC UA writes, DCP factory reset) | **Upgraded** | DCP factory reset decoded from frames built by scapy's independent `pnio/pnio_dcp` encoder (this exposed a real robustness bug: zero DCPDataLength → fixed); BACnet WriteProperty and OPC UA WriteRequest built by changing only the service field of a REAL captured request. Still no real capture *containing* those events exists publicly |
| Real-data misses | **Fixed** | Real `cip_stop_plc.pcap` (CIP Stop 0x07) was undetected → CIP Reset/Start/Stop added; real S7 PLC-stop ×2, S7 download ×2, WRITE_VAR, DNP3 file/binary-output writes all alert |
| Global IPv6 on real packets | **Done (captured files)** | tcpdump test-suite captures with global 2604:1380:… addresses incl. hop-by-hop jumbogram assembled natively (`tests/test_ot_kerberos.py`). The Python fallback assembler fails on 80 KB IPv6 jumbograms (native is authoritative). This Wi-Fi has no global IPv6, so a live link is still untested |
| Whole-network coverage | **Measured, deployment doc** | `/capture/coverage` + Hosts-page card compute visible-vs-known devices (verdict full/partial/own-traffic-only, blind-spot list from an active sweep); `docs/DEPLOYMENT_COVERAGE.md` gives mirror/TAP/gateway/bridge placement. Placement itself is a deployment choice |
| OPC UA SignAndEncrypt | **Inherent** | Ciphertext cannot be inspected by a passive sensor without the session keys; metadata (SNI/JA4-style, sizes, timing) only |
| Live NIC re-run on the newest code | **Blocked** | Needs an elevated sensor started with the new code; 6+ UAC requests this session were not approved |

## Live NIC validation on the newest code — 2026-09-26 (real Wi-Fi, elevated sensor, `docs/reports/live_nic_validation.json`)

| Metric | Result |
|---|---|
| Engine | native, 4 assembler shards |
| Capture ratio (engine vs the NIC's own counter, 60 s, real internet downloads) | **1.0039** (529,507 vs 527,445 packets) |
| Drops | kernel 0, records 0, user 0 |
| Peak rate | 175.7 Mbit/s (the internet link is the limit) |
| Devices seen | 294 hosts (183 local), 72 IPv6 hosts (all link-local; this network has no global IPv6) |
| Alerts / ML alerts | 0 / 0 on ordinary traffic |
| Coverage verdict | *partial* — 155 of 183 local devices have visible unicast traffic (84.7%) |

Root cause of the repeated "sensor never starts": every extra sensor tried to write the same `sensor.log`, which the first elevated sensor still held open; the launcher now logs to `sensor-<port>.log`. Note: one earlier validator run crashed with `KeyError: 'capture'` because a second validator was stopping the same capture — run one validator per sensor.

## Added 2026-09-27

| # | Item | Status | Evidence |
|---|---|---|---|
| 26 | API/dashboard had no authentication; datastores published on all interfaces | **Done** | API key middleware (API + sensor), loopback-only published ports, dashboard sign-in, compose refuses to start without a key: `tests/test_security.py`, `docs/OPERATIONS.md` §1 |
| 27 | No CI | **Done** | `.github/workflows/ci.yml` (Linux + Windows pytest with native build, dashboard build, compose validation). First run found a real bug (Windows-generated `package-lock.json` broke `vite` on Linux) — fixed and verified in a node:22 container |
| 28 | Recall gap: distcc / SMTP enumeration / Tomcat manager captures | **Done (in-sample)** | ENG-14; live replay 15/15 unique attack captures; in-sample caveat in PRD §14.2 |
| 29 | Real-network false positives (broadcast beacons, OCSP/CTL, idle push connections, mDNS, 1 MB upload) | **Done on one network** | 23 → 1 alert on a real 20-min capture (8,593 flows): `tests/test_false_positives_real_wifi.py`, PRD §14.3. Expect new kinds on other networks |
| 30 | OPC UA channel security | **Partly** | Policy None / SHA-1 policies flagged; SignAndEncrypt bodies cannot be read without keys (permanent limit) |
| 31 | Multi-tenant isolation | **Done for stored alerts/captures/jobs** | Per-tenant keys; not compute-isolated, OpenSearch path shared: `docs/OPERATIONS.md` §2 |
| 32 | Backups / alert loss during outages | **Done** | Scheduled `pg_dump` + restore drill (identical rows), on-disk alert spool (`tests/test_forwarder_spool.py`) |
| 33 | Sensor auto-restart | **Done (Windows), systemd untested** | Windows task installed and proved: runs as SYSTEM, no UAC for capture, killed sensor relaunched in ~15 s (`docs/OPERATIONS.md` §4). Reboot persistence not yet observed; systemd unit only syntax-checked |
| 37 | User logins / roles / audit | **Done** | Named users (scrypt), signed tokens, roles viewer/analyst/sensor/admin, audit log, login lockout, dashboard sign-in; verified end to end through TLS (`docs/OPERATIONS.md` §1b). No SSO/MFA/password reset |
| 38 | Multi-tenant isolation verified on the running stack | **Done (data + rate/slots)** | 20/20 e2e checks + positive control; not cgroup compute isolation |
| 39 | False positives on other networks | **Measured, procedure + allowlist in place** | 343 ICS captures: 1 generic alert / 5,497 flows; Modbus ML gated (13.8% of writes duplicated the rule); `docs/SITE_ONBOARDING.md`, `scripts/site_calibration.py`, `src/allowlist.py` |
| 40 | ENG-14 out of sample | **HTTP rules: done; SMTP/distcc: still in-sample** | Real nmap/curl vs real Tomcat: 3/3 + clean benign control (`samples/lab_eng14`); one real gap found and fixed |
| 41 | Reboot persistence, systemd, public certificate issuance | Open (need a reboot / Linux host / public DNS) | `scripts/verify_after_reboot.ps1` ready; Caddy ACME config validated at config level only |
| 34 | High availability | Design only | `docs/OPERATIONS.md` §5; never run multi-node |
| 35 | 24-72 h soak on a mirrored production link | Open | 4 h replay soak done (`docs/reports/soak_mixed_4h.json`); needs the real link |
| 36 | TLS in front of API/dashboard | **Done (local CA)** | Caddy `proxy` service, HTTPS 443/8443, HSTS etc., plaintext ports loopback-only (`docs/OPERATIONS.md` §1). Public certificate issuance and the live sensor behind the proxy not verified |
