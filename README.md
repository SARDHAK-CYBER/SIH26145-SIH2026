# StealthTap

Passive AI-DPI network threat detection — SIH 2026, Problem Statement 26145 (NTRO), Team XOR.

StealthTap inspects network traffic (uploaded PCAPs, live capture on a chosen interface, or streamed Zeek logs) and raises typed security alerts using 13 rule/statistical engines, three trained ML models, and an unsupervised per-network behavioural baseline — without ever storing packet payload. Packet parsing and flow assembly (both the upload and live paths) run on a validated native Rust core (`native/stealthtap_core`); detection logic stays in Python, unchanged, with an automatic fallback to the pure-Python parser if the native module isn't built.

**Ships as a service, on Linux and Windows** (not a frozen executable — the native module is per-platform anyway, and a service behaves identically on both):
- **Docker stack** (`docker compose up -d`) — full pipeline: real Zeek 6.0.3 + 6 ICSNPP OT plugins, Suricata (20,829 ET Open rules), YARA, Postgres, Redis, OpenSearch, Redpanda, React dashboard. The image builds the native Rust module (multi-stage), so uploads run on the fast path inside the container.
- **Bare service** (`pip install -r requirements.txt` + `maturin develop --release` + `uvicorn`, or `python stealthtap_app.py`) — no Docker/Redis/Postgres. Select a network interface like Wireshark and watch alerts live.
- Living status: [`docs/PRIORITIES.md`](docs/PRIORITIES.md) (regenerated from a real system check by `scripts/update_priorities.py`) and the latest full report in [`docs/reports/LATEST.md`](docs/reports/LATEST.md).

## Honest accuracy — read before deploying

This is the single most important thing in this document. Every other network-security README you've read says "99% accuracy." We measured ours, against real attack and benign captures (not the training data), with a reproducible harness — and it is not that.

Run: `python scripts/eval_real_traffic.py "<pcap folder>" --out eval_results`

Latest measured result (25 real attack captures — Hydra brute force, BlackEnergy, Mirai, UnrealIRCd, distcc backdoor, and others — plus 2 benign captures of ordinary desktop traffic; file-level ground truth, no OpenSearch/Suricata in this run):

| Config | Attacks detected | Benign captures clean | Benign flow false-positive rate |
|---|---|---|---|
| Rule engines only | 24/25 (96%, 95% CI 80–99%) | 1/2 | 0.16% (1 of 624 flows) |
| AI models only | 5/25 (20%, 95% CI 9–39%) | 2/2 | 0.00% |
| Hybrid (rules + AI) | 25/25 (100%, 95% CI 87–100%) | 1/2 | 0.16% (1 of 624 flows) |

**Read the 25/25 correctly.** The previous run missed six captures (`distcc_exec_backdoor`, `smtp`, `tomcat` and their `*2` twins — Metasploit sessions with no volumetric signature). ENG-14 (below) was written *after* inspecting those files, so their detection is **in-sample**: it shows the rules do what they claim on real traffic, not that the same recall will hold on unseen exploits. The one alert on the "benign" `normal.pcap` is a true positive — that file contains a real nmap-style SYN scan of the router. Benign evidence in this table is small (624 flows in two files); the 20-minute real Wi-Fi capture below is the larger benign test.

**What this means in practice:**
- Rules carry detection; the ML models do not carry it. The `flow` model (features: duration, bytes, protocol) is a **DDoS-shape detector**: 99.9% of held-out DDoS-capture flows, and essentially none of the intrusion captures. Its old false-positive rate was real and large — **23.7% of 8,937 real benign flows at 0.6 (8.8% even at 0.99)** — because it had seen only ~600 benign flows. It was **retrained with a large real benign set** (a 20-minute live Wi-Fi capture): on benign flows from *unseen minutes of that network* the false-positive rate is **0.00% (0/4,276)**, on real flows from **other networks** it never trained on it is **0.8% (2/237) at ≥0.95**, and held-out DDoS-capture recall stays **99.9%** (`docs/reports/flow_retrain_real_benign.json`). It **still cannot alert alone by default** (`ML_FLOW_STANDALONE_CONFIDENCE`): two networks are not enough to bound the rate at scale, and DDoS is already covered by ENG-01. Set it to `0.98` if you accept that trade.
- The DNS DGA model is solid (674,898 rows, real held-out precision 0.94/recall 0.88) and is used as shipped.
- Every "recall" number above has a **wide confidence interval** — 25 files is a small, non-independent sample (several are near-duplicate pairs from one lab). Treat these numbers as a floor and a methodology, not a market claim.
- This measured run used the in-process parser only (Zeek/Suricata require Docker, which was unavailable when this run was taken) — Docker-path rule recall should be measured separately and is expected to be higher with Suricata's signature set included.
- **AI-based detection with no rules is currently the weakest configuration on this dataset**, not the strongest — see `docs/PRD.md` §7 for why, and what changes that.

**Real benign network test (the number that matters for false alarms).** A 20-minute live capture on a real Wi-Fi network (7.0 million packets, 8,593 flows, 294 hosts; recorded through the sensor with `scripts/collect_live_pcap.py`, kept local because it holds real payloads) was replayed through the full live pipeline. It first raised **23 alerts**, every one a false positive of a kind the two small benign files could not show: 15 × C2 on UDP broadcast heartbeats, 2 × C2 on Windows OCSP/CTL certificate fetches, 3 × Slowloris on idle push/peer-to-peer connections (ports 5228, 7680), 1 × DDoS on mDNS, 1 × exfiltration on an ordinary 1.2 MB upload. All five causes are fixed in Rust and Python (`tests/test_false_positives_real_wifi.py`). The same replay now raises **1 alert (0.12 per 1,000 flows)** — a periodic fetch of wikipedia.org made by the traffic-generating helper itself — and real-capture recall (15/15 unique attack captures) did not change. One real network is still one network: expect new false-positive kinds elsewhere and treat this as the method, not a guarantee.

See `docs/PRD.md` for the full methodology, root-cause fixes already applied (flow-direction inference, exfiltration volume floor, recon-vs-normal-browsing distinction, DGA registrable-domain scoring), and what's still open.

## Honest throughput — read before deploying at high speed

Same rule as accuracy: measured, not asserted.

| Layer | Measured throughput | Meets the 1-5 Gbps target? |
|---|---|---|
| Native Rust parser/assembler alone (parsing + flow assembly, no detection) | 393,856 pps (`samples/netbios_ssn2.pcap`) — comfortably 1-5+ Gbps at realistic packet sizes | Yes |
| Full pipeline: native assembly + all 13 engines + 3 ONNX models, one core | ~6,300-20,000 pps depending on measurement method (up from ~1,580 pps at the start of this work) — see methodology note below | **No** — roughly 20-80x short |

**Why the gap:** parsing is compiled, typed, zero-copy Rust; detection is 13 engines, most still interpreted Python, running sequentially on every flow. That's an architectural ceiling, not a bug — profiling (not guessed at) found and fixed several real, measurable costs:
- Stateful engines (flood/beacon/exfil/bruteforce counters) were paying Redis network round-trip latency on every flow, even on localhost — switched the default backend to an in-process store; **measured 3x** on identical detection code, only the backend changed.
- DNS/SSL/Modbus ML scoring was calling ONNX one record at a time; batched it, matching the pattern already used for connection-flow scoring.
- Two profile-guided fixes: a needless packet re-serialization before handing it to the native assembler (~15% of pipeline time), and one engine (`ENG-05`) rebuilding a full history set on every flow instead of only when a new probe was added (~20%).
- **The fast-path/slow-path split is now real, not just proposed**: `native/stealthtap_core/src/eng01.rs`, `eng02.rs`, `eng05.rs`, `eng06.rs`, `eng13.rs` are validated native ports of the five most CPU/state-heavy engines — same thresholds and formulas as their Python originals (byte-for-byte equivalence proven per-engine, see `scripts/validate_native_eng*.py`), Python now only builds the final `Alert` on a real positive. Combined effect on the full pipeline, measured with the same CPU-time profiler before/after: **6.66s → 2.36s on the same 48,150-packet capture, a 2.83x reduction this round alone**.

Methodology note: this dev machine showed real, substantial throughput swings (not code regressions) purely from other concurrent load on the box — running the full Docker analysis stack alongside a wall-clock benchmark cut measured pps by 5-10x with zero code changes. Where that matters, prefer the CPU-time-profiled number (isolated from system scheduling noise) over a single wall-clock run.

**What would close the remaining gap**: the remaining ~7 engines (ENG-03/04/07/09/11 and the Suricata/YARA/BZAR Docker-only engines) are either already cheap (stateless or exact-match), Docker-only (can't run in the hot path regardless), or lower-volume in practice — diminishing returns from porting them individually. The larger remaining lever is the ONNX inference cost itself (now the single biggest remaining line item) and further architectural work on how many flows reach Python at all. See `docs/PRD.md` §11 for the full methodology and every number behind this table.

### Update 2026-09-27 — deployment hardening, ENG-14, OPC UA policy, tenancy, backups

* **Access control.** API key required on the API and the sensor (`STEALTHTAP_API_KEY`; compose refuses to start without one); Postgres/Redis/OpenSearch/Redpanda published on loopback only; dashboard prompts for the key; refuses non-loopback bind without a key. Optional per-tenant keys isolate stored alerts, uploaded captures and jobs. TLS is *not* included — front it with a reverse proxy. Details and limits: `docs/OPERATIONS.md`.
* **ENG-14 — attacks on plain-text services**, decided from decoded payloads (Rust decoders + Python twin, parity-tested on real captures): distcc command execution, SMTP account enumeration (VRFY/EXPN, RCPT harvesting with refusals), HTTP Basic default credentials / guessing / code-deployment endpoints (Tomcat manager WAR upload, Jenkins script console). Live replay of the real corpus: **15/15** unique attack captures detected (was 11/14). The upload path now runs the same native payload decoders, so an uploaded pcap and a live capture reach the same verdict (and S7comm/IEC-104/BACnet/OPC UA/PROFINET events now reach ENG-07 on upload too).
* **OPC UA SignAndEncrypt.** Ciphertext bodies remain uninspectable (a passive sensor has no keys), but the security policy is negotiated in clear: channels using policy `None` or deprecated SHA-1 policies now raise `INSECURE_CONFIGURATION` findings (LOW/MEDIUM, once per client/server/policy per hour; `OPCUA_POLICY_ALERTS=0` disables).
* **Resilience.** Alert spool on disk if the API/DB is down (re-sent in order), scheduled `pg_dump` backups with a restore drill (row counts identical), systemd unit and Windows auto-restart task for the sensor, CI (`.github/workflows/ci.yml`).
* **Real benign network test.** A 20-minute live Wi-Fi capture (7.0M packets) exposed 23 false positives the small benign files could not; fixed (ENG-01/02/06/09) → 1 alert. The flow model, whose false-positive rate was 23.7% on real flows, was retrained with real benign flows (0% on held-out minutes, 0.8% on other networks, DDoS recall 99.9%). Details: `docs/PRD.md` §14.
* **Accounts and roles:** named users (scrypt) with signed login tokens, roles viewer/analyst/sensor/admin, audit log, per-tenant rate and analysis limits, dashboard sign-in; tenant isolation verified end to end through the TLS proxy (`docs/OPERATIONS.md` §1b).
* **New networks:** `scripts/site_calibration.py` groups a site's alerts into triage rows; `config/allowlist.json` suppresses verified-benign patterns with guard rails and an audit trail; procedure in `docs/SITE_ONBOARDING.md`. 343 real ICS captures raised 1 generic-engine alert in 5,497 flows; the Modbus ML model (13.8% of real writes, duplicating the rule) is now corroboration-only.
* **ENG-14 out of sample (HTTP rules):** real nmap/curl attacks against a real Tomcat in an isolated Docker network: 3/3 detected, benign control clean, one gap found and fixed. SMTP/distcc rules remain in-sample.
* Fixed: ICS alerts reused the flow uid as `alert_id`, so a second ICS alert on the same flow was silently dropped by the database's `ON CONFLICT DO NOTHING`.

### Update 2026-09-26 (second pass) — separate dashboards, native capture engine, real-data live path

* **Two dashboards**: `#/live` (overview, alerts, hosts, flows, packets, capture control) and `#/pcap` (upload analysis), both with a Wireshark-style packet inspector. No synthetic data is shown.
* **Native capture engine** (Rust, GIL-free) + flow engines in Rust: **~950k pps / 6.0 Gbit/s sustained** on a real captured traffic mix through the full pipeline, a 15-minute / 127 GB soak with no drops, memory flat. Flow-per-packet floods (mirai) hold 100–420k pps.
* Real-capture accuracy through the live path: 11/14 attack captures detected, no false alert on the clean benign capture; OT/Kerberos decoders validated on real public captures. Full numbers and limits: `docs/PRD.md` §13.
* **Windows note**: with Npcap in "Administrators only" mode, run `powershell -File scripts\start_sensor.ps1` once (one UAC prompt) for live NIC capture. Live capture on a real NIC still needs re-running on the native engine.

### Update 2026-09-26 — real-traffic hardening pass (measured, not asserted)

A full-stack test (`python scripts/system_check.py`) found and fixed these; every row has a regression test (`tests/test_regressions_2026_09.py`, `tests/test_api_availability.py`, `tests/test_raw_ingest.py`, `tests/test_tls_sni.py`):

| Issue found | Fix | Measured |
|---|---|---|
| One large upload froze the whole API, `/health` included | Heavy stages off the event loop, concurrency cap + 429 backpressure, 600 s deadline, async job endpoints, Suricata size-skip | 93.8 MB / 565k-flow capture: >10 min freeze → **HTTP 200 in 33 s**, worst `/health` 58 ms |
| Docker image had no native module | Multi-stage build compiles the wheel | verified in-container |
| Live capture ceiling ≈ 10k pps (scapy dissection ~100 µs/packet) | Raw-frame ingestion straight into the native assembler (`RawFrame`, all backends) | 6.5k → **~45–75k pps**, identical unique detections |
| IPv6 silently dropped (76.6% of a real network) | IPv6 + extension-header walk in both native parsers | native == Python incl. flow uid |
| Native JA4 returned a *wrong* fingerprint for a split ClientHello | Fail closed in native and Python (also for a cut inside an extension header) | tested at 5 cut points |
| Native `expire()` O(k·n) | order-preserving `retain` | 942.8 → 38.8 ms (24×) |
| ENG-01 Redis path | 2 pipelines → 1, `hiredis` C parser | 24.3 → 13.9 s / 12,300 flows |
| RECONNAISSANCE alert flood (22,588 alerts, one scanner) | One alert per campaign + 10× escalation | — |
| TLS traffic had rule-only detection (no `tls` model, no labeled data) | ENG-03 scores the TLS **SNI** with the trained DGA model (`TLS_SNI_MIN_CONFIDENCE`, default 90) | 0 alerts on 33 real SNIs + 25 CDN-style names; 6/6 DGA-style names fire. Small real sample — see `scripts/eval_tls_sni.py` |
| Anomaly baseline needed ~10 min before doing anything | `warm_start` from the batch's own span | — |

Decisions made from data: **Treelite not integrated** (its GTIL is 1.4–4× *slower* than onnxruntime; XGBoost-native is faster but inference is <1% of the pipeline — `scripts/bench_inference_backends.py`). **Multi-core engine pool stays opt-in and is not recommended**: with real Redis 4 workers measured 5.6k pps vs 44.9k pps single-process, because ENG-01 pays a Redis round trip per flow (fix path: batch ENG-01 commands per worker batch). AF_XDP is available for Linux sensors behind the `afxdp` cargo feature; Windows has no kernel-bypass equivalent short of Windows Server.

## Detection pipeline

```
                                    ┌─ Upload PCAP ──▶ Zeek+ICSNPP/Suricata/YARA (Docker)
                                    │                    or native Rust parser, Python fallback
Ingest paths ──────────────────────┼─ Live NIC capture ▶ AF_PACKET (Linux, kernel mmap ring)
(4, one shared engine set)         │                      / Npcap (Windows) ▶ native Rust
                                    │                      LiveFlowAssembler, Python fallback
                                    ├─ Live streaming ──▶ Zeek → Redpanda → Faust worker
                                    └─ Offline batch ───▶ static Zeek JSON logs
                                              │
                                              ▼
                          src/flow_mapping.py — ONE record→flow mapper, all 4 paths
                                              │
                    ┌─────────────────────────┴──────────────────────────┐
                    ▼                                                    ▼
     13 rule/statistical engines (ENG-01..13)              3 trained ONNX models
     — always run, deterministic                            (dns / flow / modbus)
     optionally sharded across worker PROCESSES              batched, not per-record
     (src/capture/engine_pool.py, opt-in)                    (src/capture/scoring.py)
                    │                                                    │
                    └──────────────────┬─────────────────────────────────┘
                                        ▼
                       src/inference/fusion.py — alert policy:
                    weak models need rule corroboration to fire
                                        │
                    ┌───────────────────┼────────────────────┐
                    ▼                                        ▼
     src/inference/online_baseline.py             Pydantic Alert → Postgres (Docker)
     live-learning per-network baseline             or in-memory (standalone)
     (conformal-calibrated, no pre-trained data)              │
                                                                ▼
                                                    React dashboard (Visualizer
                                                    Studio: live aggregation
                                                    builder, not static charts)
```

## The 14 detection engines

| Engine | Threat class | Method |
|---|---|---|
| ENG-01 | Volumetric DDoS / Slowloris | RedisBloom Count-Min Sketch flood counter + HyperLogLog spoofed-source ratio, per 10s window |
| ENG-02 | C2 beaconing | Coefficient-of-variation on inter-arrival times (catches jittered beacons, not just perfect periodicity) |
| ENG-03 | DGA domains / DNS tunnelling / TLS SNI | Trained XGBoost+IsolationForest on registrable domain, or deterministic lexical heuristic fallback; same model applied to the TLS SNI (strict floor) |
| ENG-04 | Encrypted malware (JA4) | Real JA4 TLS fingerprint (live path) matched against threat intel |
| ENG-05 | Reconnaissance | Fan-out of **unanswered probe-shaped** flows per source per 5 min (excludes normal browsing) |
| ENG-06 | Data exfiltration | Per-flow byte-ratio (with a volume floor) + accumulated low-and-slow ratio over 5 min |
| ENG-07 | OT/ICS anomaly | Modbus, DNP3, S7comm, IEC-104, EtherNet/IP-CIP, BACnet, OPC UA, PROFINET-DCP dangerous commands; OPC UA weak security policies |
| ENG-08 | Malicious files | YARA scan of Zeek-extracted cleartext files |
| ENG-09 | HTTP threats | Suspicious user-agent + high-entropy URI |
| ENG-10 | Signature match | Suricata ET Open (20,829 rules) |
| ENG-11 | Kerberoasting | Kerberos service-ticket request pattern |
| ENG-12 | BZAR notices | Zeek BZAR ATT&CK-for-ICS notices |
| ENG-13 | Brute force / credential stuffing | Connection-attempt rate to auth ports (10 attempts/60s, below both measured real attack rates) |
| ENG-14 | Plain-text service attacks | distcc non-compiler jobs, SMTP account enumeration, HTTP default credentials / auth guessing / deployment endpoints (payload-decoded) |

Plus **the live-learning baseline** (`src/inference/online_baseline.py`): learns per-service (protocol, port) flow statistics from *your* traffic (minimum 1,500 flows / 10 minutes), then flags conformal-calibrated outliers — no attack labels, no pre-trained data, works uni-directionally.

## Trained ML models

| Family | Training rows | Precision / Recall / F1 / ROC-AUC | Alerting policy |
|---|---|---|---|
| `dns` (DGA) | 674,898 | 0.94 / 0.88 / 0.91 / 0.97 | Standalone, on registrable domain |
| `flow` (DDoS-shaped) | 23,213 (97% attack rows, 4 features) | 0.9996 / 0.9985 (in-distribution — does not transfer) | **Corroboration-only** — see accuracy section above |
| `modbus` | 51,608 | 1.0 / 1.0 / 1.0 / 1.0 | Standalone, OT traffic only |

Isolation Forests are trained but demoted to advisory everywhere (F1 < 0.3 on held-out data) — XGBoost drives every family. `MANIFEST.json` in `models/` has the full numbers.

## OT/industrial protocol coverage

| Protocol | Status |
|---|---|
| Modbus TCP, DNP3 | Zeek + ICSNPP, Suricata, dedicated detection (ENG-07) |
| EtherNet/IP, S7comm(+plus), OPC UA, PROFINET (IO-CM) | Zeek + ICSNPP parsers, no dedicated detection logic yet |
| IEC 60870-5-104, IEC 61850 (GOOSE/SV/MMS), EtherCAT, BACnet, HART-IP | Third-party open parsers exist (see `docs/PRD.md` §9); not integrated |
| Modbus RTU, PROFIBUS DP/PA, Foundation Fieldbus H1, wired HART | **Serial buses — not visible on any Ethernet capture.** Need a serial adapter or protocol gateway; out of scope for a NIC-based sensor |

## Quick start — Docker (full stack, Linux or Windows)

```bash
cp .env.example .env   # set real passwords AND STEALTHTAP_API_KEY (>=16 random chars), never commit .env
docker compose up -d --build     # services restart on failure and are health-gated
python scripts/system_check.py   # full-stack check -> docs/reports/LATEST.md
```
Dashboard: **https://localhost** (asks for the API key; Caddy's local CA, so the browser warns until you trust it) · API: **https://localhost:8443** (`X-API-Key` header). Plaintext ports 4173/8000 stay on 127.0.0.1. To serve a LAN or the internet set `STEALTHTAP_BIND`/`STEALTHTAP_HOST`/`STEALTHTAP_PUBLIC_API`/`STEALTHTAP_TLS` — `docs/OPERATIONS.md` §1. Windows sensor as an auto-restarting SYSTEM task: `packaging\windows\install_sensor_task.ps1`.

## Quick start — bare service (no Docker)

```bash
pip install -r requirements.txt
pip install maturin && maturin develop --release -m native/stealthtap_core/Cargo.toml   # optional but ~10x faster
python stealthtap_app.py            # http://127.0.0.1:8100  (or: uvicorn on src.api)
```
Live capture needs elevated privileges (Administrator on Windows, root/`CAP_NET_RAW` on Linux). **Windows also needs [Npcap](https://npcap.com/) installed separately** — its free licence forbids redistribution, so it is never bundled. Linux sensors can add `--features afxdp` to the maturin build for AF_XDP.

The PyInstaller single-executable path is retired in favour of the service deployment above (`packaging/` is kept for reference only).

## Verify it yourself

```bash
python -m pytest tests/ -q                                             # 266 unit/integration tests
python scripts/system_check.py [--accuracy]                            # full stack: infra, native, engines, models, perf, accuracy
python scripts/update_priorities.py                                    # refresh docs/PRIORITIES.md from a real check
python scripts/analyze_local.py samples/simulated_attack_traffic.pcap  # full pipeline, no Docker
python scripts/eval_real_traffic.py "<your pcap folder>" --out eval_results  # accuracy on real data
python scripts/validate_native_parser.py "<your pcap folder>"          # native upload-parser vs. Python, byte-for-byte
python scripts/validate_native_live_assembler.py "<your pcap folder>"  # native live-assembler vs. Python, byte-for-byte
python scripts/bench_throughput.py "<some.pcap>"                       # measured live-pipeline pps/Mbit/s, not estimated
```

## Everything is open-source, no paid components

Zeek (BSD), Suricata (GPLv2), YARA (BSD), ICSNPP (BSD-3), XGBoost/scikit-learn/ONNX (Apache-2/BSD), React (MIT). Windows capture uses Npcap, which is free (not open-source) for up to 5 systems and is never bundled or redistributed by this project — see the licence at npcap.com.

## Documentation

- `docs/PRIORITIES.md` — living priority list (auto-refreshed status block + hand-maintained items)
- `docs/reports/LATEST.md` — latest full system-check report; `docs/reports/history.csv` — trend
- `docs/SITE_ONBOARDING.md` — calibrating a new network: observe, triage groups, allowlist, decide the ML question
- `docs/OPERATIONS.md` — access control, tenancy, backup/restore drill, alert spool, sensor auto-restart, HA design and its limits
- `docs/PRD.md` — full requirements, methodology, root-cause analysis, roadmap
- `native/README.md` — native Rust core: scope, validation methodology, measured performance, what's still Python-only
- `docs/LIVE_CAPTURE_DEPLOYMENT.md` — deploying the live/streaming sensor
- `docs/MODEL_CONTRACT.md` — feature schema, train/serve parity contract
- `CHANGES.md` — change history
