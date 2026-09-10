# StealthTap — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Team:** TeamXOR · **Event:** Smart India Hackathon 2026 · **PS ID:** 26145 · **Org:** National Technical Research Organisation (NTRO)

---

## 1. What this is

A passive, **read-only** network threat-intelligence pipeline for a monitoring enclave behind a data diode or SPAN/mirror port. It only ever *watches* — no probes, no completed handshakes, no blocking, no return path. Every decision comes from passively observed metadata: flow records, DNS queries, TLS handshake fingerprints, industrial-protocol function codes — **never decrypted payload**.

It runs as an IDS-style pipeline — protocol parsing, signature matching, behavioural rule engines, and a trained hybrid ML layer with anomaly detection — over **four interchangeable ingest paths** that all share the same detection engines, the same models, and the same standardized alert schema:

| Path | Trigger | Parsing | Storage | Status |
|---|---|---|---|---|
| **Upload PCAP** | `POST /analyze/pcap` from the dashboard | real Zeek 6.0.3 + 6 ICSNPP + Suricata (20,829 rules) + YARA | PostgreSQL | working, benchmarked |
| **Live capture** | pick a NIC in the dashboard / `live_agent` CLI | in-process kernel capture (AF_PACKET / Npcap) + real JA4 + Modbus/DNP3 decode | PostgreSQL (shared) | working; kernel-level, latency-measured |
| **Live streaming** | Zeek sniffing an interface (air-gapped) | Zeek → log-shipper → Redpanda → Faust | OpenSearch | built, engine-parity, not load-tested |
| **Offline batch** | static Zeek logs on disk | — | OpenSearch | working |

---

## 2. Quick start

### Full stack (Docker)

```bash
cp .env.example .env      # set OPENSEARCH_ADMIN_PASSWORD and POSTGRES_PASSWORD
docker compose up -d --build
docker compose ps         # 11 services Up
curl http://localhost:8000/health     # {"status":"ok","models_loaded":["flow","dns","modbus"],...}
```

- **Dashboard** → http://localhost:4173 (Upload PCAP + Live Capture tabs)
- **API docs** → http://localhost:8000/docs
- **Alerts** → `GET http://localhost:8000/alerts`
- **OpenSearch Dashboards** (streaming path) → http://localhost:5601

Generate a synthetic test capture: `python pcap_simulator.py` → upload `simulated_attack_traffic.pcap`.

### The stealth tap (on a monitoring host)

```bash
CAPTURE_IFACE=eth1 docker compose --profile tap up -d --build sensor
```

`network_mode: host`, only `NET_RAW`/`NET_ADMIN` capabilities, **no published ports**, read-only rootfs; captures `eth1` at kernel level and forwards alerts to the shared DB. See **`docs/LIVE_CAPTURE_DEPLOYMENT.md`**.

### Local, no Docker

```bash
python -m src.capture.live_agent list                                               # interface picker
python -m src.capture.live_agent run --pcap samples/simulated_attack_traffic.pcap   # full live pipeline over a file
python -m src.capture.live_agent run --iface eth0 --bpf "ip or ip6"                 # real NIC (root / CAP_NET_RAW on Linux)
python -m src.capture.live_agent serve --port 8100                                  # REST + SSE for the dashboard's Live tab
python scripts/analyze_local.py samples/simulated_attack_traffic.pcap               # PCAP path, engines + models, no infra
python -m pytest -q tests/                                                          # unit + smoke tests
```

---

## 3. Architecture

```
                        ── UPLOAD PATH (primary, fully tested) ──
 browser ──POST /analyze/pcap──▶ api (FastAPI)
                                  ├─▶ zeek-batch      real Zeek 6.0.3 + ICSNPP (Modbus/DNP3/S7comm/EtherNet-IP/OPC-UA/PROFINET) + BZAR + file extract
                                  ├─▶ suricata-batch  Suricata 7.0.3 + 20,829 ET Open rules   (runs CONCURRENTLY)
                                  ├─▶ YARA (ENG-08)   scans files Zeek extracted from cleartext protocols only
                                  ├─▶ ENG01–13        rule engines (below)
                                  ├─▶ hybrid ML       XGBoost + Isolation Forest, ONNX, per family (flow/dns/tls/modbus)
                                  └─▶ PostgreSQL      one queryable alert history + a per-tool coverage report

                        ── LIVE CAPTURE PATH (kernel-level, real-time) ──
 NIC ─▶ kernel ring (AF_PACKET mmap + PACKET_FANOUT + in-kernel BPF  /  Npcap ring + pcap_stats)
      ─▶ FlowAssembler   conn/dns/ssl + real JA4 from the ClientHello + Modbus/DNP3 function-code decode
      ─▶ ENG01–13 + hybrid ML   phase-split: immediate (dns/tls/OT), 2 s flow snapshots, on flow completion
      ─▶ per-(class,src,dst) cooldown ─▶ SSE stream + POST /alerts/ingest ─▶ PostgreSQL (same table as upload)

                        ── LIVE STREAMING PATH (air-gapped capture) ──
 Zeek (zero-IP capture ns) ─▶ log-shipper (tails JSON logs) ─▶ Redpanda ─▶ streaming-engine (Faust, ENG01–13 + ML)
      ─▶ relay.py (one-way Unix socket, schema-validated) ─▶ OpenSearch
```

Every analysis returns a **pipeline coverage report** — per-tool `records_processed` / `alerts_fired` — so "did every tool actually run on this input" is a checkable fact, not a claim.

---

## 4. Detection layers

### Behavioural rule engines (`src/engines/`)

| Engine | Threat | Mechanism |
|---|---|---|
| ENG-01 | Volumetric / protocol DDoS + Slowloris | time-bucketed flow-rate (Redis CMS) + **spoofed-source flood** via distinct-source-IP HyperLogLog entropy |
| ENG-02 | Botnet C2 beaconing | coefficient-of-variation of inter-arrival times |
| ENG-03 | DGA + DNS tunnelling | **trained `dns` XGBoost** on 262 char-n-gram + lexical features; deterministic lexical heuristic when no model; mDNS/LLMNR/`.local` filtered |
| ENG-04 | Malware in encrypted sessions | **real JA4** (live path) / Zeek JA4 (upload) matched against FoxIO threat intel — metadata only, never decrypted |
| ENG-05 | Reconnaissance / port scanning | distinct-destination fan-out, memory-bounded |
| ENG-06 | Data exfiltration | per-flow **and** accumulated outbound:inbound byte ratio; scored on completed flows |
| ENG-07 | OT / ICS | dangerous **Modbus** function codes, **DNP3** control codes (OPERATE/DIRECT_OPERATE/COLD_RESTART → CRITICAL), **EtherNet/IP CIP** service codes — byte-level verified |
| ENG-08 | Malicious files | YARA (~401 rules) on cleartext-extracted files |
| ENG-09 | HTTP C2 / exfil | library-default UA + URI entropy + large POST bodies |
| ENG-10 | Suricata bridge | maps `eve.json` classtypes → alert schema |
| ENG-11 | Kerberoasting | TGS request + RC4 (`rc4-hmac`) cipher for a service account |
| ENG-12 | SMB lateral movement | parses MITRE **BZAR** notices, technique IDs extracted from BZAR's own output |
| ENG-13 | Brute force / credential stuffing | connection attempts per (src, dst, auth-port) over a wide window |

### Hybrid ML layer (`src/inference/`, `src/features/`)

- **Four protocol families** — `flow` (9 features), `dns` (262), `tls` (3), `modbus` (4).
- One feature module (`src/features/feature_extraction.py`) is imported by **both** training and serving → no train/serve skew. `FEATURE_SCHEMA_VERSION` gates compatibility.
- Per family: **XGBoost** (supervised, known-bad) + **Isolation Forest** (unsupervised, benign-only, novel-attack). Combine as `max()`; `detection_mode` records which fired.
- **ONNX Runtime only** (CPU), no pickle. Batched inference (one call per model per batch).
- Missing model for a family → that family's ML is skipped, pipeline still runs.
- Global XGBoost feature importances ship per family → `Alert.top_contributing_features`.

**Trained today** (`models/MANIFEST.json`, all held-out test sets, `scripts/train_family.py`):

| Family | Rows | XGBoost P / R / F1 / ROC-AUC | Note |
|---|---|---|---|
| `dns` (DGA) | 674,898 | 0.935 / 0.880 / 0.907 / 0.972 | 25 DGA malware families + Alexa benign |
| `flow` (DDoS/exfil) | 23,213 | 0.9996 / 0.9985 / 0.999 / 0.998 | rebuilt from labelled flow captures |
| `modbus` (OT) | 51,608 | 1.000 / 1.000 / 1.000 / 1.000 | small feature space, clean separation |
| `tls` (JA4) | — | not trained | no public labelled JA4 dataset — ENG-04 runs rule-based |

Isolation Forests trained but **demoted to advisory** on all three families (held-out F1 < 0.3) — XGBoost drives detection; the IF score is still reported in `model_scores`.

### Standardized alert schema (`src/alert_schema.py`)

Pydantic v2, `extra="forbid"`. `alert_id, timestamp, severity, confidence_score(0–100), threat_class(12 Literals incl. NETWORK_INTRUSION_ATTEMPT), flow_identifier, mitre_attack, evidence, forensics, detection_mode(rule/xgboost/isolation_forest), model_scores, top_contributing_features`. One record for every detection from every layer and every path.

---

## 5. Live capture — kernel-level, latency-measured

`src/capture/` is the in-process live path (no Zeek, no containers required).

- **Backends** (`backends.py`): `AFPacketBackend` (Linux — raw `AF_PACKET` + `PACKET_MMAP` RX ring + `PACKET_FANOUT` multi-worker + kernel BPF via `SO_ATTACH_FILTER`, ring sized from `--buffer-mb`); `ScapyBackend` (libpcap/Npcap — in-kernel BPF via `conf.L2listen`, enlarged ring, `pcap_stats` drop counters). Fastest available is auto-selected.
- **Real JA4** (`ja4.py`) computed from the TLS ClientHello per the FoxIO spec — replaces the old placeholder so ENG-04 works on live TLS.
- **Modbus + DNP3** decoded from raw bytes in the flow assembler → ENG-07 fires live.
- **Phase-split scoring** — immediate for dns/tls/OT (latency-measurable end to end), 2 s dirty-flow snapshots for rate/fan-out engines, full scoring on flow completion.
- **Bounded latency** — the userspace queue drops oldest on overflow rather than growing; the **kernel** drop counter (`pcap_stats` / `PACKET_STATISTICS`) is the ground-truth "can't keep up" signal.
- **`GET /capture/status`** reports, live: `throughput.pps/.mbps/.peak_*`, `throughput.kernel_drop_total/_delta`, `dropped` (userspace), `detection_latency.p50/p95/p99/max_ms`, `active_flows`, `high_speed` flag (crosses `LIVE_HIGHSPEED_*` or the kernel starts dropping).

**Measured** (real Wi-Fi capture, this pipeline): kernel-level libpcap backend, DGA alerts via the trained model, throughput 195 pps / peak 370, kernel-drop 0, **detection latency 157 ms p50 / 328 ms p95 / 328 ms p99**.

---

## 6. Project layout

```
stealthtap-ntro/
├── src/
│   ├── alert_schema.py            standardized Alert (PS constraint e)
│   ├── flow_mapping.py            single record→flow mapper (all four paths import this)
│   ├── engines/                   ENG01–13
│   ├── features/feature_extraction.py   canonical features (train + serve)
│   ├── inference/                 HybridModelServer (ONNX), ml_alerts
│   ├── capture/                   live capture: interfaces, ja4, flow_assembler, backends, live_agent, forwarder
│   ├── api/                       FastAPI app, /analyze/pcap, /capture/*, /alerts/ingest
│   ├── relay/, storage/           streaming-path relay + OpenSearch client
│   └── offline_engine.py, streaming_engine.py, log_shipper.py
├── models/                        trained ONNX + MANIFEST.json + *_feature_importance.json
├── scripts/
│   ├── train_family.py            hybrid model trainer (train/serve parity)
│   ├── analyze_local.py           run the PCAP pipeline locally, no infra
│   ├── setup_netns.sh             air-gapped capture namespace (zero IP, promisc)
│   └── simulate_attacks.py, yara_scan_worker.py
├── rules/                         ~401 YARA rules + 20,829 Suricata ET Open rules
├── intel/                         real JA4 threat intel (FoxIO)
├── dashboard-app/                 React + TypeScript + Vite (Upload + Live modes)
├── docs/                          PRD.md, MODEL_CONTRACT.md, TRAINING_GUIDE.md, LIVE_CAPTURE_DEPLOYMENT.md
├── docker-compose.yml             11 core services + `sensor` (profile: tap)
├── Dockerfile, sensor.Dockerfile, zeek-batch.Dockerfile, suricata-batch.Dockerfile
├── requirements.txt / requirements-train.txt
└── pcap_simulator.py, pcap_parser.py, benchmark_pipeline.py
```

---

## 7. Current status — honest

| Component | Status |
|---|---|
| Rule engines (DDoS, recon, exfil, OT/Modbus, HTTP, brute-force) | working, verified against real captured traffic |
| DNP3 + EtherNet/IP OT detection | working (byte-level verified codes); parsed & analysed end to end |
| Suricata (20,829 ET Open rules) | **working, fully integrated** — real detections through the production code path, concurrent with Zeek |
| YARA | 401 rules, verified detections |
| DGA/DNS-tunnelling ML (`dns`) | trained full-scale (674,898 rows), curve-derived threshold |
| `flow` + `modbus` ML | **newly trained** on the in-repo labelled CSVs, real held-out metrics |
| `tls` ML | not trained (no public labelled JA4 set) — ENG-04 runs rule-based with **real JA4** |
| Kerberoasting (ENG-11), BZAR (ENG-12) | working / builds & parses; not yet exercised against a real attack pcap |
| Live capture (kernel-level, dashboard-driven) | **working** — real NIC capture, real JA4, DNP3, latency/throughput telemetry |
| Stealth `sensor` service | built — host network, minimal caps, no ports, read-only, forwards to shared DB |
| Live streaming path (Zeek→Redpanda→Faust) | engine-parity with the upload path; not yet load-tested end to end |
| Pipeline coverage transparency | every analysis reports per-tool records-processed / alerts-fired |
| Detection latency & throughput (PS constraint d) | **measured on the live path** (p50/p95/p99 + pps/Mbit/s + kernel drops), reported live in `/capture/status` |

**Known open items:** (1) upload-path JA4 in `zeek-batch` is disabled — `FoxIO-LLC/ja4` is not a valid zkg shortname; set the `JA4_ZKG_SOURCE` build arg to a reachable source to enable it (the **live path** JA4 works via `src/capture/ja4.py`). (2) `flow`/`modbus` models were trained on modest in-repo datasets — retrain on CICIDS2017/2018 and CIC Modbus 2023 per `docs/TRAINING_GUIDE.md` for submission-grade numbers. (3) the live streaming path needs a real load test. (4) on some Windows dev hosts scapy's first import is slow/blocking — `SCAPY_USE_PCAPDNET=1` (set automatically by `src/capture/__init__.py` and `tests/conftest.py`) mitigates it; Linux/Docker are unaffected.

Full detail: **`docs/PRD.md`** and **`docs/StealthTap_PRD_Status_Gap_Report.md`**.

---

## 8. License notes

Bundles third-party open-source detection content, licenses kept alongside:
- `rules/LICENSE_AND_ATTRIBUTION.md` — YARA rules (GPLv2, Yara-Rules/rules)
- `intel/LICENSE_AND_ATTRIBUTION.md` — JA4 threat intel (FoxIO License 1.1)
- Suricata ruleset — Emerging Threats Open (MIT/BSD, mixed per file)
- BZAR — MITRE-authored (github.com/mitre-attack/bzar), loaded via Zeek's package manager
