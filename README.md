# StealthTap

Passive AI-DPI network threat detection — SIH 2026, Problem Statement 26145 (NTRO), Team XOR.

StealthTap inspects network traffic (uploaded PCAPs, live capture on a chosen interface, or streamed Zeek logs) and raises typed security alerts using 13 rule/statistical engines, three trained ML models, and an unsupervised per-network behavioural baseline — without ever storing packet payload. Packet parsing and flow assembly (both the upload and live paths) run on a validated native Rust core (`native/stealthtap_core`); detection logic stays in Python, unchanged, with an automatic fallback to the pure-Python parser if the native module isn't built.

**Runs two ways:**
- **Docker stack** — full pipeline: real Zeek 6.0.3 + 6 ICSNPP OT plugins, Suricata (20,829 ET Open rules), YARA, Postgres, Redis, React dashboard.
- **Standalone desktop app** (`stealthtap_app.py`, meant to be packaged with PyInstaller — see the packaging caveat below) — no Docker/Redis/Postgres, for Windows and Linux. Select a network interface like Wireshark and watch alerts live.

## Honest accuracy — read before deploying

This is the single most important thing in this document. Every other network-security README you've read says "99% accuracy." We measured ours, against real attack and benign captures (not the training data), with a reproducible harness — and it is not that.

Run: `python scripts/eval_real_traffic.py "<pcap folder>" --out eval_results`

Latest measured result (25 real attack captures — Hydra brute force, BlackEnergy, Mirai, UnrealIRCd, distcc backdoor, and others — plus 2 benign captures of ordinary desktop traffic; file-level ground truth, no OpenSearch/Suricata in this run):

| Config | Attacks detected | Benign captures clean | Benign flow false-positive rate |
|---|---|---|---|
| Rule engines only | 18/25 (72%, 95% CI 52–86%) | 1/2 | 0.48% |
| AI models only | 9/25 (36%, 95% CI 20–55%) | 0/2 | 0.64% |
| Hybrid (rules + AI) | 20/25 (80%, 95% CI 61–91%) | 0/2 | 1.12% |

**What this means in practice:**
- Rules carry detection; the shipped ML models do not generalize well alone. The `flow` model (trained on 8 DDoS captures) is now gated to **corroboration-only** — it can raise an alert on its own only above 2.0 confidence, i.e. never — because standalone it flagged ordinary DNS-over-UDP flows as `VOLUMETRIC_DDOS` at 99% confidence on live home-network traffic (its training set is DDoS-shaped 4-feature flows, not general traffic).
- The DNS DGA model is solid (674,898 rows, real held-out precision 0.94/recall 0.88) and is used as shipped.
- Every "recall" number above has a **wide confidence interval** — 25 files is a small, non-independent sample (several are near-duplicate pairs from one lab). Treat these numbers as a floor and a methodology, not a market claim.
- This measured run used the in-process parser only (Zeek/Suricata require Docker, which was unavailable when this run was taken) — Docker-path rule recall should be measured separately and is expected to be higher with Suricata's signature set included.
- **AI-based detection with no rules is currently the weakest configuration on this dataset**, not the strongest — see `docs/PRD.md` §7 for why, and what changes that.

See `docs/PRD.md` for the full methodology, root-cause fixes already applied (flow-direction inference, exfiltration volume floor, recon-vs-normal-browsing distinction, DGA registrable-domain scoring), and what's still open.

## Honest throughput — read before deploying at high speed

Same rule as accuracy: measured, not asserted.

| Layer | Measured throughput | Meets the 1-5 Gbps target? |
|---|---|---|
| Native Rust parser/assembler alone (parsing + flow assembly, no detection) | 393,856 pps (`samples/netbios_ssn2.pcap`) — comfortably 1-5+ Gbps at realistic packet sizes | Yes |
| Full pipeline: native assembly + all 13 engines + 3 ONNX models, one core | ~4,800-7,000 pps (up from ~1,580 pps before this round of fixes) | **No** — roughly 50-80x short |

**Why the gap:** parsing is compiled, typed, zero-copy Rust; detection is 13 engines of interpreted Python running sequentially on every flow. That's an architectural ceiling, not a bug — profiling (not guessed at) found and fixed three real, measurable costs along the way:
- Stateful engines (flood/beacon/exfil/bruteforce counters) were paying Redis network round-trip latency on every flow, even on localhost — switched the default backend to an in-process store (`src/capture/scoring.py`); **measured 3x** on identical detection code, only the backend changed.
- DNS/SSL/Modbus ML scoring was calling ONNX one record at a time; batched it, matching the pattern already used for connection-flow scoring.
- Two profile-guided fixes: the live path was needlessly re-serializing an already-parsed packet before handing it to the native assembler (~15% of pipeline time), and one engine (`ENG-05`, recon) was rebuilding a full history set on every flow instead of only when a new probe was added (~20%).

**What would close the remaining gap**: a fast-path/slow-path split — native triage on every flow, full Python engine scoring only on flows actually flagged — not yet built. See `docs/PRD.md` §11 for the full methodology and every number behind this table.

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

## The 13 detection engines

| Engine | Threat class | Method |
|---|---|---|
| ENG-01 | Volumetric DDoS / Slowloris | RedisBloom Count-Min Sketch flood counter + HyperLogLog spoofed-source ratio, per 10s window |
| ENG-02 | C2 beaconing | Coefficient-of-variation on inter-arrival times (catches jittered beacons, not just perfect periodicity) |
| ENG-03 | DGA domains / DNS tunnelling | Trained XGBoost+IsolationForest on registrable domain, or deterministic lexical heuristic fallback |
| ENG-04 | Encrypted malware (JA4) | Real JA4 TLS fingerprint (live path) matched against threat intel |
| ENG-05 | Reconnaissance | Fan-out of **unanswered probe-shaped** flows per source per 5 min (excludes normal browsing) |
| ENG-06 | Data exfiltration | Per-flow byte-ratio (with a volume floor) + accumulated low-and-slow ratio over 5 min |
| ENG-07 | OT/ICS anomaly | Modbus + DNP3 dangerous function codes |
| ENG-08 | Malicious files | YARA scan of Zeek-extracted cleartext files |
| ENG-09 | HTTP threats | Suspicious user-agent + high-entropy URI |
| ENG-10 | Signature match | Suricata ET Open (20,829 rules) |
| ENG-11 | Kerberoasting | Kerberos service-ticket request pattern |
| ENG-12 | BZAR notices | Zeek BZAR ATT&CK-for-ICS notices |
| ENG-13 | Brute force / credential stuffing | Connection-attempt rate to auth ports (10 attempts/60s, below both measured real attack rates) |

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

## Quick start — Docker (full stack)

```bash
cp .env.example .env   # set real passwords, never commit .env
docker compose up -d --build
```
Dashboard: http://localhost:4173 · API: http://localhost:8000

## Quick start — standalone desktop app (no Docker)

```bash
python stealthtap_app.py            # dev mode, opens http://127.0.0.1:8100
```
Or build a single executable:
```bash
cd dashboard-app && VITE_API_BASE= VITE_LIVE_API_BASE= npx vite build --outDir ../build/ui --emptyOutDir && cd ..
pip install pyinstaller
pyinstaller packaging/stealthtap.spec --noconfirm      # -> dist/stealthtap(.exe)
```
Live capture needs elevated privileges (Administrator on Windows, root/`CAP_NET_RAW` on Linux). **Windows also needs [Npcap](https://npcap.com/) installed separately** — its free licence forbids redistribution, so it is never bundled; the app detects it at runtime.

**Packaging status — disclosed, not glossed over**: this frozen build has not yet been produced or run. `packaging/stealthtap.spec` does not currently declare the native Rust module (`native/stealthtap_core`) as a binary to bundle, so a build today would most likely fall back to the slower pure-Python parser at runtime rather than fail loudly. Fix and a real build-and-run test are needed before treating the `.exe`/Linux binary as deliverable — see `native/README.md`.

## Verify it yourself

```bash
python -m pytest tests/ -q                                             # 69 unit/integration tests
python scripts/analyze_local.py samples/simulated_attack_traffic.pcap  # full pipeline, no Docker
python scripts/eval_real_traffic.py "<your pcap folder>" --out eval_results  # accuracy on real data
python scripts/validate_native_parser.py "<your pcap folder>"          # native upload-parser vs. Python, byte-for-byte
python scripts/validate_native_live_assembler.py "<your pcap folder>"  # native live-assembler vs. Python, byte-for-byte
python scripts/bench_throughput.py "<some.pcap>"                       # measured live-pipeline pps/Mbit/s, not estimated
```

## Everything is open-source, no paid components

Zeek (BSD), Suricata (GPLv2), YARA (BSD), ICSNPP (BSD-3), XGBoost/scikit-learn/ONNX (Apache-2/BSD), React (MIT). Windows capture uses Npcap, which is free (not open-source) for up to 5 systems and is never bundled or redistributed by this project — see the licence at npcap.com.

## Documentation

- `docs/PRD.md` — full requirements, methodology, root-cause analysis, roadmap
- `native/README.md` — native Rust core: scope, validation methodology, measured performance, what's still Python-only
- `docs/LIVE_CAPTURE_DEPLOYMENT.md` — deploying the live/streaming sensor
- `docs/MODEL_CONTRACT.md` — feature schema, train/serve parity contract
- `CHANGES.md` — change history
