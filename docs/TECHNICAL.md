# StealthTap — Technical Reference

Deep-dive reference for engineers: architecture, detection engines, ML models, the OS-level capture APIs, and the measured
accuracy/throughput/latency numbers. For an overview see [`README.md`](../README.md); for install/deploy steps see
[`INSTALLATION.md`](INSTALLATION.md); for the full requirements/methodology/history see [`PRD.md`](PRD.md).

## Contents
- [Architecture](#architecture)
- [The 14 detection engines](#the-14-detection-engines)
- [Trained ML models](#trained-ml-models)
- [OT/industrial protocol coverage](#otindustrial-protocol-coverage)
- [OS-level capture: Windows and Linux APIs used](#os-level-capture-windows-and-linux-apis-used)
- [Accuracy — measured, not asserted](#accuracy--measured-not-asserted)
- [Throughput and latency — measured, not asserted](#throughput-and-latency--measured-not-asserted)
- [Verifying it yourself](#verifying-it-yourself)

## Architecture

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
     14 rule/statistical engines (ENG-01..14)              3 trained ONNX models
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

Packet parsing and flow assembly (both the upload and live paths) run on a validated native Rust core
(`native/stealthtap_core`) — see [`native/README.md`](../native/README.md) for its exact scope and validation methodology.
Detection logic (every threshold, every accuracy fix) stays in Python, unchanged; the native module never changes what fires,
only how fast the bytes get turned into flows. If the native module isn't built, everything falls back automatically to the
pure-Python parser/assembler — same output, slower.

## The 14 detection engines

| Engine | Threat class | Method |
|---|---|---|
| ENG-01 | Volumetric DDoS / Slowloris | Count-Min Sketch flood counter + HyperLogLog spoofed-source ratio, per 10 s window |
| ENG-02 | C2 beaconing | Coefficient-of-variation on inter-arrival times (catches jittered beacons, not just perfect periodicity) |
| ENG-03 | DGA domains / DNS tunnelling / TLS SNI | Trained XGBoost+IsolationForest on registrable domain, or a deterministic lexical heuristic fallback; same model applied to the TLS SNI |
| ENG-04 | Encrypted malware (JA4) | Real JA4 TLS fingerprint (live path) matched against threat intel |
| ENG-05 | Reconnaissance | Fan-out of unanswered probe-shaped flows per source per 5 min (excludes normal browsing) |
| ENG-06 | Data exfiltration | Per-flow byte-ratio (with a volume floor) + accumulated low-and-slow ratio over 5 min |
| ENG-07 | OT/ICS anomaly | Modbus, DNP3, S7comm, IEC-104, EtherNet/IP-CIP, BACnet, OPC UA, PROFINET-DCP dangerous commands; OPC UA weak security policies |
| ENG-08 | Malicious files | YARA scan of Zeek-extracted cleartext files |
| ENG-09 | HTTP threats | Suspicious user-agent + high-entropy URI (excludes OCSP/CRL/CTL certificate-infrastructure fetches) |
| ENG-10 | Signature match | Suricata ET Open (20,829 rules) |
| ENG-11 | Kerberoasting | Kerberos service-ticket request pattern |
| ENG-12 | BZAR notices | Zeek BZAR ATT&CK-for-ICS notices |
| ENG-13 | Brute force / credential stuffing | Connection-attempt rate to auth ports |
| ENG-14 | Plain-text service attacks | distcc non-compiler jobs, SMTP account enumeration, HTTP default credentials / auth guessing / deployment endpoints (payload-decoded) |

Plus the **live-learning baseline** (`src/inference/online_baseline.py`): learns per-service (protocol, port) flow statistics
from *your* traffic (minimum 1,500 flows / 10 minutes), then flags conformal-calibrated outliers — no attack labels, no
pre-trained data. Multicast/broadcast service-discovery traffic (SSDP, mDNS, LLMNR) is excluded from both learning and
scoring, since it is high-variance by protocol design and produced false positives in real testing (see the accuracy section).

## Trained ML models

| Family | Training rows | Precision / Recall / F1 / ROC-AUC | Alerting policy |
|---|---|---|---|
| `dns` (DGA) | 674,898 | 0.94 / 0.88 / 0.91 / 0.97 | Standalone, on registrable domain |
| `flow` (DDoS-shaped) | 23,213 attack rows + 8,937 real benign flows (retrained) | 0.9996 / 0.9985 in-distribution; 0.00%–0.8% FPR on real benign flows after retraining (see accuracy section) | **Corroboration-only** by default |
| `modbus` | 51,608 | 1.0 / 1.0 / 1.0 / 1.0 in-distribution | **Corroboration-only** — flags 13.8% of real writes, duplicating ENG-07 |

Isolation Forests are trained but demoted to advisory everywhere (F1 < 0.3 on held-out data) — XGBoost drives every family.
`models/MANIFEST.json` has the full numbers. Neither `flow` nor `modbus` alerts alone by default
(`ML_FLOW_STANDALONE_CONFIDENCE`, `ML_MODBUS_STANDALONE_CONFIDENCE`) — see [`INSTALLATION.md`](INSTALLATION.md) for how to
change that per-deployment, and only after measuring with `scripts/flow_model_operating_points.py` on that network's own
traffic.

## OT/industrial protocol coverage

| Protocol | Status |
|---|---|
| Modbus TCP, DNP3 | Zeek + ICSNPP, Suricata, dedicated detection (ENG-07) |
| EtherNet/IP, S7comm(+plus), OPC UA, PROFINET (IO-CM) | Zeek + ICSNPP parsers + dedicated ENG-07 detection (native Rust + Python decoders) |
| IEC 60870-5-104 | Native decoder + ENG-07 detection |
| IEC 61850 (GOOSE/SV/MMS), EtherCAT, HART-IP | Third-party open parsers exist; not integrated |
| Modbus RTU, PROFIBUS DP/PA, Foundation Fieldbus H1, wired HART | **Serial buses — not visible on any Ethernet capture.** Need a serial adapter or protocol gateway; out of scope for a NIC-based sensor |

## OS-level capture: Windows and Linux APIs used

The native Rust core (`native/stealthtap_core/src/capture.rs`, `src/capture/backends.py`) picks the fastest capture path each
OS actually offers, in this priority order, with automatic fallback:

| Priority | Platform | Mechanism | Functions / APIs |
|---|---|---|---|
| 1 | Linux | Raw `AF_PACKET` socket with a kernel-side `PACKET_MMAP` RX ring and `PACKET_FANOUT` load-spreading across worker processes | `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)`, `setsockopt(SOL_PACKET, PACKET_RX_RING, …)`, `PACKET_FANOUT`, plus an in-kernel classic-BPF filter |
| 1 (opt-in) | Linux | AF_XDP kernel-bypass capture, behind the `afxdp` Cargo feature (`native/stealthtap_core/src/afxdp.rs`) | libxdp/libbpf via `xsk-rs`; zero-copy where the NIC driver supports it |
| 2 | Windows | Npcap (WinPcap-API-compatible driver) loaded at **runtime** via `libloading` — no SDK or import library needed at build time, and a machine without Npcap gets a clear error instead of an unloadable module | `pcap_create`, `pcap_set_snaplen`, `pcap_set_promisc`, `pcap_set_timeout`, `pcap_set_buffer_size`, `pcap_activate`, plus `pcap_setbuff` / kernel NPF ring enlargement from `scapy.libs.winpcapy` on the Python fallback path |
| 3 | Linux/macOS fallback | `libpcap` (`libpcap.so.0.8` / `.so.1` / `.dylib`) via the same runtime-loaded FFI shim as Npcap — same function names, since Npcap is WinPcap/libpcap-API-compatible | same `pcap_*` functions as above |
| 4 | Any OS | Portable scapy-based backend (`ScapyBackend` in `src/capture/backends.py`) — libpcap/Npcap under scapy, kernel BPF filter, enlarged kernel ring buffer | scapy's own `L2socket`/`AsyncSniffer`, backed by the same `pcap_*` calls |

Notes:
- **Windows requires [Npcap](https://npcap.com/)** installed separately with "WinPcap API-compatible Mode" — its free licence
  forbids redistribution, so it is never bundled with this project. With Npcap in "Administrators only" mode (the default),
  the sensor process must run elevated — see [`INSTALLATION.md`](INSTALLATION.md) for the auto-restarting SYSTEM task that
  avoids a UAC prompt on every capture start.
- **Link-layer handling**: real NIC capture is always Ethernet-framed; the live assembler's scope is Ethernet only (confirmed
  against `src/capture/backends.py`). Classic-pcap file parsing (the upload path) also accepts Linux-cooked-capture framing.
- **Fast path vs. slow path**: `AFPacketBackend` and Npcap/libpcap both hand raw frames straight to the native Rust
  `LiveFlowAssembler` (`RawFrame`, zero-copy where possible) — no scapy dissection in the hot path. The portable `ScapyBackend`
  is the automatic fallback when neither of the above is usable (e.g., AF_PACKET unavailable, Npcap not installed).
- **Why runtime loading, not linking**: `native/stealthtap_core` is a single binary that runs on Windows and Linux without a
  platform-specific build variant for the capture layer — it locates and loads whichever driver (`wpcap.dll` /
  `libpcap.so*`) is actually present on the host at process start, not at compile time.

## Accuracy — measured, not asserted

Every network-security README says "99% accuracy." This project measured its own, against real attack and benign captures
(not the training data), with a reproducible harness — run it yourself: `python scripts/eval_real_traffic.py "<pcap folder>"
--out eval_results`.

**Labelled real-attack corpus** (25 real attack captures — Hydra brute force, BlackEnergy, Mirai, UnrealIRCd, distcc backdoor,
and others — plus 2 benign captures of ordinary desktop traffic; file-level ground truth):

| Config | Attacks detected | Benign captures clean | Benign flow false-positive rate |
|---|---|---|---|
| Rule engines only | 24/25 (96%, 95% CI 80–99%) | 1/2 | 0.16% (1 of 624 flows) |
| AI models only | 5/25 (20%, 95% CI 9–39%) | 2/2 | 0.00% |
| Hybrid (rules + AI) | 25/25 (100%, 95% CI 87–100%) | 1/2 | 0.16% (1 of 624 flows) |

**Read the 25/25 correctly.** Six captures (`distcc_exec_backdoor`, `smtp`, `tomcat` and their `*2` twins) were only detected
after ENG-14 was written specifically from inspecting them — that detection is **in-sample**: it proves the rules work on
real traffic, not that the same recall holds on unseen exploits. The one alert on the "benign" `normal.pcap` is a true
positive (a real nmap-style SYN scan of the router in that file). Every recall number above has a wide confidence interval —
25 files is a small, non-independent sample.

**Out-of-sample confirmation with real attack tools** (not the same tools/exploits the rules were written from):
- Real nmap NSE scripts (`http-default-accounts`, `http-brute`) and `curl` PUT of a WAR file against a real Apache Tomcat 8.5
  in an isolated Docker network: **3/3 attack captures detected**, benign control (browsing, a mistyped password,
  strong-credential logins) stayed clean. Found and fixed one real gap: a deployment request that itself carried a default
  credential was under-reported.
- Real nmap NSE `distcc-cve2004-2687` (the actual exploit script): **initially missed** — the script splits its handshake
  across two TCP segments, which the decoder didn't reassemble. Fixed (bounded per-flow reassembly buffer, Rust + Python);
  now detected.
- Real Python smtplib account enumeration (30 VRFY + 30 RCPT probes): detected. Real nmap `smtp-enum-users` sending only 2
  VRFY probes: **not detected** — a documented, deliberate gap (the rule needs 3 distinct probes; lowering the threshold to
  1–2 would flag ordinary mail-server administration).

**Real benign network tests (the number that matters for false alarms):**
- A 20-minute live capture on a real Wi-Fi network (7.0M packets, 8,593 flows, 294 hosts) first raised 23 false positives
  across five distinct causes (broadcast heartbeats mistaken for C2, OCSP/CTL certificate fetches, idle keepalives mistaken
  for Slowloris, mDNS mistaken for a DDoS flood, an ordinary upload mistaken for exfiltration). All five fixed; replay now
  raises 1 alert per 8,593 flows.
- A follow-up 1.76-hour continuous live run on the same network, after the fixes: **0 kernel/record/user-space packet drops**,
  memory flat (+1.82 MB/hour after warm-up), and one further false-positive kind found and fixed live — the unsupervised
  baseline detector flagging ordinary SSDP/mDNS device-discovery traffic. Reconfirmed live after the fix: 1,866 real SSDP and
  16,187 real mDNS packets passed through with zero false alerts.
- 343 real industrial-control captures from many public sites (5,497 flows): 1 generic-engine false positive total. This also
  found the Modbus ML model duplicating ENG-07's rule (13.8% of real writes) — now corroboration-only.

**The flow ML model's false-positive rate — a real number, and its fix.** The shipped model was trained on only ~600 benign
flows and measured 23.7% FPR on 8,937 real benign flows at its default threshold. Retrained on a large real benign set (time
split, so the held-out minutes are unseen): **0.00% FPR on held-out minutes of the same network, 0.8% on flows from other
networks it never trained on**, with DDoS-capture recall unchanged at 99.9%. It still does not alert standalone by default —
two networks are not enough to bound the rate at scale, and DDoS is already covered by the rule engine.

Full methodology, every root-cause fix, and the complete history: [`PRD.md`](PRD.md) §7, §13, §14.

## Throughput and latency — measured, not asserted

**Sustained throughput, deployed configuration** (native capture, sharded flow assembly, full detection pipeline, real
captured traffic mix): **~950,000 packets/second, 6.0 Gbit/s sustained** — a 15-minute / 127 GB soak with 0 packet drops and
flat memory — comfortably clearing the stated 1–5 Gbps target. With capture sharded across flow-hash threads (default
`min(4, cores/4)`, tunable via `STEALTHTAP_SHARDS`), the same real traffic mix reaches **up to 1.58M pps ≈ 10 Gbit/s**, with
output identical to an unsharded run.

**Live-link results** (real Wi-Fi NIC, through the deployed sensor):
- 60-second validations: capture ratio 1.0039–1.0113 against the NIC's own hardware counters, 0 kernel drops, up to
  ~181 Mbit/s observed.
- 1.76-hour continuous run: capture ratio 1.0029, 0 kernel/record/user-space packet drops, sensor process memory
  156.5→40.1 MB after warm-up with a flat +1.82 MB/hour slope thereafter.
- Detection latency: p95 0.91 ms end to end; worst observed API response time under a 93.8 MB / 565k-flow upload: 58 ms.

### Performance engineering behind the number

Packet parsing and flow assembly are compiled, zero-copy Rust (393,856 pps on that layer alone, unsharded). Detection runs
14 engines; the five most CPU/state-heavy (`ENG-01`, `02`, `05`, `06`, `13`) were ported to native Rust, byte-for-byte
equivalent to their Python originals (`scripts/validate_native_eng*.py`), cutting CPU time on a reference 48,150-packet
capture from 6.66 s to 2.36 s (2.83×). Two further measured fixes: an in-process state store in place of a per-flow Redis
round trip (3× on identical detection code), and batched ONNX inference in place of one call per record. The combination —
native capture and assembly, native ports of the hot-path engines, batched ML, and flow-hash sharding — is what reaches the
950k pps / 6.0 Gbit/s figure above. Full methodology and every intermediate number: [`PRD.md`](PRD.md) §11.

**Decisions made from measurement:** Treelite was evaluated for faster tree inference and not adopted — its GTIL runtime
measured 1.4–4× slower than onnxruntime on these models, and inference is under 1% of pipeline time regardless
(`scripts/bench_inference_backends.py`). A multi-process engine-pool mode exists and is opt-in, not the default — with real
Redis, 4 worker processes measured 5.6k pps versus 44.9k pps single-process, because that mode reintroduces a Redis round
trip per flow for cross-process state.

## Verifying it yourself

```bash
python -m pytest tests/ -q                                             # unit/integration tests (285 at last count)
python scripts/system_check.py [--accuracy]                            # full stack: infra, native, engines, models, perf, accuracy
python scripts/update_priorities.py                                    # refresh docs/PRIORITIES.md from a real check
python scripts/analyze_local.py samples/simulated_attack_traffic.pcap  # full pipeline, no Docker
python scripts/eval_real_traffic.py "<your pcap folder>" --out eval_results  # accuracy on real data
python scripts/validate_native_parser.py "<your pcap folder>"          # native upload-parser vs. Python, byte-for-byte
python scripts/validate_native_live_assembler.py "<your pcap folder>"  # native live-assembler vs. Python, byte-for-byte
python scripts/bench_throughput.py "<some.pcap>"                       # measured live-pipeline pps/Mbit/s, not estimated
python scripts/site_calibration.py "<pcap folder>" --name myrun        # false-positive triage on your own captures
python scripts/flow_model_operating_points.py --benign <your benign captures> --attack-dir <attack captures>  # flow-model FPR at each threshold, on your own traffic
```

Living status: [`docs/PRIORITIES.md`](PRIORITIES.md) (auto-refreshed by `scripts/update_priorities.py`) and the latest full
report in [`docs/reports/LATEST.md`](reports/LATEST.md).
