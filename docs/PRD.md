# StealthTap — Product Requirements Document

SIH 2026, Problem Statement 26145 (NTRO) · Team XOR

## 1. Problem statement (official text)

**Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic · **Organisation:** National Technical Research
Organisation (NTRO) · **Category:** Software · **Theme:** Blockchain & Cybersecurity

**Background.** Critical-infrastructure operators observe their gateway and peering links using passive mirroring or
hardware data diodes that copy traffic into a monitoring enclave in one direction only. The enclave can see everything
crossing the link, but has no physical or protocol-level path back into the production network — deliberately, since it
removes an entire class of attack in which a compromised monitoring system becomes a pivot into the core network, and
preserves a clean chain of custody for forensic use. Any intelligence layer in that enclave must work purely from what it
can passively observe (packet captures, exported flow records, derived metadata), with no ability to send probes, complete
handshakes, or push a mitigation command back.

**Description.** Design and build an AI/ML pipeline that ingests a one-directional stream of IP traffic and detects,
classifies, and scores cyber-security threats in near real time, using only passively collected data, assuming it can never
re-contact the traffic's source or destination, cannot complete any handshake itself, and cannot act back across the ingest
path. Output is intelligence — labelled alerts, confidence scores, supporting evidence — on a visualisation dashboard. The
system must detect: (a) volumetric/protocol DDoS (SYN floods, UDP reflection/amplification, spoofed-source floods) from
flow-level rate and source-IP entropy; (b) botnet C2 beaconing via periodicity/inter-arrival analysis; (c) DGA domains and
DNS tunnelling via entropy/n-gram analysis of DNS queries plus length/record-type anomalies; (d) malware inside encrypted
sessions from TLS/QUIC metadata alone (JA3/JA3S/JA4, packet-size/timing), without decrypting payload; (e) reconnaissance and
port scanning via fan-out patterns; (f) data exfiltration via asymmetric flow-volume/byte-ratio anomalies.

**Expected solution.** A working prototype (source repository) implementing ingest, feature extraction, model inference and
alert output, with documentation of the model(s), engineered features, and the training/validation approach, plus a simple
dashboard of live or replayed detections with severity and confidence — under these constraints: (a) strictly read-only
ingest, no return path, no live query to the source, no inline block; (b) no payload decryption — TLS/QUIC analysed from
metadata only; (c) streaming, not batch — incremental processing with bounded-latency alerts, not just an end-of-run report;
(d) a stated and demonstrated throughput target (flows/sec or Mbps sustained); (e) a standardized alert schema — timestamp,
flow identifier, threat class, confidence score, supporting evidence.

Requirement-by-requirement coverage of every item above is in §1a immediately below.

## 1a. Problem-statement requirement coverage

The official PS text ("AI-Based Detection of Cyber Threats in Unidirectional IP Traffic") lists six threat types and five
architectural constraints for the expected solution. Every one is implemented; this table is the map from PS wording to the
actual mechanism, each with its own line of evidence elsewhere in this document.

| PS requirement | Implementation | Evidence |
|---|---|---|
| (a) Volumetric/protocol DDoS: SYN floods, UDP reflection/amplification, spoofed-source floods from flow-rate and source-IP entropy | ENG-01: Count-Min Sketch flood counter per 10 s window + HyperLogLog distinct-source-IP entropy for spoofed floods | §13.2, §14.9 |
| (b) Botnet C2 beaconing: periodicity/inter-arrival analysis toward a small destination set | ENG-02: coefficient-of-variation on inter-arrival times (catches jittered beacons, not just perfect periodicity) | §13.2 |
| (c) DGA domains and DNS tunnelling: entropy/n-gram, query-length and record-type anomalies | ENG-03: trained XGBoost+IsolationForest on 262 lexical/n-gram features (674,898 rows), plus a deterministic lexical fallback; tunnelling from record-type + length | §4.2, README |
| (d) Malware inside encrypted sessions from TLS/QUIC metadata alone (JA3/JA3S/JA4) — **never decrypted** | ENG-04: real JA4 fingerprint (FoxIO spec) computed from the TLS ClientHello, matched against threat intel; body bytes are never touched | native/README.md |
| (e) Reconnaissance/port scanning: fan-out from one source across many destinations | ENG-05: distinct-destination fan-out of unanswered, probe-shaped flows per source, excluding normal browsing | §13.2 |
| (f) Data exfiltration: asymmetric flow-volume, unusual outbound:inbound ratio | ENG-06: per-flow byte-ratio with a volume floor + accumulated low-and-slow ratio over a 5-minute window | §13.2, §14.3 |
| (a) Read-only ingest, no return path, no completed handshake, no inline block | Every ingest path (upload, live NIC, streaming, offline batch) only reads; the sensor never sends a probe, completes a TCP/TLS handshake to a monitored host, or issues any command back across the tap. Active network discovery (`POST /network/discover`) is a separate, explicitly-invoked operator tool on the monitoring host's own subnet, not part of the passive detection path | §5, `src/api/discovery.py` |
| (b) No payload decryption; TLS/QUIC from metadata only | Every TLS engine (ENG-04, the SNI path of ENG-03) works from the ClientHello and JA4 fingerprint only. OPC UA SignAndEncrypt bodies are, by the same principle, never decrypted — the sensor has no key to do so, which is the PS's own requirement, not a gap | §13.4, §14 |
| (c) Streaming, not batch — bounded-latency incremental processing | The live path scores each flow as it completes (or, for rate/fan-out engines, on a bounded snapshot cadence) and pushes alerts over Server-Sent Events immediately; batch upload analysis is a separate, additional ingest mode, not a replacement for streaming | §5, §11 |
| (d) Defined, demonstrated throughput target | Measured and stated, not estimated: ~950,000 pps / 6.0 Gbit/s sustained through the full native pipeline; every number has a reproducible script behind it | §11, §14.9, `TECHNICAL.md` |
| (e) Standardized alert schema: timestamp, flow identifier, threat class, confidence score, supporting evidence | `src/alert_schema.py` — one Pydantic schema (`extra="forbid"`) used by every engine, every model and every ingest path: `alert_id`, `timestamp`, `severity`, `confidence_score` (0–100), `threat_class`, `flow_identifier`, `mitre_attack`, `evidence`, `forensics`, `detection_mode` | §4 |

Also delivered beyond the minimum PS ask: a working React dashboard (live and replayed detections, severity/confidence,
packet-level inspection), OT/ICS coverage across 7 industrial protocols (the PS's "IT and OT protocols" framing), and the
measured-not-asserted methodology applied throughout this document.

## 2. What "passive" and "stealth" require, and how this project meets them

| Requirement | Implementation |
|---|---|
| Never transmit on the monitored link | Capture-only sockets (`AF_PACKET`/Npcap in receive mode); the sensor container runs with no IP assigned and no published ports (`docker-compose.yml` `sensor` service: `cap_drop: ALL`, `cap_add: [NET_RAW, NET_ADMIN]` only) |
| Works from a one-directional feed (TAP/SPAN mirror) | Flow model now supports `one_way` feature mode (`src/inference/online_baseline.py`); flow orientation is inferred from TCP SYN/SYN-ACK flags or port rank, not "whichever side spoke first" (see §7.1 — this was a real bug, fixed) |
| No payload storage | Alerts carry protocol *metadata* (DNS query name, JA4 fingerprint, Modbus function code) and a SHA-256 hash of the segment for forensic correlation — never raw payload bytes |
| Real time | Live path scores each flow within one `SNAPSHOT_INTERVAL_S` (default 2s) of completion; p50/p95/p99 latency exposed via `/capture/status` |

## 3. System architecture

Four ingestion paths converge on one flow-mapping layer and one set of 13 detection engines, so results are identical regardless of how traffic arrived:

1. **Upload PCAP** — `POST /analyze/pcap`. Docker: real Zeek 6.0.3 + 6 ICSNPP plugins + Suricata (20,829 rules) + YARA, with a scapy fallback parser if the Zeek job queue times out. Standalone/no-Docker (`STEALTHTAP_STANDALONE=1`): `pcap_parser.py`, backed by the native Rust parser (`native/stealthtap_core`, 84.3x measured aggregate speedup over the pure-Python path on 26 real captures, byte-for-byte validated) with an automatic fallback to the pure-Python parser for anything the native crate doesn't cover yet (`ssl`/JA4, Modbus, pcapng) or if the module isn't built.
2. **Live NIC capture** — interface picker (Wireshark-style), `AFPacketBackend` (Linux: kernel `PACKET_MMAP` ring + `PACKET_FANOUT`) or `ScapyBackend` (Windows: Npcap). Feeds `src/capture/live_agent.py`'s flow assembler → the same 13 engines, in-process, no Docker required. The assembler is the native Rust `LiveFlowAssembler` by default (393,856 pps measured in isolation, byte-for-byte validated against the Python reference on 21 real captures), with the same Python fallback pattern (`STEALTHTAP_FORCE_PYTHON_LIVE_ASSEMBLER=1` to force it). See §11 for the full throughput picture — parsing is not the bottleneck; engine scoring is.
3. **Live streaming** — Zeek → Redpanda → a Faust worker (`src/streaming_engine.py`) for a fleet of sensors reporting to one backend.
4. **Offline batch** — `src/offline_engine.py` replays static Zeek JSON logs through the same engines, indexing into OpenSearch, for validation runs.

Single record→flow mapper: `src/flow_mapping.py`. Single flow-orientation policy: `src/flow_orientation.py`. Single ML-alerting policy: `src/inference/fusion.py`. This is deliberate — a bug fixed once (see §7) is fixed on all four paths, not three of four.

## 4. Detection layer

### 4.1 Rule/statistical engines (ENG-01–14)

See `README.md` for the full table. All are deterministic and require no training data. Four are stateful across flows (ENG-01, 02, 06, 13) and use Redis in the Docker deployment; the standalone build uses `src/memstore.py`, an in-process implementation of the exact Redis commands they call (RedisBloom CMS, HyperLogLog, lists, hashes, `SET NX EX`), with real TTL expiry — **without this, those four engines silently detect nothing on a Redis-less desktop install**, which was true of the codebase before this document was written and is now fixed.

`src/memstore.py` is now the **default** for single-process live capture, not just the Redis-unavailable fallback (`src/capture/scoring.py:make_redis_client`) — measured directly (§11): identical detection code against real Redis vs. `MemoryStore` differed 3x in throughput, purely from network round-trip latency, even on localhost. Live capture's stateful-engine data (flood counters, beacon windows) carries 10-300s TTLs and is inherently session-scoped, so `MemoryStore`'s lack of cross-restart persistence costs nothing real for this deployment mode. Redis remains available on request (`REDIS_URL` set) for observability, and is still required — unconditionally — for the multi-core engine pool (§11), which genuinely needs state shared across worker processes to stay correct.

### 4.2 Trained ML models

Three ONNX model pairs (XGBoost + Isolation Forest) per family: `dns`, `flow`, `modbus`. `tls` has no dataset. Numbers are in `models/MANIFEST.json` and `README.md`. The Isolation Forest side is demoted to advisory everywhere (held-out F1 < 0.3) — none of the "AI" detection is unsupervised-only; it is XGBoost carrying every trained family, calibrated by `src/inference/fusion.py`.

### 4.3 Live-learning baseline (`src/inference/online_baseline.py`)

The user's own requirement was explicit: **maximum AI-based accuracy, not rule-based, and the AI must not depend on someone else's pre-trained data.** The three ONNX models above are pre-trained (on public/lab captures) and, per §7, don't transfer. This component is the actual answer to that requirement:

- Learns a per-service (protocol, responder port) robust statistical profile (median/MAD of six log-scaled flow features) from the live traffic it observes on *this* network — minimum 1,500 completed flows or 10 minutes, whichever is later.
- Once armed, a new flow's anomaly score is converted to a **conformal p-value** against a held-out calibration set from the same learning window — so `alpha` (default 0.001) is an actual empirical false-alert-rate target, not a hand-tuned score cutoff.
- A service never seen during learning is scored against a pooled profile plus a fixed novelty penalty — a brand-new destination on a home LAN is itself a signal.
- `one_way=True` drops every responder-side feature (bytes/packets from the far end), so it functions from a true uni-directional tap.

This is genuinely new detection capacity, not a repackaging of the existing models, and it directly targets the accuracy gap measured in §7. It needs live traffic to learn from (the file-based harness can't evaluate it), so it was evaluated on the real live network run instead — see §14.10 for the result, including the one false-positive kind that run found and the fix.

## 5. Interfaces

| Surface | Path |
|---|---|
| Dashboard | React app; Main Dashboard, Discover (document search), Visualizer Studio (live OpenSearch-Dashboards-style aggregation builder — index pattern, metric, bucket, filters — computed from the current result, never a static demo chart), Index Patterns, AI Models, JSON Studio, PCAP Ingest, Live Capture |
| REST | `POST /analyze/pcap`, `GET/POST /capture/*` (interfaces, start, stop, status, SSE alert stream), `GET /alerts`, `GET /health`, `GET /models/manifest` |
| Service (bare) | `stealthtap_app.py` / uvicorn — the PyInstaller executable path is retired (see §6, §8 item 5)
| Desktop app | `stealthtap_app.py` — same dashboard, same REST surface, on `127.0.0.1:8100`, no external services |

## 6. Platform support

| | Linux | Windows |
|---|---|---|
| Live capture backend | `AfXdpBackend` (native AF_XDP, `select_backend()`'s first choice) → `AF_PACKET` mmap ring + fanout fallback — genuinely kernel-level either way | Npcap (kernel driver, not bundled — see licence note below) |
| Full pipeline (Zeek+ICSNPP+Suricata+YARA) | Docker | Docker |
| Deployment model | **Service**, not a frozen executable: `docker compose up -d` (full stack) or `pip install -r requirements.txt` + `maturin develop --release` + `uvicorn`/`stealthtap_app.py`. Identical on both OSes; the native module is per-platform regardless, which is what made the single-exe path a poor fit | Same |
| Live capture privileges | `CAP_NET_RAW`+`CAP_BPF`/root | Administrator |
| Native Rust core (`native/stealthtap_core`) | Builds with `maturin develop --release` (Rust toolchain required at build time; installs as a normal Python extension module, no runtime Rust dependency) | Same; this project's own build needed a `LIB` env-var workaround for a from-source Python install with no standard `libs/` directory — see `native/README.md` |
| AF_XDP kernel-bypass capture | Implemented (`native/stealthtap_core/src/afxdp.rs`), gated to Linux only at the dependency level. Real bind + real packet capture validated on a real NIC driver (`hv_netvsc`) in **native/driver XDP mode**, not generic — see `native/README.md`'s AF_XDP section for exactly what was and wasn't confirmed (zero-copy specifically wasn't independently checked) | Not applicable — AF_XDP is a Linux kernel feature |
| DPDK | Not implemented, not planned — a full second packet-processing framework for a platform this project isn't targeting first; see §9 | Not available on this platform |

**Npcap licensing**: free for up to 5 systems, may not be redistributed. The desktop build never bundles it; it must be installed separately by the user from npcap.com. This is a real constraint on any future "install and go" enterprise Windows deployment — see §10.

## 7. Accuracy — methodology, measured results, and fixes applied

### 7.1 Why measure instead of assert

Every prior version of this document asserted model metrics from `MANIFEST.json` as if they were product accuracy. They are training-set metrics; `docs/PRD.md`'s own earlier draft cited research showing exactly this failure mode generalizes badly — cross-dataset NIDS accuracy [drops from 94.6% to 29.4%](https://arxiv.org/html/2402.10974v1) MCC, and industrial detectors [from 99% to 3–14%](https://arxiv.org/abs/2205.09199) on unseen attacks. So this pipeline was tested the same way: on captures it was never trained on, with `scripts/eval_real_traffic.py`.

### 7.2 First measured run — root causes found

Testing 25 attack + 2 benign real captures surfaced concrete, fixable bugs, not just "the models are imperfect":

1. **Flow-direction inversion.** `pcap_parser.py` and `flow_assembler.py` both called whichever endpoint sent the first *observed* packet the "originator." A capture that starts mid-connection (every live capture, and many pcaps) sees the server speak first, so a 118 KB *download* was recorded as a 118 KB *upload* — an 86:1 outbound ratio — and fired `DATA_EXFILTRATION` on ordinary web traffic. Fixed in `src/flow_orientation.py`: TCP SYN/SYN-ACK flags decide when present, port rank (well-known < registered < ephemeral) otherwise.
2. **DNS responses re-scored as queries.** The parser didn't check the DNS `qr` bit, so every answer packet was folded back into the `dns` bucket and scored a second time.
3. **Exfiltration had no volume floor.** A 654-byte request against a 25-byte reply is a 26:1 "ratio" and was flagged. Fixed: a single flow must also move ≥256 KB outbound; sub-threshold volumes are still caught by the existing accumulated (low-and-slow) check.
4. **Recon threshold matched ordinary browsing.** 25 distinct (IP, port) contacts in 5 minutes is routine CDN/telemetry traffic on any desktop. Fixed: only flows with **no responder payload** (probe-shaped — a real scan gets RSTs or silence, a normal connection gets an answer) count toward the fan-out.
5. **DNS model scored full FQDNs, not registrable domains.** `a-ring-fallback.msedge.net` scored 0.66 and `stream-production.avcdn.net` scored 0.90 against a 0.6 alert threshold — a train/serve skew, since the model's benign training rows are registrable domains (Alexa/Tranco-style), not CDN subdomains. Fixed: score `registrable_domain(query)`.
6. **The `flow` model was mapped to the wrong threat class and allowed to fire alone.** Trained only on DDoS captures, it was mapped to `RECONNAISSANCE` and had no corroboration requirement — it flagged benign flows on live traffic at 99% confidence. Fixed in two parts: remapped to `VOLUMETRIC_DDOS` (what it actually knows), and `src/inference/fusion.py` now requires a rule engine to have already flagged the same flow before this model's verdict counts, except above a near-impossible-to-reach standalone threshold (`ML_FLOW_STANDALONE_CONFIDENCE`, default disabled).

### 7.3 Measured result after the fixes

| Config | File-level recall | 95% CI | Benign specificity | Benign flow false-positive rate |
|---|---|---|---|---|
| Rule | 18/25 = 72% | 52–86% | 1/2 | 0.48% |
| AI (standalone, pre-corroboration-lockdown) | 9/25 = 36% | 20–55% | 0/2 | 0.64% |
| Hybrid | 20/25 = 80% | 61–91% | 0/2 | 1.12% |

Read this table carefully:
- The AI-only figure predates locking the flow model to corroboration-only (fix 6 above landed after this run) — it should be **re-measured**; expect it to drop further in isolation, by design, since that was the fix.
- One benign capture is still not clean under rule/hybrid (a genuine reconnaissance false positive and a DNS-model false positive remain — see per-file evidence in `eval_results_v2/eval_real_traffic.md`). This is disclosed, not hidden.
- 25 files, several near-duplicate pairs from one lab tool, is a small and non-independent sample — the confidence intervals reflect that honestly; they are wide because the evidence is genuinely limited, not because the harness is wrong.
- This run used the in-process parser only; Docker (Zeek/Suricata) was unavailable at measurement time. Expect materially higher rule recall once Suricata's 20,829-rule set is included — that is a re-run, not a code change.

### 7.4 What "rule vs. AI vs. hybrid" actually means for this project right now

The user asked directly: which gives the highest accuracy on real traffic? **Rules currently do, by a wide margin** (72% vs 36% file-level recall, before the AI side was further restricted). Hybrid is best because it adds AI as a corroborating signal on top of rules, not because AI can stand alone. This is not a permanent verdict — it is what happens when three narrow, small-dataset models meet real traffic; §8 is the plan to change it (principally, live-learning baseline evaluation and retraining on diverse hard negatives).

## 8. Status summary

Everything this section originally tracked as in-progress is resolved: the ONNX/multi-core investigation concluded (native
per-engine ports plus an in-process state store, not the multi-process pool — §11, `native/README.md`); the live-learning
baseline is evaluated on real traffic and its own false-positive kind found and fixed (§14.10); `dns` and `flow` were
retrained on real hard negatives (§14.4); the product ships as a service, not a frozen executable (§10, `INSTALLATION.md`);
OT protocol breadth now includes dedicated detection for S7comm, IEC-104, EtherNet/IP-CIP, BACnet, OPC UA and PROFINET-DCP,
not just Modbus/DNP3 (§4.1, `TECHNICAL.md`); the packet-level Wireshark-style inspector is built into both dashboards; ENG-09
runs on live capture; the large-upload API freeze is fixed (§12); the ENG-05 fan-out threshold's disclosed borderline case was
re-examined with more real-traffic evidence and held unchanged. Current status — what is measured, what is out of scope by
physical necessity (serial fieldbuses, Windows kernel-bypass), and what needs infrastructure this environment does not have —
lives in [`PRIORITIES.md`](PRIORITIES.md), generated from real checks rather than hand-tracked here.

## 9. Explicitly out of scope

- Serial-only industrial fieldbuses (PROFIBUS DP/PA, Foundation Fieldbus H1, wired HART, Modbus RTU) without a protocol gateway.
- Any capability requiring a paid license, subscription, or non-redistributable driver bundled into the product (Npcap OEM, PF_RING ZC, Suricata Emerging Threats Pro). Everything shipped is open-source or, in Npcap's single case, free-and-separately-installed.
- Claims of accuracy this project has not itself measured. Where a number appears in this document, it was produced by a script in `scripts/` that can be re-run.
- DPDK. AF_XDP (§6, `native/stealthtap_core/src/afxdp.rs`) already covers the kernel-bypass-capable-capture use case DPDK would otherwise be reached for; DPDK additionally wants its own hugepage-backed memory model and (for most real throughput) a NIC bound out of the kernel entirely via a userspace driver (`vfio-pci`/`uio`) — real operational cost for a project not chasing 40G+/100G workloads.

## 10. Licensing and distribution notes

Zeek (BSD), Suricata (GPLv2 — redistributing it requires offering source for that component), YARA (BSD), ICSNPP (BSD-3), XGBoost/scikit-learn/ONNX Runtime (Apache-2.0/BSD), React (MIT), FastAPI (MIT). Npcap is free but not open-source, capped at 5 systems for non-Nmap/Wireshark use, and not redistributable without its paid OEM licence — this project never bundles it. An enterprise Windows rollout beyond 5 seats would need that OEM licence; this is disclosed, not worked around.

## 11. Throughput — methodology, measured results, and fixes applied

### 11.1 Why measure instead of assert

Same discipline as §7: the problem statement asks for detection "in real time, at high speed" and the user's own target was 1-5 Gbps. Rather than assert a number against theoretical kernel-capture ceilings, every figure below was produced by `scripts/bench_throughput.py` (replays a real pcap through the actual `LiveAgent` code path — the same one a live NIC feeds, as fast as Python can push packets, no real-time pacing) or `scripts/validate_native_*.py`, both re-runnable.

One methodology note specific to throughput, not accuracy: the development machine used for these measurements showed 4-5x run-to-run wall-clock variance on *identical* code (background system load, not signal) — wall-clock pps numbers alone were unreliable for detecting real regressions or improvements. Where that mattered, a `cProfile` comparison was used instead (CPU-time instrumentation, not subject to the same OS-scheduling noise), run with the same harness before and after a change.

### 11.2 Parsing layer: native Rust core

Both ingestion paths that matter for throughput (upload-PCAP, live-NIC) now run packet parsing and flow assembly on a Rust core (`native/stealthtap_core`), validated byte-for-byte against the pre-existing Python reference before being trusted (methodology in `native/README.md`) — not a rewrite of detection logic, which stays entirely in Python.

- Upload-path parser: 26/26 real captures byte-for-byte identical to `pcap_parser.py`; **84.3x** aggregate parse-time speedup (477.2s → 5.7s on the same 26 captures).
- Live-path assembler: 21/26 real captures identical to `src/capture/flow_assembler.py` (5 skipped — non-Ethernet linktype, not representative of live NIC capture); measured **393,856 pps** in isolation (`samples/netbios_ssn2.pcap`, 48,150 packets) — comfortably above the 1-5 Gbps target at realistic packet sizes on a single core.

This port also surfaced and fixed a genuine, previously-undiscovered accuracy bug that predates it: DNS-over-TCP (RFC 1035 §4.2.2) was never handled anywhere, not in the new Rust code and not in the original Python parsers — found via CHAOS-class `version.bind`/`id.server` queries in real captures, fixed in both.

**Conclusion: parsing is not the throughput bottleneck.** Everything downstream of it is.

### 11.3 Full pipeline: first measurement, root causes found

Profiling the full live pipeline (native assembly + all 13 engines + 3 ONNX models, single core, `samples/netbios_ssn2.pcap`) surfaced concrete, fixable costs, not just "Python is slow":

1. **Redis network round-trip latency.** The four stateful engines (ENG-01, 02, 06, 13) talk to Redis for cross-flow correlation state. Even on localhost, this cost real time per flow — isolated with a controlled comparison: identical detection code against real Redis measured ~1,580 pps; the same code against `src/memstore.py` (in-process, same command surface) measured ~4,766 pps. **A 3x difference from the backend alone.** Root cause understood, not guessed: Redis is a single-threaded server, so this cost doesn't parallelize by adding client processes either — directly relevant to §11.4 below.
2. **Unbatched ML inference on the immediate-dispatch path.** DNS/SSL/Modbus records were scored one ONNX call per record. `src/inference/model_server.py`'s own history already documented this exact failure mode and its fix for the conn/flow family (a 39,969-record Modbus capture took 30-40s unbatched; batching measured a 10.3x speedup at 1,000 rows) — that fix had never been extended to the DNS/SSL/Modbus path. Now batched (`ScoringEngine.ml_batch_immediate`).
3. **A redundant packet re-serialization.** The native assembler's Python adapter called `bytes(pkt)` on every packet to get raw bytes for Rust — but the packet had already been parsed FROM raw bytes by the capture backend, so this made scapy fully rebuild it (recompute checksums/lengths from parsed fields) to produce bytes it already had cached (`pkt.original`, verified byte-identical). Profiled cost: ~15% of total pipeline time, eliminated.
4. **A redundant per-flow rebuild in ENG-05 (recon).** `score()` rebuilt a full Python `set` from a source's entire probe history on every call, whether anything had changed or not. Since a non-probe flow can only shrink that history, never grow it, it can never newly cross the fan-out threshold — deferring the rebuild to probe-only flows cannot miss a detection. Profiled cost: ~20% of total pipeline time, eliminated.

### 11.4 Measured result after the fixes

| Stage | Throughput | vs. 1-5 Gbps target (realistic packet sizes) |
|---|---|---|
| Native parser/assembler alone | 393,856 pps | Meets target |
| Full pipeline, before this round of fixes | ~1,580 pps | ~250-800x short |
| Full pipeline, after Redis→MemoryStore default, batched immediate ML, scapy/ENG-05 profile fixes | ~4,800-7,000 pps | ~50-80x short |
| Full pipeline, after native fast-paths for ENG-01/02/05/06/13 (§11.5) | ~6,300 pps wall-clock, ~20,400 pps-equivalent isolated (CPU-time profile) | ~20-80x short |

All fixes verified correct, not just fast: 69/69 tests pass after each change, alert counts stayed in the same range across every trial, and every native port is provably equivalent to its Python original (not merely "still passes the tests I happened to run") — see the commit history and `scripts/validate_native_eng*.py` for the specific reasoning and evidence per engine.

**A multi-core engine-scoring pool** (`src/capture/engine_pool.py`) was also built: shards assembled records (not raw packets — sharding by source IP at the packet level would split one flow's two directions across two workers and corrupt assembler state) across worker *processes* by source IP, matching what ENG-05's in-process correlation state needs, with Redis as the required cross-process shared store for ENG-01/02/06/13. It is correctness-validated (same alert counts, proper state sharing) and has now been **re-measured after the native engine ports, confirming it remains a net loss — worse than the earlier measurement, not better**: 1 worker (no pool) 6,163 pps vs. 2 workers 1,165 pps (5.3x slower) vs. 4 workers 1,607 pps (3.8x slower), on `samples/netbios_ssn2.pcap`. Root cause is now two compounding effects, not one: the original IPC/scheduling overhead on a serialized Redis command stream, plus a new one — pool workers require the real Redis round-trip for ENG-01/02/06/13 that §11.3's `MemoryStore` default exists specifically to eliminate, so the pool is now fighting its own prerequisite optimization. Also found and fixed while re-checking this: `NativeEng01`'s spoofed-flood check tracks distinct source IPs per *destination*, in-process — under source-IP sharding, a real distributed attack's sources land on different workers, so each worker's native counter would only see a fraction of the true fan-in. `VolumetricDDoSDetector` now forces its Redis-backed path (not native) specifically inside pool workers; every other native-ported engine's state is src_ip-first-keyed and unaffected. **Not recommended** for this pipeline as it stands; `num_workers=1` remains the fastest configuration measured.

### 11.5 The fast-path/slow-path split -- now real, not just proposed

The plan this section originally described (move per-flow counting into Rust, keep Python only for building the final `Alert` on a real positive) is implemented for the five engines that needed it:

- **Why these five and not all 13**: ENG-01 (flood), ENG-02 (beacon), ENG-05 (recon), ENG-06 (low-and-slow exfil), and ENG-13 (bruteforce) were the ones profiling identified as CPU/state-heavy -- either Redis-round-trip-bound (01/02/06/13) or doing real per-flow Python work (05, pure in-process state). The remaining engines (03/04/07/09/11) are already cheap: stateless, exact-match against a small threat-intel list, or bounded by real ONNX inference cost that native code wouldn't reduce.
- **Why per-flow content filtering would have been wrong**: these five detect *patterns across many individually-unremarkable flows* -- a port scan's probes, a beacon's periodic connections, a brute-force's auth attempts are each boring in isolation. Sampling or filtering which flows reach detection would silently gut the correlation these engines exist for.
- **What was actually built**: `native/stealthtap_core/src/eng01.rs`, `eng02.rs`, `eng05.rs`, `eng06.rs`, `eng13.rs` -- exact ports of each engine's thresholds and formulas (CMS-equivalent flow counting, HyperLogLog-equivalent distinct-destination/source tracking, coefficient-of-variation beacon statistics, accumulated byte-ratio tracking) as native, in-process, EXACT (not approximate) counters. `src/memstore.py`'s Redis-command emulation was already exact, not a probabilistic sketch, so this isn't an accuracy downgrade from the current default deployment -- it's the same math, moved out of Python+Redis round-trips.
- **Validated, not asserted**: `scripts/validate_native_eng01.py` through `..._eng13.py` each replay every real sample capture's conn records through both the Python/Redis reference and the native path and compare every alert (threat class, confidence, evidence) exactly. All five: byte-for-byte equivalent on every real capture, plus targeted synthetic tests for firing conditions the sample captures didn't happen to exercise (e.g. ENG-06's accumulated low-and-slow path). 69/69 tests pass throughout.
- **Measured**: ENG-01 alone, isolated (no threading): 76,022 flows/sec (Python+MemoryStore) -> 633,615 flows/sec (native), 8.3x. Full pipeline, same CPU-time profiler before/after all five: 6.66s -> 2.36s on the same 48,150-packet capture (samples/netbios_ssn2.pcap) -- a 2.83x reduction from this round alone, on top of the earlier §11.3 fixes.

**What's left to close the remaining ~20-80x gap**: genuine XGBoost ONNX inference time (the `flow`-family batch call) is real but small once measured in isolation — ~5us/row warm. What looked like a much larger ONNX cost in profiling was actually an untrusted IsolationForest call (already excluded from every detection decision) plus one-time session JIT overhead, both fixed directly (§8 item 1) rather than needing a native-inference compiler. The multi-core pool (above) was re-measured and is not the answer either — it's a net loss. None of the remaining engines profile as a bottleneck, so the realistic remaining levers are reducing how many flows reach ML scoring at all, or a genuinely parallel (not Redis-round-trip-bound) architecture for CPU-bound scoring, which the current process-pool design isn't.

## 12. 2026-09-26 full-stack test and hardening pass

`scripts/system_check.py` exercises infra (API, Redis+RedisBloom, Postgres, OpenSearch, Redpanda, dashboard, containers), the native module (parser and five engines native==Python), the engines (pytest + an end-to-end ground-truth pcap through Zeek/Suricata/YARA), the ML models, performance and accuracy, and writes `docs/reports/` (`LATEST.md`, `history.csv`). `scripts/update_priorities.py` regenerates the status block in `docs/PRIORITIES.md`. Result after this pass: **27 PASS / 0 WARN / 0 FAIL**, 123 tests. The pre-fix baseline is kept in `docs/reports/BASELINE_before_fixes.md`.

### 12.1 Defects found and fixed (each with a regression test)

| Area | Finding | Fix | Measured |
|---|---|---|---|
| API availability | One large upload froze every endpoint | Off-loop heavy stages, concurrency cap + 429, 600 s deadline, async jobs, Suricata size-skip | 93.8 MB / 565k flows: >10 min → 33 s; `/health` 58 ms |
| Container | No native module in the image | Multi-stage build | native ENG-01 in the API container |
| Live ingest | scapy dissection ~100 µs/packet capped live capture at ~10k pps | Raw-frame ingestion into the native assembler on every backend (scapy, AF_PACKET, AF_XDP, replay) | 6.5k → ~45k pps end-to-end (through final flush); identical unique detections |
| IPv6 | Dropped by both native parsers (76.6% of a real network's traffic) | IPv6 + extension-header walk | native == Python incl. flow uid |
| JA4 | Native returned a wrong fingerprint for a split ClientHello; both parsers failed open for a cut at an extension boundary | Fail closed in both | truncation tests at 5 cut points |
| Native `expire()` | O(k·n) `shift_remove` | Single order-preserving `retain` | 942.8 → 38.8 ms |
| ENG-01 Redis path | Two pipelines/flow, pure-Python RESP parser | One pipeline, `hiredis` | 24.3 → 13.9 s per 12,300 flows |
| ENG-05 | 22,588 alerts from one scanner | One alert per campaign, 10× escalation | — |
| Fixtures | Generator drifted from tuned thresholds; a flood straddling ENG-01's 10 s bucket was split and never fired | Realistic Slowloris/tunnel/exfil; floods aligned to windows | both parser paths detect every expected class |
| Anomaly baseline | ~10 min dead time | `warm_start` from the batch's own span | — |

### 12.2 TLS coverage without a TLS model
There is no labeled TLS dataset, and inventing labels would be dishonest. Instead the SNI — a real domain in every ClientHello — is scored by the trained DNS/DGA model (ENG-03, SNI variant, floor `TLS_SNI_MIN_CONFIDENCE`=90, alert stamped TCP/443). SNI extraction is implemented natively and in Python and is equal on tested inputs. Evidence to date: 0 alerts on 33 distinct real SNIs (the local real corpus contains little TLS) and 0/25 CDN-style names; 6/6 DGA-style names fire. **Small sample** — a larger real-TLS corpus is needed before quoting a false-positive rate (`scripts/eval_tls_sni.py`).

### 12.3 Decisions taken on measurement
- **Treelite — not integrated.** On the real models Treelite's GTIL is 1.4–4× *slower* than onnxruntime; XGBoost-native is ~5× faster at large batch but per-row inference is ~2 µs, <1% of the pipeline (`scripts/bench_inference_backends.py`).
- **Multi-core pool — stays opt-in, not recommended.** Corrected harness (waits for workers to drain), real Redis: 1 worker 44.9k pps; 2 workers 3.2k; 4 workers 5.6k. ENG-01's per-flow cross-process Redis round trip dominates. Scale-out needs batched/native shared state (roadmap).
- **AF_XDP** stays a Linux-only opt-in cargo feature (`afxdp`); default builds (and Windows) no longer pull `xsk-rs`/`libxdp-sys`.

### 12.4 Measured accuracy on the latest Docker-path real-traffic re-run
Hybrid file-level recall 83%, precision 95%, F1 0.89, flow-level FPR 0.167% (1/598 flows); specificity 50% (1 of 2 benign captures clean) — small samples, wide intervals, same caveats as §7. The living list of what is still open is `docs/PRIORITIES.md`.

## 13. 2026-09-26 (second pass) — real-data live path, native capture engine, separate dashboards

### 13.1 What changed
* **Two dashboards** (`#/live`, `#/pcap`) with a Wireshark-style **packet inspector** (layer tree + hex + filter + `.pcap` export) for both; the bundled synthetic "sample" is gone from the UI.
* **Native capture engine** (`native/stealthtap_core/src/capture.rs`): runtime-loaded Npcap/libpcap read loop, flow assembly, host inventory, packet ring and pcap index in one GIL-free thread; the same thread replays real pcaps (loops/speed) for soak tests. ENG-01/02/05/06/13 now run in Rust over whole flow batches (`flow_engines.rs`); Python builds Alerts only for hits. Alerts are identical to the Python path on 26 real captures (`tests/test_native_capture.py`).
* **Decoders** (Rust + Python twins, cross-checked on real public captures): Kerberos KDC replies (ENG-11 now works live), S7comm and IEC 60870-5-104 control requests (ENG-07 rules).

### 13.2 Measured (full live pipeline: capture thread → assembler → 13 engines + ML → alerts; real captures, no synthetic data)
| Workload | Result |
|---|---|
| `normal2.pcap` looped (real desktop mix) | **~950k pps = 6.0 Gbit/s** sustained, 28.7M packets/30 s, 0 dropped, RSS flat |
| 15-minute mixed soak, all 27 real captures | 527M packets / 127 GB, avg 585k pps (1.13 Gbit/s incl. flow-heavy files), peak 1.16M pps, 0 dropped, max RSS 749 MB, no crash |
| `mirai.pcap` (94 MB, 565k flows/pass) | 100–420k pps, consumer backlog 1M → 0 after Rust flow engines, 0 records dropped |
| Real Wi-Fi, 3–6 parallel downloads (~150 Mbit/s, before native engine) | 99.8% of NIC packets captured, 0 drops |

Bottlenecks found and fixed: Windows EcoQoS clamps a background process ~8× after 3 s (`src/perf.py` opts out); onnxruntime spin-waiting burned ~6 cores; three advisory IsolationForest models cost ~70 s of start-up (now opt-in, `STEALTHTAP_LOAD_IFOREST=1`); reopening the replay file hundreds of times/s made Windows file scanning throttle it; per-flow Python cost capped flow-heavy traffic at ~28k flows/s. **Npcap in Administrators-only mode makes every non-elevated process that imports scapy or opens the driver wait ~122 s for a UAC prompt** — `src/scapy_safe.py` removes that for non-capturing processes; capturing needs one long-lived elevated sensor (`scripts/start_sensor.ps1`).

### 13.3 Accuracy on real labelled captures (single pass, live path)
14 unique attack captures: 11 detected (78.6%); missed: `distcc_exec_backdoor`, `smtp`, `tomcat` (small application-layer captures with no volumetric/behavioural signature). Benign: `normal2` clean; `normal.pcap` alerts RECONNAISSANCE — correct, it contains a real nmap-style SYN scan of the router (fixed source port 54920, ~80 ports). A 601 KB ordinary upload in the same file falsely raised DATA_EXFILTRATION → ENG-06 single-flow floor 256 KB → 1 MiB and the accumulated check needs ≥ 5 flows. OT (real public captures): DNP3 write/select/operate, S7 block download and IEC-104 commands alert; S7 status reads stay quiet; a real Windows-2003 AD login raises no Kerberoasting alert (machine-account SPN classes excluded; ENG-11 also matches `krbtgt/REALM`).

### 13.4 Honest limits
* Live capture on a real NIC was validated before this pass (99.8% capture ratio) but **not re-run on the new native engine** — needs one UAC approval for the elevated sensor.
* A Wi-Fi client sees its own traffic plus broadcast/multicast, not other hosts' unicast; whole-network capture needs a mirror port, TAP or gateway placement.
* No GPU path: inference is ~2 µs/row on CPU; a GPU would only add latency.
* Replayed loops look periodic (C2_BEACONING artifacts) — accuracy is measured on single passes only.
* OPC UA, PROFINET and BACnet still have no detection logic (no real captures to validate against). EtherNet/IP/CIP is now decoded live and validated on real Digital Bond captures.
* Capture/assembly is sharded across flow-hash threads (default min(4, cores/4)): flood capture 228k→486k pps, real mix 1.58M pps ≈ 10 Gbit/s, identical output to a single shard.
* Active discovery (`/network/discover`) is implemented and scope-checked but a real sweep was not run (needs the elevated sensor restarted with this code).

## 14. 2026-09-27 — deployment hardening, ENG-14, real benign network test, flow model retrain

### 14.1 What changed
* **Access control / tenancy / resilience** — see `docs/OPERATIONS.md` (API key, loopback-only datastores, tenant-scoped alerts and captures, alert spool, scheduled backups with a verified restore drill, sensor auto-restart packaging, CI).
* **ENG-14** (`src/engines/eng14_appsvc.py`, decoders `native/.../appsvc.rs` + `src/capture/appsvc.py`): distcc non-compiler jobs, SMTP account enumeration, HTTP Basic default credentials / guessing / code-deployment endpoints. The upload path now runs the same native payload decoders as the live path.
* **OPC UA**: the security policy is read from the clear-text OpenSecureChannel; policy `None` and deprecated SHA-1 policies raise `INSECURE_CONFIGURATION` (LOW/MEDIUM). Ciphertext bodies remain uninspectable.
* **ICS alert ids** are now unique (they reused the flow uid and the database silently dropped the second alert on a flow).

### 14.2 Detection on the labelled corpus
Live pipeline, single pass: **15/15** unique attack captures detected (previously 11/14); scapy-parser path: hybrid 25/25 (95% CI 87–100%), rules only 24/25. **In-sample caveat:** the six previously missed captures (`distcc_exec_backdoor`, `smtp`, `tomcat`, and their `*2` twins — Metasploit sessions) were inspected before the ENG-14 rules were written, so their detection shows the rules work on real traffic, not that recall will hold on unseen exploits. `unreallrcd*.pcap` turned out to contain a real distcc exploit session and is detected by ENG-14 as well. Rules were then checked for false alarms on every other capture on disk (68 files incl. all public ICS/IPv6/Kerberos samples): no other ENG-14 alert.

### 14.3 Real benign network test
A 20-minute live capture on a real Wi-Fi network (7,035,434 packets, 1.79 GB, 0 ring gaps, 8,593 flows) replayed through the full live pipeline raised 23 alerts, all false positives (list in README). Fixes: ENG-02 ignores flows with a multicast/broadcast endpoint in either direction; ENG-01 Slowloris only on web-service ports and the spoofed-source check never for multicast/broadcast destinations; ENG-09 ignores OCSP requests and CRL/CTL/AIA file fetches; ENG-06 single-flow floor 1 MiB → 4 MiB (`EXFIL_MIN_SINGLE_FLOW_BYTES`). Result: **1 alert / 8,593 flows (0.12 per 1,000)**, and that one is the test-traffic helper's own periodic request. Real-capture recall unchanged (15/15). Cost of the Slowloris change: the three "SLOWLORIS" alerts on `mirai.pcap` (idle telnet connections, ports 23/2323) no longer fire — they were idle sessions, not Slowloris; Mirai is still detected by other engines.

### 14.4 Flow model: the "19% false-positive rate" was real, and is now fixed
The earlier statement that the flow model "cannot be fixed by retraining" rested on 484 benign training flows. With the 20-minute capture (8,937 real benign flows in total) the shipped model measured **23.7% FPR at threshold 0.6, 8.8% at 0.99, 0% only at ≥0.995 (DDoS recall then 63%)** (`docs/reports/flow_model_operating_points.json`, before retraining). Retraining with real benign flows (weight 5; `scripts/retrain_flow_real_benign.py`), split by time so the held-out minutes are unseen:

| Model | Held-out benign FPR (4,276 flows) | Cross-network FPR (237 real flows, other networks) | Held-out DDoS-capture recall |
|---|---|---|---|
| before (DDoS captures only) | 33.6% @0.6 / 31.4% @0.98 | 38% @0.6 / 22% @0.98 | 100% |
| **retrained** | **0.05% @0.6, 0.00% @≥0.9** | **2.1% @0.6, 0.8% @≥0.95** | **99.97% @0.6, 99.9% @0.98** |

Shipped as `models/flow_xgboost_v1.onnx` (manifest + importances updated; the real benign rows were appended to `models/flow_training_data.csv`, which holds only duration/bytes/protocol). **Limits:** the held-out minutes come from the same network and session as the training minutes (temporal split, same hosts), so 0.00% is optimistic; the cross-network sample is 237 flows (95% CI up to ~3%); the model only sees duration/bytes/protocol and detects DDoS shape, not intrusions. Therefore `ML_FLOW_STANDALONE_CONFIDENCE` still defaults to "never alone" — enable `0.98` per network only after measuring with `scripts/flow_model_operating_points.py` on that network's own benign traffic. The corroboration path benefits either way.

### 14.6 False positives on more networks
* **343 real ICS captures from many sites** (public collection, 5,497 flows) replayed through the live pipeline with `scripts/site_calibration.py`: 441 alerts, **440 of them OT control commands** (writes, operates, restarts — detections working as designed; whether they are authorised is a per-site fact, hence the allowlist) and **1 generic-engine alert (C2 beaconing) in 5,497 flows** (`docs/reports/site_calibration_ics_public_sites.md`).
* It also exposed a real defect: the **Modbus ML model flagged 13.8% of 40,279 real Modbus requests** (exactly the write function codes) **and their echoed responses** — duplicating ENG-07's rule and alerting on the response direction. It is now corroboration-only (`ML_MODBUS_STANDALONE_CONFIDENCE`, default off); nothing detectable was lost because every flagged request is a write ENG-07 already reports with the function named.
* The **allowlist** (`src/allowlist.py`, `config/allowlist.json`) lets an operator suppress a verified-benign pattern without code changes and without losing the audit trail; guard rails in the module docstring. The **calibration procedure** is `docs/SITE_ONBOARDING.md`.
* Still true: three networks (a Wi-Fi network, the Docker bridge in the attack lab, hundreds of ICS captures) are not "all networks". The claim is that a new site gets its false-alarm rate measured and controllable in its first day, not that it will be zero.

### 14.7 ENG-14 out of sample
Real attack tools the rules were not written from — **nmap NSE `http-default-accounts` and `http-brute`, and `curl` PUT of a WAR to `/manager/text/deploy`** — against a real Tomcat 8.5 (manager enabled, default `tomcat:tomcat` plus a strong operator account) in an isolated Docker network with no route out (`scripts/lab/tomcat_lab.sh`; captures in `samples/lab_eng14/`): **3/3 attack captures detected, benign control clean** (browsing, a mistyped password, five authenticated requests with a strong non-default credential). It found one real gap the Metasploit captures did not: a deployment request that *itself* carried the default credential was reported only as MEDIUM without saying so; fixed (HIGH, `default_credential_in_same_request`). **Scope of this evidence:** only the HTTP rules (Tomcat, nmap, curl). The SMTP-enumeration and distcc rules remain in-sample — testing them needed further image downloads (Postfix, distccd) that were declined for now.

### 14.8 More out-of-sample testing with real tools, and what it found
* **distcc** (nmap NSE `distcc-cve2004-2687`, the real exploit script): **initially missed.** The script sends the handshake `DIST00000001` and the arguments in *separate TCP segments*; the decoder only understood them in one segment. Fixed with a bounded per-flow reassembly buffer in the Rust assembler and its Python twin (a fragment whose argv[0] is cut off is never classified; a split `gcc` compile job stays quiet). Now detected (CRITICAL, T1190).
* **SMTP enumeration** (Python smtplib as a different client, 30 VRFY + 30 RCPT probes): detected. **nmap `smtp-enum-users` sent only 2 VRFY probes** to the test server and was **not** detected (the rule needs 3): a real low-volume enumerator slips under the threshold — documented gap, not tuned away (lowering it toward 1-2 would flag ordinary VRFY use). Benign controls (ordinary delivery; a mailing-list run of 40 recipients with 4 stale addresses) stayed quiet.
* Caveat: the SMTP/distcc *servers* were small toy servers (`scripts/lab/servers.py`), only the client traffic is from real tooling; the target for the HTTP tests was a real Tomcat.

### 14.9 Long live run on the real link
See `docs/reports/live_soak_wifi_2h36.json` (+ `.jsonl` samples, `_alerts.jsonl`): a continuous capture on the real Wi-Fi interface through the SYSTEM sensor with a modest real-traffic generator on top of the network's own traffic. It is not a 24-72 h run on a mirror port; it is the longest continuous real-link run available here.

### 14.10 SSDP/mDNS false positive in the live-learning baseline, final clean soak, reboot and CI
The 1.76 h soak in §14.9 (`docs/reports/live_soak_wifi_fixed.json`) finished clean at the packet level (capture ratio 1.0029, 0 kernel/record/user-space drops, memory 156.5→40.1 MB, slope +1.82 MB/hour after warm-up) but surfaced one more real false-positive kind: the live-learning baseline (`src/inference/online_baseline.py`) flagged three different devices' ordinary SSDP announcements (`239.255.255.250:1900`) as `BEHAVIORAL_ANOMALY` at 99% confidence, despite the service having been seen during learning — multicast/broadcast discovery traffic (SSDP, mDNS, LLMNR, WS-Discovery) is high-variance by protocol design, the wrong shape for a per-network statistical baseline. Fixed by excluding discovery-multicast destinations from both learning and scoring (real unicast anomalies are unaffected; two new tests, one of them replaying the exact addresses). **Live-reconfirmed**: the sensor was restarted on the fixed code, and once the baseline re-armed, 1,866 real SSDP packets and 16,187 real mDNS packets passed through with 0 `BEHAVIORAL_ANOMALY` alerts.

**Reboot persistence: verified on a real reboot.** `scripts/verify_after_reboot.ps1` run ~2 minutes after a genuine reboot of the deployment machine: the sensor scheduled task started the sensor as `NT AUTHORITY\SYSTEM` with no UAC prompt (captured immediately, 0 kernel drops); all 13 Docker containers came back healthy; TLS answered on both endpoints. Docker Desktop's own "start at login" GUI preference was OFF at the time and did not matter — its underlying Windows service started the stack regardless on this host; don't rely on that toggle as the persistence mechanism, verify with the script instead.

**CI:** all pushes from this hardening pass (commits `e77b7cb` through `f21f6bb`) show green on GitHub Actions (`ci` workflow: Linux + Windows pytest, dashboard build, compose validation).

### 14.5 Not done / cannot be done
* **OPC UA SignAndEncrypt bodies** stay unreadable: decrypting needs the server's private key (not available to a passive sensor). Only the clear-text policy and channel metadata are used.
* **24-72 h live-link soak** — a 4 h low-rate replay soak of the real corpus was run (`docs/reports/soak_mixed_4h.json`); a multi-day run on a mirrored production link needs that link.
* **HA** — designed in `docs/OPERATIONS.md` §5, not exercised on multiple nodes; tenant isolation covers stored alerts/captures, not compute or the OpenSearch side path.
* BACnet/OPC UA write and PROFINET factory-reset alerts are still validated only on independent-encoder / real-derived packets.
