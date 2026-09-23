# StealthTap — Product Requirements Document

SIH 2026, Problem Statement 26145 (NTRO) · Team XOR

## 1. Problem statement (as given)

Build a passive, stealth network-monitoring capability that performs deep packet inspection on uni-directional IP traffic, using AI-based and rule-based detection, to identify network intrusions and threats across IT and OT protocols, in real time, at high speed, without altering or injecting traffic.

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

### 4.1 Rule/statistical engines (ENG-01–13)

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

This is genuinely new detection capacity, not a repackaging of the existing models, and it directly targets the accuracy gap measured in §7 — but it has **not yet been evaluated against the real-capture harness** (it needs live traffic to learn from, which the file-based harness doesn't provide). That evaluation is the top open item (§8).

## 5. Interfaces

| Surface | Path |
|---|---|
| Dashboard | React app; Main Dashboard, Discover (document search), Visualizer Studio (live OpenSearch-Dashboards-style aggregation builder — index pattern, metric, bucket, filters — computed from the current result, never a static demo chart), Index Patterns, AI Models, JSON Studio, PCAP Ingest, Live Capture |
| REST | `POST /analyze/pcap`, `GET/POST /capture/*` (interfaces, start, stop, status, SSE alert stream), `GET /alerts`, `GET /health`, `GET /models/manifest` |
| Desktop app | `stealthtap_app.py` — same dashboard, same REST surface, on `127.0.0.1:8100`, no external services |

## 6. Platform support

| | Linux | Windows |
|---|---|---|
| Live capture backend | `AF_PACKET` mmap ring + fanout — genuinely kernel-level | Npcap (kernel driver, not bundled — see licence note below) |
| Full pipeline (Zeek+ICSNPP+Suricata+YARA) | Docker | Docker |
| Standalone desktop app | Yes — needs `CAP_NET_RAW`/root for live capture | Yes — needs Administrator for live capture |
| Native Rust core (`native/stealthtap_core`) | Builds with `maturin develop --release` (Rust toolchain required at build time; installs as a normal Python extension module, no runtime Rust dependency) | Same; this project's own build needed a `LIB` env-var workaround for a from-source Python install with no standard `libs/` directory — see `native/README.md` |
| 10G+ kernel-bypass (AF_XDP/DPDK) | Not implemented — see §8 | Not available on this platform at any tier |

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

## 8. Open items / roadmap

1. **Reduce ONNX inference cost / revisit the multi-core pool** — the fast-path/slow-path split is done for the five engines that needed it (§11.5); the dominant remaining per-flow cost is now genuine ONNX batch-inference time, not Python engine overhead. Either reduce how many flows reach ML scoring, or re-measure `src/capture/engine_pool.py` now that the engines it would parallelize are no longer Redis-bound (not yet re-tested after the native ports).
2. **Evaluate the live-learning baseline** against real live traffic (it cannot be evaluated by the file-based harness — it needs to *learn* before scoring). It is the actual answer to "max AI accuracy, not pre-trained," and it is currently unverified.
3. **Retrain `dns` and `flow` on hard negatives** — CDN/telemetry domains for DNS, diverse non-DDoS benign flows for `flow` — using the real captures in `eval_results*/` as a start.
4. **Re-run the harness with Docker up** (Zeek + Suricata) to get the honest hybrid number including signature matching — Docker was confirmed working on the dev machine (§11 methodology note) but this specific re-run hasn't been done yet.
5. **Fix and test PyInstaller packaging** — `packaging/stealthtap.spec` predates the native Rust module (now five engines' worth of it) and doesn't declare it as a binary to bundle; no frozen build has been produced or run yet. See §11 and `native/README.md`.
6. **OT protocol breadth** — EtherNet/IP, S7comm, OPC UA, PROFINET are parsed but have no dedicated *detection* logic (unlike Modbus/DNP3, which do via ENG-07). IEC 60870-5-104, IEC 61850, EtherCAT, BACnet, HART-IP have open-source Zeek parsers (BSD-licensed, ICSNPP and DINA-community) that are not yet integrated. PROFIBUS, Foundation Fieldbus H1, wired HART, and Modbus RTU are serial buses and are **out of scope for any Ethernet-NIC-based sensor** — no software fix changes this; they need a hardware gateway.
7. **A packet-level, Wireshark-style inspector in the dashboard** — the live/upload UIs currently surface alerts and aggregations (Visualizer Studio), not per-packet drill-down. Not yet built.
8. **Windows kernel-bypass** — no path currently exists beyond Npcap's standard capture mode; not planned unless a specific enterprise requirement calls for it.

## 9. Explicitly out of scope

- Serial-only industrial fieldbuses (PROFIBUS DP/PA, Foundation Fieldbus H1, wired HART, Modbus RTU) without a protocol gateway.
- Any capability requiring a paid license, subscription, or non-redistributable driver bundled into the product (Npcap OEM, PF_RING ZC, Suricata Emerging Threats Pro). Everything shipped is open-source or, in Npcap's single case, free-and-separately-installed.
- Claims of accuracy this project has not itself measured. Where a number appears in this document, it was produced by a script in `scripts/` that can be re-run.

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

**A multi-core engine-scoring pool** (`src/capture/engine_pool.py`) was also built: shards assembled records (not raw packets — sharding by source IP at the packet level would split one flow's two directions across two workers and corrupt assembler state) across worker *processes* by source IP, matching what ENG-05's in-process correlation state needs, with Redis as the required cross-process shared store for ENG-01/02/06/13. It is correctness-validated (same alert counts, proper state sharing) but **is not yet a net throughput win** — root cause is finding 1 above: splitting Redis-bound work across processes adds IPC/scheduling overhead on top of the same serialized Redis command stream, without parallelizing the actual bottleneck. Now that the engines themselves are native and no longer Redis-bound in the default path, this is worth re-measuring -- not yet done.

### 11.5 The fast-path/slow-path split -- now real, not just proposed

The plan this section originally described (move per-flow counting into Rust, keep Python only for building the final `Alert` on a real positive) is implemented for the five engines that needed it:

- **Why these five and not all 13**: ENG-01 (flood), ENG-02 (beacon), ENG-05 (recon), ENG-06 (low-and-slow exfil), and ENG-13 (bruteforce) were the ones profiling identified as CPU/state-heavy -- either Redis-round-trip-bound (01/02/06/13) or doing real per-flow Python work (05, pure in-process state). The remaining engines (03/04/07/09/11) are already cheap: stateless, exact-match against a small threat-intel list, or bounded by real ONNX inference cost that native code wouldn't reduce.
- **Why per-flow content filtering would have been wrong**: these five detect *patterns across many individually-unremarkable flows* -- a port scan's probes, a beacon's periodic connections, a brute-force's auth attempts are each boring in isolation. Sampling or filtering which flows reach detection would silently gut the correlation these engines exist for.
- **What was actually built**: `native/stealthtap_core/src/eng01.rs`, `eng02.rs`, `eng05.rs`, `eng06.rs`, `eng13.rs` -- exact ports of each engine's thresholds and formulas (CMS-equivalent flow counting, HyperLogLog-equivalent distinct-destination/source tracking, coefficient-of-variation beacon statistics, accumulated byte-ratio tracking) as native, in-process, EXACT (not approximate) counters. `src/memstore.py`'s Redis-command emulation was already exact, not a probabilistic sketch, so this isn't an accuracy downgrade from the current default deployment -- it's the same math, moved out of Python+Redis round-trips.
- **Validated, not asserted**: `scripts/validate_native_eng01.py` through `..._eng13.py` each replay every real sample capture's conn records through both the Python/Redis reference and the native path and compare every alert (threat class, confidence, evidence) exactly. All five: byte-for-byte equivalent on every real capture, plus targeted synthetic tests for firing conditions the sample captures didn't happen to exercise (e.g. ENG-06's accumulated low-and-slow path). 69/69 tests pass throughout.
- **Measured**: ENG-01 alone, isolated (no threading): 76,022 flows/sec (Python+MemoryStore) -> 633,615 flows/sec (native), 8.3x. Full pipeline, same CPU-time profiler before/after all five: 6.66s -> 2.36s on the same 48,150-packet capture (samples/netbios_ssn2.pcap) -- a 2.83x reduction from this round alone, on top of the earlier §11.3 fixes.

**What's left to close the remaining ~20-80x gap**: the dominant remaining cost is now genuine ONNX inference time (the `flow`-family batch call), not per-engine Python overhead -- none of the remaining engines profile as a bottleneck. Closing the rest of the gap needs either reducing how many flows reach ML scoring at all, or revisiting the multi-core pool now that the per-flow CPU cost it would parallelize is real (see §11.4's note above and §8 item 1).
