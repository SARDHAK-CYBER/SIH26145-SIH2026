# StealthTap — Full Project Status & Gap Analysis Report

**Project:** StealthTap — Unidirectional Network Threat Intelligence
**Team:** TeamXOR
**Competition:** Smart India Hackathon 2026, Problem Statement 26145
**Organization:** National Technical Research Organisation (NTRO)
**Report basis:** Full source review — PRD, README, `docker-compose.yml`, `requirements.txt`, `setup_netns.sh`, `relay.py`, both `Dockerfile`s, `alert_schema.py`, `schema.py`, `offline_engine.py`, `opensearch_client.py`, `simulate_attacks.py`, `streaming_engine.py`, and all seven detection engines (`eng01`–`eng07`) plus `base.py`.
**Report date:** September 8, 2026

---

## 1. Problem Statement (as issued by NTRO)

**Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Background:** Critical-infrastructure operators observe gateway and peering links using passive mirroring or hardware data diodes that copy traffic into a monitoring enclave in one direction only. The enclave can see everything crossing the link but has no physical or protocol-level path back into the production network — this removes the risk of a compromised monitoring system becoming a pivot into the core network, and preserves a clean forensic chain of custody. The intelligence layer must therefore work purely from passive observation (packet captures, NetFlow/IPFIX/sFlow, derived metadata), with no probes, no completed handshakes, and no action sent back across the ingest path.

**Objective:** Design and build an AI/ML pipeline that ingests a one-directional stream of simulated IP traffic and detects, classifies, and scores cyber-security threats in near real time, using only passively collected data, outputting labelled alerts with confidence scores and supporting evidence on a visualisation dashboard.

**Required threat coverage:**

| # | Threat class | Detection approach specified |
|---|---|---|
| a | Volumetric / protocol DDoS | SYN floods, UDP reflection/amplification, spoofed-source floods via flow-rate and source-IP entropy statistics |
| b | Botnet C2 beaconing | Periodicity / inter-arrival analysis toward a small set of destinations |
| c | DGA domains & DNS tunnelling | Entropy/n-gram analysis, query-length and record-type anomalies |
| d | Malware in encrypted sessions | TLS/QUIC metadata only (JA3/JA3S or JA4, packet-size and timing sequences) — no decryption |
| e | Reconnaissance / port scanning | Fan-out from one source across many destination ports/hosts |
| f | Data exfiltration | Asymmetric flow-volume anomalies, outbound-to-inbound byte ratios |

**Architectural constraints on the expected solution:**

| # | Constraint | Requirement |
|---|---|---|
| a | Read-only ingest | No return path, no live query to source, no inline block |
| b | No payload decryption | TLS/QUIC analysed from metadata only |
| c | Streaming, not batch | Incremental processing, bounded latency — an end-of-run report alone is insufficient |
| d | Defined throughput target | Must state **and demonstrate** a tested rate (flows/sec or Mbps) |
| e | Standardized alert schema | Minimum fields: timestamp, flow identifier, threat class, confidence score, supporting evidence |

**Required deliverable:** A working prototype (source repository) covering ingest → feature extraction → model inference → alert output, a simple live/replayed detection dashboard, and documentation of the model(s), engineered features, and training/validation approach.

---

## 2. Executive Summary

StealthTap is a dual IT/OT threat-detection pipeline built around Zeek (packet parsing), Redpanda (streaming transport), a Faust-based worker layer running six IT detection engines plus one OT engine, and OpenSearch/Dashboards for storage and visualization. The design philosophy — strict network-namespace isolation between a "capture" zone and a "soc" zone, crossed only by a schema-validated Unix-domain-socket relay — is a genuinely strong, well-reasoned answer to the PS's read-only/no-return-path constraint, and goes further than the PS strictly requires.

However, full source review shows a meaningful gap between the **documented architecture** and the **currently runnable system**. The batch/offline path (Zeek logs → Python engines → OpenSearch) is real and working. The streaming path — the one the PS explicitly requires as the primary mode — currently cannot run end-to-end: the process meant to bridge Zeek's output to the detection engines is designed to live in a network namespace that has no route to the message broker it depends on, and nothing yet publishes data onto the topic that broker layer expects to consume. Several other claims in the PRD/README (trained ML models, real forensic hashing, a fully wired SIEM pipeline) are currently stubs or placeholders rather than working implementations.

None of this is unusual for a hackathon-stage prototype, and the underlying engineering is generally sound where it exists. The purpose of this report is to give a precise, evidence-based picture of exactly what is done, what is stubbed, and what is structurally blocked, so remaining effort can be targeted correctly before submission.

---

## 3. Technology Stack (as verified in source)

### Application layer (`requirements.txt`, confirmed)
| Package | Version | Role |
|---|---|---|
| faust-streaming | ≥0.10.16 | Stream-processing framework for live detection engines |
| river | ≥0.21 | Incremental/online ML (named in README; not yet observed in use in any reviewed engine) |
| redis | ≥5.0 | Client for Redis / RedisBloom (Count-Min Sketch) |
| pydantic | ≥2.6 | Alert schema definition and validation |
| opensearch-py | ≥2.5 | OpenSearch client |
| numpy, scipy | ≥1.26 / ≥1.12 | Signal processing (FFT-based beacon detection) |
| torch | ≥2.2 | DGA convolutional model |
| scikit-learn | ≥1.4 | Reserved / not yet observed in use in reviewed engines |
| onnxruntime, safetensors | ≥1.17 / ≥0.4 | Intended model-loading path (avoids pickle deserialization) |
| pytest | ≥8.0 | Test framework (no test files reviewed yet) |

### Infrastructure (`docker-compose.yml`, confirmed)
| Service | Image | Notes |
|---|---|---|
| Redpanda | redpandadata/redpanda:v24.2.7 | Kafka-compatible broker, single-node dev config |
| Redis | redis/redis-stack-server:7.2.0-v11 | Includes RedisBloom (Count-Min Sketch, HLL) |
| OpenSearch | opensearchproject/opensearch:2.14.0 | Requires a real password via `.env`, no default permitted |
| OpenSearch Dashboards | opensearchproject/opensearch-dashboards:2.14.0 | Depends on OpenSearch |

### Capture layer (`Dockerfile` for Zeek, confirmed)
- Base: `zeek/zeek:6.0.3`
- ICSNPP plugins installed: `icsnpp-modbus`, `icsnpp-s7comm`, `icsnpp-enip`, `icsnpp-dnp3` — full OT/ICS protocol parsing coverage
- Runs as a dedicated non-root capability set (`cap_net_raw`, `cap_net_admin` via `setcap`, reinforced by `docker run --cap-add`)

### Network isolation (`setup_netns.sh`, confirmed)
- Two Linux network namespaces: `capture` (IP-less, ARP off, promiscuous — pure passive sniffing) and `soc` (normal addressing, DHCP)
- No veth pair between them; the only sanctioned crossing is a Unix-domain-socket relay (`/var/run/stealthtap/alerts.sock`)

---

## 4. Architecture

```
[Zeek, capture netns — no IP, promiscuous]
        │  (writes JSON log lines: conn.log, dns.log, ssl.log, modbus.log)
        ▼
 ┌────────────────────────────────────────────┐
 │  BATCH PATH (confirmed working)             │
 │  offline_engine.py reads logs/pcap_run/*.log│
 │  → 7 detection engines → OpenSearchStorage  │
 └────────────────────────────────────────────┘

 ┌────────────────────────────────────────────┐
 │  STREAMING PATH (currently non-functional)  │
 │  streaming_engine.py (Faust) expects to     │
 │  consume Kafka topic "stealthtap.flows"     │
 │  from Redpanda, run 6 IT engines, then      │
 │  push alerts to relay.py over a UDS         │
 │                                              │
 │  Gap 1: no producer publishes to the topic  │
 │  Gap 2: file's own docstring places this    │
 │  process in the IP-less "capture" netns,    │
 │  which cannot reach redpanda:9092           │
 └────────────────────────────────────────────┘
        │
        ▼
 relay.py (soc-side, UDS listener)
   — validates against alert_schema.Alert
   — STATUS: sink is a stub; currently prints,
     does not yet bulk-index into OpenSearch
```

**Isolation design:** genuinely strong. No IP ever touches the capture interface; the relay's real security property (as its own docstring states) is schema validation and field rejection, not the transport. This is a better answer to the PS's read-only constraint than most conventional IDS designs.

**The open architectural question:** the streaming engine's requirement to reach Redpanda conflicts with its instruction to run in an IP-less namespace. A workable resolution consistent with the rest of the design: keep Zeek fully isolated with zero IP (as today), write its logs to a shared volume, and run a small, separately-networked "shipper" process that tails those logs and publishes to Redpanda — mirroring the pattern the batch path already proves works, without asking Faust to live somewhere it structurally cannot operate.

---

## 5. Repository Structure (confirmed via `tree`)

```
stealthtap-ntro/
├── logs/pcap_run/            # Zeek-format JSON log output, consumed by offline_engine.py
├── samples/                  # Demo PCAPs
├── scripts/                  # setup_netns.sh and related
├── src/
│   ├── engines/              # eng01–eng07 detectors + base.py (all reviewed)
│   ├── relay/                # relay.py (reviewed)
│   ├── storage/              # opensearch_client.py (reviewed)
│   ├── alert_schema.py       # canonical Alert schema (reviewed — in active use)
│   ├── schema.py             # secondary AlertSchema — confirmed unused/dead code
│   ├── offline_engine.py     # batch entrypoint (reviewed)
│   └── streaming_engine.py   # Faust streaming entrypoint (reviewed)
├── tests/                    # no test files reviewed yet
├── docker-compose.yml        # Redpanda, Redis, OpenSearch, Dashboards
├── requirements.txt          # reviewed
└── zeek/                     # Zeek config (local.zeek not yet reviewed)
```

Not yet reviewed: `local.zeek` config, contents of `tests/`, any `docs/` folder (none observed in the tree — see Gap list), and the individual detector unit tests if any exist.

---

## 6. Current Implementation Status, Engine by Engine

| Engine | Detects | Implementation status | Fires on current test fixtures? |
|---|---|---|---|
| ENG01 | Volumetric DDoS + Slowloris | Slowloris fully implemented; volumetric-burst path is a stub — Redis CMS is incremented but never queried | **No** |
| ENG02 | C2 beaconing | FFT/entropy logic fully implemented and reasonable | **No** — needs 32 buffered samples per flow-key; single-shot test data never fills the buffer |
| ENG03 | DGA / DNS tunnelling | Tunnelling branch (entropy + record type) solid; DGA branch uses an untrained CNN (random weights, no loaded checkpoint) | Tunnelling: **Yes**. DGA: unreliable |
| ENG04 | Encrypted malware (JA4) | Static exact-match against 3 hardcoded hashes, simpler than the Isolation-Forest approach described in the README | **No** — test JA4 doesn't match the hardcoded set. **Also contains a schema bug** (see Gap list) that would crash on a real match |
| ENG05 | Reconnaissance | Fan-out logic correctly implemented, 25-target threshold | **No** — test data only hits 3 distinct targets |
| ENG06 | Data exfiltration | Ratio-based detection correctly implemented | **Yes** |
| ENG07 | OT/ICS (Modbus) | Dangerous-function-code matching correctly implemented; wired into batch only, absent from the streaming detector list | **Yes** (batch only) |

**Net result: 3 of 7 engines currently produce a visible alert against the project's own test fixtures.** This is a test-data and wiring problem more than a detection-logic problem for most of these — the underlying logic in ENG02/ENG05 in particular looks sound and just isn't being exercised correctly.

---

## 7. Problem Statement Compliance Matrix

### Threat coverage (a–f)

| PS requirement | Status | Notes |
|---|---|---|
| (a) Volumetric/protocol DDoS | **Partial** | Only Slowloris implemented; core volumetric case (SYN flood, UDP amplification, spoofed-source) not yet detected |
| (b) C2 beaconing | **Implemented, untested** | Logic present; no realistic multi-flow time-series test data exists yet |
| (c) DGA / DNS tunnelling | **Partial** | Tunnelling solid; DGA detection unreliable pending trained model weights |
| (d) Encrypted malware (JA4) | **Implemented, simplified** | Static hash list rather than the ML-based approach described in the README; also has a schema bug |
| (e) Reconnaissance | **Implemented, untested** | Logic present; test data doesn't reach the fan-out threshold |
| (f) Data exfiltration | **Implemented and verified working** | |

### Architectural constraints (a–e)

| PS requirement | Status | Notes |
|---|---|---|
| (a) Read-only ingest | **Strong** | IP-less capture interface, no veth pair, UDS-only crossing — exceeds the PS's bar |
| (b) No payload decryption | **Met** | JA4-metadata-only approach throughout |
| (c) Streaming, not batch | **Not met** | Only batch has been demonstrated end-to-end; the streaming path cannot currently run (see architecture section) |
| (d) Defined, demonstrated throughput | **Not met** | No load test has been run; PRD's "thousands of flows/sec" is a capability claim, not a measured result |
| (e) Standardized alert schema | **Met, with caveats** | `alert_schema.Alert` is well-structured (Literal-typed, bounded confidence, MITRE mapping, evidence + forensics fields); the forensic hash field is currently a placeholder string, not a real computed hash |

---

## 8. Full Gap & Error List

### Critical — blocking core compliance or demo function

1. **ENG01 volumetric DDoS detection is unimplemented.** The Redis Count-Min Sketch is correctly initialized and incremented on every flow, but nothing ever queries it for a burst threshold. This is PS threat class (a), listed first in the problem statement.
2. **Streaming engine cannot reach its broker.** `streaming_engine.py`'s docstring places it in the IP-less `capture` namespace; it also requires an outbound connection to `redpanda:9092`, which that namespace has no route to. As written, the process cannot start.
3. **No producer publishes to the Kafka flows topic.** Independent of issue #2, nothing currently bridges Zeek's log output into `stealthtap.flows`. Even a networking fix wouldn't produce a working live demo without this.
4. **Relay's OpenSearch sink is a stub.** By its own docstring, `relay.py` currently just prints validated alerts rather than indexing them. Schema validation works; storage does not.
5. **ENG04 has a schema-crashing bug.** It constructs an alert with `threat_class="ENCRYPTED_MALWARE_SESSION"`, which is not in `alert_schema.Alert`'s allowed Literal values (`"ENCRYPTED_MALWARE"` is). This will raise a `ValidationError` the first time the detector legitimately fires — currently masked because the test JA4 hash happens not to match.
6. **No demonstrated throughput number.** PS constraint (d) explicitly requires a stated and tested rate; none has been measured yet.

### High — functional correctness and demo reliability

7. **Test fixtures don't exercise most engines realistically.** Single-flow, single-shot synthetic data cannot trigger engines that need multiple time-spaced observations (ENG02) or larger fan-out counts (ENG05), and the ENG04 fixture's JA4 hash doesn't match its own hardcoded allow-list.
8. **DGA model runs with untrained, randomly-initialized weights.** No checkpoint is loaded despite `onnxruntime`/`safetensors` being included in requirements for exactly this purpose. Results are effectively non-deterministic.
9. **OT detection is absent from the live/streaming path.** `streaming_engine.py`'s detector list omits `eng07`; OT coverage currently exists in batch mode only.
10. **Hardcoded `localhost` in `offline_engine.py` and `opensearch_client.py`.** Inconsistent with `streaming_engine.py`'s correct use of environment-variable-driven, compose-service hostnames. Will fail to resolve if run as its own container on the compose network rather than directly on the host.
11. **OpenSearch credential mismatch risk.** `opensearch_client.py` hardcodes a literal password while `docker-compose.yml` deliberately forces a `.env`-supplied value with no default — these must match exactly, and a hardcoded secret in source is poor practice regardless.
12. **Forensic hash is a placeholder.** `segment_hash` is set to the static string `"simulated_hash_for_pcap"` rather than a real computed hash, undermining the "clean chain of custody" claim central to the PS's own stated motivation for the diode architecture.

### Medium — documentation, hygiene, and correctness details

13. **No model/feature/training documentation exists yet.** Explicitly required by the PS as part of the deliverable; no `docs/` folder was found in the repository tree.
14. **Relay's "drop unrecognized fields" claim isn't enforced in code.** Pydantic v2 ignores extra fields by default unless `model_config = ConfigDict(extra="forbid")` is set on `Alert`; it currently isn't.
15. **Dead, duplicate schema class.** `schema.py`'s `AlertSchema` is confirmed unused by any engine or entrypoint reviewed — safe to delete, but a latent risk if anyone imports it later given it lacks the same validation strictness.
16. **TLS certificate verification disabled** (`verify_certs=False`) in the OpenSearch client, despite the PRD describing the cluster as TLS-secured.
17. **Two conflicting service-launch paths.** `docker-compose.yml` starts OpenSearch/Dashboards on the default bridge network; `setup_netns.sh`'s own printed instructions say to launch them via `docker run --network=ns:/var/run/netns/soc`. These are mutually exclusive as written.
18. **Shared UDS mount unconfirmed.** The relay and its clients need a common bind-mounted path for `/var/run/stealthtap/`; no compose or run configuration reviewed so far sets this up explicitly.
19. **Likely MITRE ATT&CK for ICS ID typo.** ENG07 uses `"T855"`; the standard ID for "Unauthorized Command Message" is `T0855`.
20. **Stale internal documentation reference.** The `docker-compose.yml` isolation comment cites "PRD section 4.2," which doesn't exist in the current PRD's structure.

### Low — non-blocking, positioning and completeness

21. **YARA / Suricata / CVE-to-MITRE mapping remain blueprint-only,** as the PRD itself states — not a compliance gap, since these aren't PS-required, but shouldn't be presented as complete.
22. **No persistent volumes for OpenSearch or Redis** — data is lost on container restart, low risk for a demo but worth a one-line runbook note.
23. **Product naming ("...& Response Engine") implies an active-response capability** the read-only architectural constraint explicitly forbids — worth a naming/framing pass before judging.
24. **Batch mode is currently framed as a co-equal "Dual-Mode Processing Engine"** rather than a secondary/offline-validation convenience, which understates how much the PS weights the streaming requirement.

---

## 9. Recommended Priority Roadmap

1. Decide and implement the real data path from Zeek into Redpanda (resolves gaps #2 and #3 together) — this unblocks the entire streaming story and is the single highest-leverage fix available.
2. Implement the volumetric-burst query against the existing Redis CMS in ENG01 — infrastructure is already there; this is scoped, bounded work.
3. Wire `relay.py`'s `opensearch_sink` to a real bulk-index call.
4. Fix the ENG04 Literal mismatch (one line) before it causes a silent alert-drop during a live demo.
5. Rebuild `simulate_attacks.py` to generate time-spaced, multi-flow sequences (ENG02) and wider fan-out (ENG05), and a JA4 hash that actually matches ENG04's allow-list — this alone should raise engine coverage from 3/7 to close to 7/7 on existing logic.
6. Run and record an actual throughput benchmark against a stated traffic rate.
7. Either load real trained weights into the DGA model or temporarily gate DGA detection on the entropy heuristic alone.
8. Write the model/feature/training documentation the PS requires as a deliverable.
9. Address the Medium/Low items in parallel — most are independent, quick fixes (typos, dead-code removal, config alignment) that don't block anything else.

---

## 10. Open Items for Next Review

- `local.zeek` configuration (determines exactly what Zeek writes to each log type)
- Contents of `tests/` — no test files have been reviewed
- Whether a `docs/` folder exists anywhere outside the reviewed tree
- The actual log-shipper / topic-producer component, once built, to confirm the streaming architecture fix
