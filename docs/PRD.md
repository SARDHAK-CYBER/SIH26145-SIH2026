# StealthTap — Product Requirements & Technical Report

**Team:** TeamXOR · **Event:** Smart India Hackathon 2026 · **PS ID:** 26145 · **Organization:** NTRO
**Revision:** 2026-09-10 (post hardening + live-capture pass — see `CHANGES.md`)

---

## 1. Problem Statement (verbatim)

**Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Background.** Critical-infrastructure operators observe their gateway and peering links using passive mirroring or hardware data diodes that copy traffic into a monitoring enclave in one direction only. The enclave can see everything crossing the link, but has no physical or protocol-level path back into the production network. This is deliberate: it removes an entire class of attack in which a compromised monitoring system becomes a pivot into the core network, and preserves a clean chain of custody for forensic use. The trade-off is that any intelligence layer sitting in that enclave must work purely from what it can passively observe — packet captures, exported flow records, derived metadata — with no ability to probe, complete handshakes, or push a mitigation command back.

**Description.** Design and build an AI/ML pipeline that ingests a one-directional stream of IP traffic and detects, classifies, and scores cyber-security threats in near real time, using only passively collected data, assuming it can never re-contact the traffic's source or destination. Output is intelligence — labelled alerts, confidence scores, and supporting evidence — displayed on a visualization dashboard.

| # | Threat category |
|---|---|
| a | Volumetric / protocol DDoS — SYN floods, UDP amplification, spoofed-source floods, from flow-level rate and source-IP entropy |
| b | Botnet C2 beaconing — periodicity/inter-arrival analysis toward a small destination set |
| c | DGA domains and DNS tunnelling — entropy/n-gram analysis, query-length and record-type anomalies |
| d | Malware inside encrypted sessions — from JA3/JA4 and TLS/QUIC metadata alone, never decrypted |
| e | Reconnaissance / port scanning — fan-out from one source across many destinations/ports |
| f | Data exfiltration — asymmetric flow-volume, outbound/inbound byte ratio anomalies |

| # | Architectural constraint |
|---|---|
| a | Read-only ingest — no return path, no live query, no inline blocking |
| b | No payload decryption — TLS/QUIC analyzed from metadata only |
| c | Streaming, not batch — incremental processing, bounded alert latency |
| d | Defined throughput target — state and demonstrate the tested traffic rate |
| e | Standardized alert schema — timestamp, flow identifier, threat class, confidence score, supporting evidence |

---

## 2. Our Solution — summary

StealthTap treats each threat category as requiring a genuinely different detection mechanism, not one model stretched across all of them. The same detection stack runs over **four interchangeable ingest paths** (upload PCAP, live NIC capture, live streaming via Zeek, offline batch), all producing the identical `Alert` record.

1. **Protocol parsing** — real Zeek 6.0.3 + 6 ICSNPP industrial-protocol plugins (Modbus, DNP3, S7comm, EtherNet/IP, OPC UA, PROFINET) for the upload/streaming paths; an in-process flow assembler with **real JA4** and Modbus/DNP3 decode for the live-capture path. Structured metadata for IT and OT traffic, never payload content.
2. **Signature-based detection, three layers deep** — YARA (~401 rules) on files Zeek extracts from cleartext protocols; Suricata (20,829 ET Open rules) for network-level signature matching, running concurrently with Zeek; BZAR (MITRE's own Zeek scripts) for SMB/DCE-RPC lateral movement.
3. **Behavioural rule engines (ENG01–ENG13)** — purpose-built logic per threat: time-bucketed rate + **source-IP HyperLogLog entropy** for DDoS/spoofed-source floods, inter-arrival coefficient-of-variation for C2, char-n-gram + lexical features for DGA, JA4 fingerprint matching for encrypted malware, fan-out counting for recon, per-flow + accumulated byte ratio for exfiltration, dangerous Modbus/**DNP3**/CIP command codes for OT, HTTP C2/exfil signals, Kerberoasting via Kerberos ticket-cipher analysis, and auth-port brute-force counting.
4. **Hybrid ML layer** — XGBoost (supervised) + Isolation Forest (unsupervised, benign-only) per protocol family. Combined with `max()` so either firing strongly raises an alert; a degenerate Isolation Forest (held-out F1 below a floor) is auto-demoted to advisory, its score still reported.
5. **Standardized alert schema** — one Pydantic `Alert`, `extra="forbid"`, MITRE ATT&CK-mapped, with `detection_mode`, `model_scores`, and `top_contributing_features` for explainability.
6. **Dashboard with pipeline transparency** — React/TypeScript; **Upload PCAP** and **Live Capture** modes; per-tool coverage table (records processed / alerts fired) so "did every tool run" is checkable; live telemetry (pps, Mbit/s, kernel drops, detection latency p50/p95/p99).

---

## 3. Full Tech Stack — and why each piece was chosen

### Ingest & protocol parsing

| Tool | Why chosen |
|---|---|
| **Zeek 6.0.3** | Industry-standard network security monitor with the deepest protocol-parsing ecosystem; produces the structured, per-protocol "derived metadata" the PS calls for. Extensible via Spicy for industrial protocols. |
| **ICSNPP (6 plugins)** | CISA-maintained OT protocol visibility — the PS's threat model spans IT and OT; generic IT tools have no OT protocol awareness. |
| **BZAR** | MITRE-authored Zeek scripts detecting SMB/DCE-RPC lateral movement with MITRE technique IDs in their own output — reuse over reinvention. |
| **AF_PACKET + PACKET_FANOUT (Linux)** / **Npcap/libpcap** | The live-capture path taps a NIC at kernel level: `PACKET_MMAP` RX ring, multi-worker `PACKET_FANOUT`, in-kernel BPF via `SO_ATTACH_FILTER`. This is what makes a high-rate link survivable and gives the kernel's own drop counters. |
| **Redpanda** | Kafka-API-compatible streaming for the Zeek→Faust path; lighter than vanilla Kafka, same client ecosystem. Satisfies PS constraint (c). |
| **scapy + psutil** | Live-capture flow assembly and cross-platform interface enumeration (the Wireshark-style picker). |

### Detection & scoring

| Tool | Why chosen |
|---|---|
| **XGBoost** | Gradient-boosted trees on engineered tabular features — microsecond-scale CPU inference (no GPU assumed), strong on modest data, exposes feature importances for explainable evidence (PS constraint e). |
| **Isolation Forest** | Unsupervised, benign-only — the one layer that can flag an attack pattern nobody has seen, in an explicitly adversarial environment. |
| **YARA** | De-facto file-content signature standard; used only on cleartext-extracted files — constraint (b) true by construction. |
| **Suricata** | Modern multi-threaded successor to Snort; JSON (`eve.json`) output; mature ET Open ruleset covering exploit/C2/credential-theft patterns the other layers miss. Independent job-queue service, concurrent with Zeek. |

### Serving, storage, interface

| Tool | Why chosen |
|---|---|
| **ONNX Runtime** | Framework-agnostic serving — XGBoost and scikit-learn IsolationForest export to one format, one runtime, no training-framework dependency at inference. No pickle. |
| **FastAPI** | Async, native Pydantic validation — the alert schema is defined once and enforced everywhere; SSE for the live alert stream. |
| **PostgreSQL** | Relational alert storage with real query/filter support; the single shared store for **every** ingest path (`/alerts/ingest` unifies live + upload). |
| **React + TypeScript + Vite** | Type-safe frontend; alert types kept in lockstep with the Python schema. |
| **Docker Compose** | Microservice isolation matching the PS's security philosophy. **11 core services** + a `sensor` service (profile `tap`) for the stealth live tap. |

Runtime deps are in `requirements.txt`; **`torch` was removed** (it existed only for a dead untrained CNN). Model-training deps are split into `requirements-train.txt`.

---

## 4. AI Models — detailed rationale and current results

**Why not a single model for all threat categories?** They are statistically different problems — DGA is character-sequence classification, DDoS is rate/volume-over-time, encrypted-malware can only use TLS metadata. StealthTap engineers the right features per family (`src/features/feature_extraction.py`: `flow` 9, `dns` 262, `tls` 3, `modbus` 4) and applies the same two-model hybrid to each. **The one feature module is imported by both the training scripts and the live engines** — the single most common cause of "scores well offline, fails in production" (train/serve skew) is eliminated by construction. `FEATURE_SCHEMA_VERSION` gates artifact compatibility.

**Why XGBoost + Isolation Forest, not a neural network?** A direct consequence of PS constraints (c) and (d): microsecond CPU inference (no GPU assumed), strong on engineered tabular features with modest data, and feature importances usable directly as "supporting evidence". The live path also runs **batched** ONNX inference — one call per model per batch of flows, never per-flow.

### Trained models (`models/MANIFEST.json`, `scripts/train_family.py`, all held-out test sets)

| Family | Dataset | Rows | XGBoost — Precision / Recall / F1 / ROC-AUC | Isolation Forest |
|---|---|---|---|---|
| `dns` (DGA / tunnelling) | 25 DGA malware families + Alexa benign | 674,898 | **0.935 / 0.880 / 0.907 / 0.972** | F1 0.067 → advisory |
| `flow` (DDoS / exfil / IT flow) | labelled flow captures (in-repo CSV) | 23,213 | **0.9996 / 0.9985 / 0.999 / 0.998** | F1 0.208 → advisory |
| `modbus` (OT command anomaly) | labelled Modbus transactions (in-repo CSV) | 51,608 | **1.000 / 1.000 / 1.000 / 1.000** | F1 0.000 → advisory |
| `tls` (JA4 / encrypted malware) | — | — | not trained (no public labelled JA4 dataset) | — |

The `dns` confidence threshold (`MIN_ML_CONFIDENCE = 0.6`) is chosen from the real precision-recall curve on the 134,980-row held-out set (at 0.6: precision 0.957, recall 0.840). **Honest note:** the `flow` and `modbus` XGBoost numbers look near-perfect because those datasets are modest and cleanly separable — treat them as "the pipeline is real, trained, and serving", not as submission headline numbers. Retrain on CICIDS2017/2018 and CIC Modbus 2023 (see `docs/TRAINING_GUIDE.md`) for that.

Every ML-sourced alert carries `model_scores` (both raw scores) and `top_contributing_features` (global XGBoost importances, e.g. `orig_bytes` / `byte_ratio` / `duration_s` for `flow`).

---

## 5. Comparison with existing tools

| Tool | What it does well | What it doesn't do (relative to this PS) | Relationship to StealthTap |
|---|---|---|---|
| **Wireshark** | Best interactive protocol dissection for a human | No automation, ML, alerting, continuous operation | Complementary — a StealthTap alert's evidence is what an analyst opens next |
| **Zeek (standalone)** | Deep, extensible protocol parsing | No ML, no unified alert schema, no dashboard, no file scanning | Core component — StealthTap adds the decision layer on top |
| **Suricata (standalone)** | Fast mature signature matching | No behavioural/ML anomaly detection; limited OT coverage; no hybrid scoring | Integrated as ENG-10, concurrent with Zeek |
| **Snort** | Long history, legacy rules | Single-threaded, superseded | Not used — Suricata chosen |
| **Security Onion** | The closest existing analog (Zeek + Suricata + Elastic) | General-purpose SOC platform, not diode-constrained; no OT dangerous-command engine; no custom hybrid ML for this PS | Honest comparison point — StealthTap differentiates via OT behavioural engines, custom-trained ML with evaluated thresholds, BZAR, and an architecture proven against read-only ingest |
| **Claroty / Dragos / Nozomi** | Mature OT threat intel, asset inventory, vendor support | Closed-source, expensive, not auditable | Not a peer comparison — the enterprise bar this prototype doesn't claim to match |
| **CICFlowMeter** | Flow feature extraction behind CICIDS | Not a detection system | The `flow` family features are informed by the same definitions |

**Honest summary:** every individual capability exists elsewhere, often more maturely. What StealthTap demonstrates is these tools wired into one coherent pipeline that respects a genuinely unusual constraint (true one-way data flow) end to end, with a real evaluated ML layer, four interchangeable ingest paths, and a fully checkable per-tool coverage report.

---

## 6. Standardized Alert Schema (PS constraint e)

```python
{
  "alert_id": str,
  "timestamp": float,
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence_score": float,          # 0-100
  "threat_class": str,                # 12 Literals: the six PS classes (split where useful, e.g.
                                       #   VOLUMETRIC_DDOS / SLOWLORIS, DGA_DOMAIN / DNS_TUNNELING),
                                       #   plus ICS_UNAUTHORIZED_CONTROL_COMMAND, MALICIOUS_FILE_DETECTED,
                                       #   and NETWORK_INTRUSION_ATTEMPT for signature/Kerberos/BZAR/
                                       #   brute-force detections outside the original six
  "flow_identifier": {"src_ip","src_port","dst_ip","dst_port","protocol"},
  "mitre_attack": {"tactic","technique_id","technique_name"},
  "evidence": dict,                   # layer-specific detail; on the live path also detection_latency_ms
  "forensics": dict,                  # sha256: content hash for chain of custody
  "detection_mode": "rule" | "xgboost" | "isolation_forest",
  "model_scores": dict | None,        # both raw scores, present when ML-fired
  "top_contributing_features": list | None,   # top XGBoost feature importances
}
```

Pydantic v2, `model_config = ConfigDict(extra="forbid")` — malformed alerts are rejected at construction. The relay (`src/relay/relay.py`) validates against this schema before anything crosses the isolation boundary; that validation, not the transport, is the security control.

---

## 7. Architecture

Four ingest paths, one detection stack, one alert store. Full diagram in `README.md` §3.

- **Upload PCAP** (primary, fully tested): browser → FastAPI → **zeek-batch ∥ suricata-batch (concurrent)** → ENG01–13 + hybrid ML + YARA + BZAR notice parsing → PostgreSQL, with a per-tool coverage report on every response.
- **Live capture** (kernel-level, real-time): NIC → `AFPacketBackend` / `ScapyBackend` (in-kernel BPF, mmap ring, `pcap_stats`) → `FlowAssembler` (real JA4, Modbus/DNP3 decode) → ENG01–13 + hybrid ML (phase-split: immediate for dns/tls/OT, 2 s flow snapshots, on completion) → per-(class,src,dst) cooldown → SSE + `POST /alerts/ingest` → PostgreSQL (same table).
- **Live streaming** (air-gapped capture): Zeek (zero-IP `capture` namespace, `scripts/setup_netns.sh`) → `log_shipper.py` (tails JSON logs off a shared volume) → Redpanda → `streaming_engine.py` (Faust, engine parity with the upload path) → `relay.py` (one-way Unix socket, schema-validated) → OpenSearch. Code-complete; not yet load-tested.
- **Offline batch**: static Zeek logs → `offline_engine.py` → OpenSearch.

**Read-only ingest (constraint a)** is enforced at OS level: `scripts/setup_netns.sh` puts the capture NIC in an IP-less namespace with ARP off and no route; the `sensor` container drops all capabilities except `NET_RAW`/`NET_ADMIN`, publishes no ports, and runs read-only. Capture is receive-only; nothing is ever transmitted back toward the monitored link.

---

## 8. Evaluation methodology

Per the PS's requirement for a documented training/validation approach:

- **`dns` family (DGA)**: 674,898-row real dataset (25 DGA malware families + Alexa benign), 80/20 stratified split, held-out evaluation. Real P/R/F1/ROC-AUC (§4). Threshold from the real precision-recall curve, not a guess.
- **`flow` + `modbus` families**: trained via `scripts/train_family.py` on the in-repo labelled CSVs using the shared `feature_extraction.build_feature_vector` (train/serve parity), 80/20 stratified, held-out metrics recorded in `MANIFEST.json`. Datasets are modest and separable — pipeline-real, not submission-grade.
- **Rule engines**: verified against real, independently-sourced traffic (ITI/ICS-Security-Tools' Modbus captures; StopDDoS spoofed-flood pcaps; THC-Hydra brute-force pcaps). Ground truth from packet-level inspection. A Modbus field-name mismatch that silently zeroed OT detection was found and fixed (and consolidated so it can't recur on any path).
- **YARA**: 401 rules verified to compile and load; functional test against EICAR and a real Laudanum webshell signature.
- **JA4**: the live-path JA4 is computed per the FoxIO spec from the ClientHello and unit-tested (`tests/test_capture.py`) for structure and determinism; matched against FoxIO's published fingerprints for Cobalt Strike / Sliver / SoftEther with correct severity tiering.
- **Suricata**: 20,829 of 20,845 rules load with zero errors; functional detection confirmed against constructed traffic and end-to-end through `_run_suricata()`.
- **Kerberoasting (ENG-11)**: logic cross-confirmed against Zeek's `KRB::Info` docs and MITRE's attack description (MITRE's "TGS-REP etype 23" = Zeek's `rc4-hmac`).
- **BZAR (ENG-12)**: builds and loads cleanly in Zeek 6.0.3; parser tested against BZAR's real message format. Not yet exercised against a genuine SMB lateral-movement pcap — open item.
- **Detection latency & throughput (PS constraint d)** — **now measured on the live path.** `GET /capture/status` reports, live: current/peak pps and Mbit/s, the **kernel** ring drop counter (`pcap_stats` / `PACKET_STATISTICS`) as the ground-truth "can't keep up" signal, the userspace-queue drop count, and detection-latency **p50 / p95 / p99 / max** (packet arrival → alert emission) for immediately-detectable classes. Measured on a real Wi-Fi capture through this pipeline: 195 pps / peak 370, kernel-drop 0, **latency 157 ms p50 / 328 ms p95 / 328 ms p99**. `python -m src.capture.live_agent run --pcap <big.pcap> --realtime` reproduces the measurement at wire speed.
- **Automated tests**: `python -m pytest tests/` — engine, feature-extraction, schema, mapping, JA4, DNP3, forwarder, and phase-split checks; no Docker/Redis/DB required.

---

## 9. Current Status & Honest Gaps

| Area | Status |
|---|---|
| DDoS (incl. spoofed-source via HLL entropy), recon, exfiltration, OT, HTTP, brute-force rule engines | **Working, verified against real traffic** |
| C2 beaconing (inter-arrival CV) | Implemented; verified against synthetic traffic |
| DGA / DNS tunnelling | **Unified in ENG-03**: rule-based tunnelling + trained `dns` XGBoost for DGA + deterministic lexical fallback; mDNS/LLMNR/`.local` filtered. The old untrained CNN is removed. |
| DGA ML (`dns`) | Trained full-scale (674,898 rows), curve-derived threshold |
| `flow` + `modbus` ML | **Trained** on the in-repo CSVs, real held-out metrics; model server loads 3 of 4 families |
| `tls` ML | Not trained (no public labelled JA4 dataset) — ENG-04 runs rule-based with **real JA4** on the live path |
| Encrypted malware (JA4) — live path | **Working** — real JA4 from the ClientHello vs. FoxIO threat intel (19 malicious + 5 dual-use) |
| Encrypted malware (JA4) — upload path | **Disabled** — `FoxIO-LLC/ja4` is not a valid zkg shortname; the `zeek-batch` build is non-fatal and skips it. Set the `JA4_ZKG_SOURCE` build arg to a reachable source to enable. |
| OT: Modbus + **DNP3** + EtherNet/IP CIP | **Working end to end** — dangerous function/service codes, byte-level verified; DNP3 OPERATE/DIRECT_OPERATE/COLD_RESTART → CRITICAL |
| Kerberoasting (ENG-11), BZAR (ENG-12) | Working / builds & parses; not yet against a real attack pcap |
| Suricata (20,829 ET Open rules) | **Working, fully verified end-to-end** |
| YARA | 401 real rules, verified |
| Zeek + 6 OT protocol plugins | Working for uploads; IEC 61850 deferred (immature ecosystem) |
| Live capture (kernel-level, dashboard-driven) | **Working** — real NIC capture, real JA4, DNP3, phase-split scoring, latency/throughput telemetry |
| Stealth `sensor` service | Built — host network, `NET_RAW`/`NET_ADMIN` only, no ports, read-only, forwards to the shared DB |
| Live streaming path (Zeek→Redpanda→Faust) | Engine parity with the upload path; **not yet load-tested** end to end |
| Detection latency / throughput (PS constraint d) | **Measured on the live path** (p50/p95/p99 + pps/Mbit/s + kernel drops), reported live |
| Standardized alert schema (PS constraint e) | **Met** — one Pydantic `Alert`, `extra="forbid"`, MITRE-mapped, explainability fields, shared by all four paths |
| Dashboard | **Working** — Upload PCAP + Live Capture modes; interface picker (live only); live telemetry + SSE alert stream; per-tool coverage; raw JSON evidence |
| Read-only ingest (PS constraint a) | **Strong** — `setup_netns.sh` rewritten (was a broken relay.py copy); IP-less capture ns; sensor container hardened; receive-only capture |

**Closing the remaining gaps**, in priority order: (1) enable upload-path JA4 by pointing `JA4_ZKG_SOURCE` at a reachable Zeek JA4 package; (2) retrain `flow`/`modbus` and add `tls` on real public datasets (CICIDS2017/2018, CIC Modbus 2023, self-generated JA4); (3) load-test the live streaming path; (4) source a real SMB lateral-movement / Kerberoasting pcap for ENG-11/ENG-12; (5) grow YARA/Suricata/JA4 coverage as those ecosystems mature.

Full change history: **`CHANGES.md`**. Deployment of the live tap: **`docs/LIVE_CAPTURE_DEPLOYMENT.md`**. Model contract: **`docs/MODEL_CONTRACT.md`**.
