# Hardening & optimization pass — 2026-09-10

Every item flagged in the architecture review / `docs/PRD.md` §9, plus
supporting optimization. Verified with `python -m pytest tests/`
(41 tests, no Docker / Redis / OpenSearch / Postgres required).

## Correctness fixes

| # | Issue | Fix |
|---|---|---|
| 1 | `scripts/setup_netns.sh` contained a verbatim copy of `relay.py` (Python) — the OS-level read-only-ingest isolation did nothing | Rewrote as a real idempotent `up` / `down` / `status` script: IP-less `capture` namespace, ARP off, promiscuous, no veth pair, relay-socket dir. |
| 2 | Modbus field read as `func_name` in `offline_engine.py` + `streaming_engine.py` (fixed only in `pcap_analysis.py`) → ENG-07 silently no-op on batch + live paths | New `src/flow_mapping.py` — one `map_record()` imported by all three ingest paths. Reads Zeek's real `func` key. |
| 3 | `offline_engine.py` hard-coded `segment_hash = "simulated_hash_for_pcap"` | `compute_segment_hash()` — deterministic `sha256:` of the canonical record when no upstream hash is present. |
| 4 | ENG-03 DGA branch ran an **untrained, randomly-initialised** CNN → non-deterministic alerts | Removed `DGAConvNet` + `torch`. ENG-03 now: rule-based tunnelling + trained `dns` ONNX model for DGA, with a **deterministic** weighted lexical heuristic (entropy / vowel ratio / consonant run / digit ratio) as the no-model fallback. |
| 5 | `/score/{family}` in `main.py` did not apply `MIN_ML_CONFIDENCE` (upload path did) | Shared `MIN_ML_CONFIDENCE` in `src/inference/model_server.py`; both paths gate on it. Endpoint also falls back to the family's MITRE mapping. |
| 6 | Live path (`streaming_engine.py`) missing ENG-09/11/13, BZAR, and all ML scoring | Rewrote to engine parity with the upload path. `log_shipper.py` now ships `http.log` / `kerberos.log` / `notice.log`. Shared ML-alert builder extracted to `src/inference/ml_alerts.py`. |
| 7 | `dns` Isolation Forest recall ≈ 0.03; a naïvely-trained `flow` IF flagged 252/572 ordinary flows | `IFOREST_MIN_F1` gate: an IF whose held-out F1 (from `MANIFEST.json`) is below the floor is **advisory only** — score still reported in `model_scores`, but XGBoost drives `threat_score` / `detection_mode`. |
| 8 | `src/schema.py` — dead duplicate `AlertSchema`, no `extra="forbid"` | Deleted (confirmed unimported). |
| 9 | `tests/test_alert_schema.py` fixture used an ISO string for `timestamp` (schema is `float`) — test was already failing | Fixture uses epoch seconds. |
| 10 | Duplicate `rules/LICENSE_AND_ATTRIBUTION (1).md` | Removed. |

## AI models

- `scripts/train_family.py` — clean CLI trainer (XGBoost + Isolation Forest → ONNX), using `feature_extraction.build_feature_vector` for train/serve parity, writing `<family>_feature_importance.json` and a `MANIFEST.json` entry.
- Trained **`flow`** and **`modbus`** from the in-repo CSVs. Model server now loads 3 of 4 families (was 1). `tls` still has no dataset.
- `top_contributing_features` (global XGBoost importances) now flow into every ML-sourced `Alert`.
- Real held-out metrics recorded in `MANIFEST.json`. `flow`/`modbus` XGBoost score near-perfect **because their datasets are small and linearly separable** — honest "pipeline is trained and working", not headline numbers.

## Optimization

- Record→flow mapping de-duplicated (was copy-pasted ×3, the source of fix #2).
- `pcap_analysis._run_engines` no longer opens a fresh Redis connection per upload — the API creates one shared client at startup (`app.state.redis`).
- `ReconDetector` (ENG-05) per-source history is now bounded (periodic prune) — was an unbounded dict in the long-running live process.
- `torch` dropped from the runtime image (was pulled in only for the dead CNN). Training-only deps split into `requirements-train.txt`.
- CORS origins configurable via `STEALTHTAP_CORS_ORIGINS` (was hard-wired `*`).
- `MODELS_DIR` / `MIN_ML_CONFIDENCE` / `IFOREST_MIN_F1` all env-overridable.

## New / changed files

```
src/flow_mapping.py            NEW  -- single record->flow mapper
src/inference/ml_alerts.py     NEW  -- shared ML->Alert builder (upload + live)
scripts/train_family.py        NEW  -- family model trainer CLI
scripts/setup_netns.sh         REWRITTEN (was broken)
requirements-train.txt         NEW
CHANGES.md                     NEW  -- this file
tests/test_pipeline_smoke.py   NEW  -- 30+ engine/pipeline/ML checks, no infra needed
models/flow_*.onnx             NEW  -- trained
models/modbus_*.onnx           NEW  -- trained
models/*_feature_importance.json NEW
src/schema.py                  DELETED
rules/LICENSE_AND_ATTRIBUTION (1).md  DELETED
requirements.txt               torch removed
src/engines/eng03_dga_dns.py   rewritten (no torch / no untrained CNN)
src/streaming_engine.py        rewritten (engine parity + ML)
src/offline_engine.py          rewritten (shared mapper + full engine set)
src/log_shipper.py             +http/kerberos/notice topics
src/inference/model_server.py  MIN_ML_CONFIDENCE, IFOREST_MIN_F1, importances
src/api/main.py, src/api/pcap_analysis.py  shared modules, shared Redis, gating
```

---

# Live network capture + stealth tap — 2026-09-10

A fourth ingest path: tap a real NIC in-process, at kernel level, and run
the **same** ENG01–13 engines + ONNX models the upload path uses. Both
the dashboard (interface picker, telemetry, live SSE alert stream) and a
hardened Docker `sensor` service for deployment on a monitoring host.

## New package — `src/capture/`

| File | Role |
|---|---|
| `interfaces.py` | Wireshark-style interface enumeration (name, description, IPs, MAC, up/down, link speed, `\Device\NPF_{GUID}` capture name, kernel-capture flag). psutil + Windows registry (winreg), cached — no slow `scapy.arch` init. |
| `ja4.py` | **Real JA4** TLS client fingerprint computed from the ClientHello per the FoxIO spec (ja4_a + ja4_b + ja4_c). Replaces `pcap_parser._placeholder_ja4` so ENG-04 has a real fingerprint to look up. |
| `flow_assembler.py` | Streaming packet → `conn`/`dns`/`ssl`/`modbus`/`dnp3` records, same shape `flow_mapping.map_record` consumes. Dirty-flow 2 s snapshots for near-real-time rate engines; Modbus (MBAP+FC) and DNP3 (link+app FC) decoded from raw bytes. |
| `backends.py` | `AFPacketBackend` (Linux: raw `AF_PACKET` + `PACKET_MMAP` RX ring + `PACKET_FANOUT` multi-worker + kernel BPF via `SO_ATTACH_FILTER`, ring sized from `--buffer-mb`, `PACKET_STATISTICS` drop counter). `ScapyBackend` (libpcap/Npcap: `conf.L2listen` in-kernel BPF, enlarged ring, `pcap_stats`). `select_backend()` picks the fastest available; fail-fast preflight with an install hint. |
| `live_agent.py` | Orchestrator: arrival-stamped bounded queue (drops **oldest** on overflow → bounded latency), phase-split scoring (immediate for dns/tls/OT, 2 s flow snapshots, on flow completion), per-(class,src,dst,discriminator) alert cooldown, `_RateMonitor` (pps/Mbit/s/peak/high-speed flag), latency histogram (p50/p95/p99/max). CLI: `list` / `caps` / `run [--pcap]` / `serve`. |
| `forwarder.py` | `HttpAlertForwarder` — batches alerts, POSTs to `STEALTHTAP_API_URL/alerts/ingest` (stdlib urllib, background thread, drop-on-fail). Sensor → shared PostgreSQL. |

## API + schema

- `src/api/live_capture.py` — router: `GET /capture/interfaces·capabilities·status·alerts`, `POST /capture/start·stop`, `GET /capture/stream` (SSE). Mounted on the main API; also runnable standalone via `live_agent serve`.
- `src/api/main.py` — `POST /alerts/ingest` (bulk) so live-capture and upload alerts share one queryable `alerts` table.
- `src/alert_schema.py` — unchanged shape; live alerts add `evidence.detection_latency_ms`.

## OT expansion

- `src/flow_mapping.py` — new `dnp3` branch (`fc_request` → `dnp3_func`).
- `src/engines/eng07_ot_anomaly.py` — DNP3 branch: `SELECT`/`OPERATE`/`DIRECT_OPERATE`/`COLD_RESTART`/`WARM_RESTART`/`STOP_APPLICATION` → CRITICAL; `WRITE`/`DISABLE_UNSOLICITED`/app-lifecycle/`DELETE_FILE` → HIGH.
- `src/api/pcap_analysis.py` — reads `dnp3.log` and scores it through ENG-07; `packet_summary` gains `dnp3_records`.
- `src/engines/eng03_dga_dns.py` — mDNS/LLMNR/`.local`/`.arpa`/`_service._proto` queries are excluded from DGA scoring (killed a false-positive flood on a live LAN).

## Dashboard

- `dashboard-app/src/components/LiveCapturePanel.tsx` — **new**. Interface `<select>` (Live mode only), kernel BPF filter, kernel-buffer size, prefer-kernel toggle, Start/Stop. Live telemetry strip: backend, throughput (pps/Mbit/s + peak), **kernel drop** ("keeping up" / rising), userspace drop, active flows, **detection latency p50/p95/p99**, dns/tls, modbus/dnp3, alerts, ML families, HIGH-SPEED banner. Live SSE alert stream with per-alert latency; de-dupes by `alert_id`.
- `App.tsx` / `ModeSelector.tsx` — Live Capture card no longer stubbed; `api/client.ts` gains the `live.*` client + `VITE_LIVE_API_BASE`; `types/alert.ts` adds `NETWORK_INTRUSION_ATTEMPT` and the capture types.

## Docker — the stealth tap

- `sensor.Dockerfile` + `docker-compose.yml` `sensor` service (profile `tap`): `network_mode: host`, `cap_drop: ALL` + only `NET_RAW`/`NET_ADMIN`, `no-new-privileges`, `read_only` rootfs, **no published ports** (control API binds 127.0.0.1). Captures `$CAPTURE_IFACE` headless, forwards alerts to the shared DB.
- `docs/LIVE_CAPTURE_DEPLOYMENT.md` — full deploy guide: IP-less capture NIC, `setup_netns.sh` air-gap, per-field telemetry meaning, latency/throughput measurement.
- `zeek-batch.Dockerfile` / `batch_policy.zeek` — JA4 plugin install made **non-fatal** with a `JA4_ZKG_SOURCE` build arg (the guessed `FoxIO-LLC/ja4` shortname isn't valid; protocol parsing must not break on it). Upload-path JA4 stays inert until a reachable source is set; the **live path** JA4 works regardless.

## Tests / tooling

```
src/capture/*                  NEW  -- interfaces, ja4, flow_assembler, backends, live_agent, forwarder
src/api/live_capture.py        NEW  -- REST + SSE router
src/capture/live_capture.py    DELETED -- a parallel single-file implementation was folded into the package
sensor.Dockerfile              NEW
docs/LIVE_CAPTURE_DEPLOYMENT.md NEW
tests/test_capture.py          NEW  -- JA4, flow assembler (DNS/Modbus/DNP3), ENG-07 DNP3, phase-split, forwarder, interface enum
tests/conftest.py              NEW  -- SCAPY_USE_PCAPDNET=1 before any scapy layer import (Windows dev first-import can block ~120 s)
requirements.txt               +psutil ; fastapi/starlette pinned (a mismatched starlette silently breaks include_router)
```

## Measured (real Wi-Fi capture, this pipeline)

Kernel-level libpcap backend · DGA alerts via the trained `dns` XGBoost model · real JA4 from a ClientHello · throughput 195 pps / peak 370 · kernel-drop 0 ("keeping up") · **detection latency 157 ms p50 / 328 ms p95 / 328 ms p99**. This is PS constraint (d), on the live path.

## Still open

- Live streaming path (Zeek→Redpanda→Faust) end-to-end load test.
- `tls` model — no public JA4 dataset.
- `flow` / `modbus` retraining on CICIDS2017/2018 + CIC-Modbus-2023 for submission metrics.
- Upload-path JA4 — set `JA4_ZKG_SOURCE` to a reachable Zeek JA4 package.
- On some Windows dev hosts scapy's first import blocks; `SCAPY_USE_PCAPDNET=1` (auto-set) mitigates. Linux/Docker unaffected.
