# native/stealthtap_core — Rust native core

A validated accelerator for two paths: the upload-PCAP parser
(`pcap_parser.py`) and the live-capture flow assembler
(`src/capture/flow_assembler.py`). Not a rewrite of detection logic —
every threshold and every accuracy fix from this project's work stays
in Python, unchanged; this crate only replaces packet parsing and flow
assembly.

## Status

**Upload-path parser** (`parse.rs`):
- Scope: classic-pcap files (Ethernet + Linux-cooked-capture link
  types), `conn` (TCP/UDP flow) and `dns` (query, including
  DNS-over-TCP per RFC 1035 §4.2.2) records.
- Not yet native: `ssl`/JA4 and `modbus` extraction for this path
  specifically — `pcap_parser.py` falls back to its own scapy pass for
  those when needed (disclosed in `pcap_parser.parse_pcap`'s
  docstring). pcapng files aren't supported either — `parse_pcap`
  raises and `pcap_parser.py` falls back to the Python parser
  automatically.

**Live-capture assembler** (`live.rs`, `ja4.rs`) — `LiveFlowAssembler`,
wired into `src/capture/live_agent.py` via
`src/capture/native_flow_assembler.py`, same graceful-fallback pattern
as everything else in this codebase (`STEALTHTAP_FORCE_PYTHON_LIVE_ASSEMBLER=1`
to opt out):
- Scope: Ethernet-framed input only (real NIC capture is always
  Ethernet — confirmed against `src/capture/backends.py`), `conn`,
  `dns` (UDP + TCP), `ssl` (real FoxIO JA4 fingerprint, not a
  placeholder), `modbus`, `dnp3`, `http` (HTTP/1.x request line +
  User-Agent/Content-Length — feeds ENG-09, which was previously
  dormant on live capture; matches Zeek's own base analyzer's scope,
  since HTTP/2 is binary-framed and out of scope there too).
  **Not implemented**: `kerberos` (ENG-11 stays dormant on live
  capture) — Kerberos is binary ASN.1, not text like HTTP, and this
  project has zero real Kerberos captures locally to validate a parser
  against. Per this project's own "Validated, not asserted" standard
  (below), shipping an unvalidated binary-protocol parser for a
  security detector was judged worse than leaving the gap disclosed.
- Flow assembly itself stays single-process even when the multi-core
  engine pool (below) is active — see that section for why.

## Validated, not asserted

`scripts/validate_native_parser.py` (upload path) and
`scripts/validate_native_live_assembler.py` (live path) compare this
crate's output against the Python reference implementation on real
captures, field-by-field, order included.

- Upload-path: 26/26 real captures byte-for-byte identical — same flow
  UIDs, same byte counts, same DNS records, same processing order.
  `scripts/eval_real_traffic.py` run twice (forced Python vs. native)
  produced identical accuracy tables to the decimal place.
- Live-path: 21/26 real captures identical (5 skipped — non-Ethernet
  linktype, not representative of live NIC capture, reported not
  silently ignored). Includes `http`: 2 of these captures carry real
  HTTP/1.x requests (`netbios_ssn2.pcap` 61 requests, `test.pcap` 5) —
  native and Python extracted identical method/uri/user_agent/
  request_body_len on every one, not just an identical count.

Real bugs found and fixed during validation, not assumed away:
1. DNS port check only covered UDP 53, missing mDNS (5353).
2. **DNS-over-TCP was never handled anywhere** — not in this crate, not
   in the pre-existing Python reference (`pcap_parser.py`,
   `flow_assembler.py`). Found via CHAOS-class `version.bind`/
   `id.server` fingerprinting queries in real captures. This predates
   the native-parser work entirely — a genuine product bug this port
   surfaced, fixed in both the Rust and Python parsers.
3. `std::collections::HashMap`'s randomized iteration order silently
   changed which flow order-sensitive rule engines saw "first" in a
   window. Fixed with `indexmap::IndexMap`.

## Measured performance

- **Upload-path** (26 real captures): Python 477.2s → Rust 5.7s —
  **84.3x** aggregate speedup. Per-file range 55x–540x
  (`mirai.pcap`, 564,832 flows: 286s → 2.6s).
- **Live-path assembler alone** (`samples/netbios_ssn2.pcap`, 48,150
  packets, isolated from engine scoring): **393,856 pps** — parsing is
  not the throughput bottleneck at any realistic packet size.
- **Full live pipeline** (native assembly + all 13 engines + ML), same
  capture: ~1,580 pps at first measurement → ~4,800–7,000 pps after
  fixing Redis round-trip latency (default to in-process `MemoryStore`,
  see `src/capture/scoring.py`), batching immediate ML scoring, and two
  profile-guided fixes (skip a redundant scapy rebuild; defer an
  engine's redundant per-call state rebuild) → ~6,300 pps wall-clock /
  ~20,400 pps-equivalent isolated (CPU-time profile) after native
  fast-paths for the five CPU/state-heavy engines (below). Still
  ~20–80x short of 1-5 Gbps through the full detection stack — the
  dominant remaining cost is now genuine ONNX inference time, not
  per-engine Python overhead. See `docs/PRD.md` §11 for the full
  throughput methodology.

## Native engine fast-paths (`eng01.rs`, `eng02.rs`, `eng05.rs`, `eng06.rs`, `eng13.rs`)

The fast-path/slow-path split: exact ports of the five engines
profiling identified as CPU/state-heavy (ENG-01 flood/Slowloris/
spoofed-flood, ENG-02 beaconing, ENG-05 recon, ENG-06 accumulated
exfiltration, ENG-13 bruteforce) — same thresholds and formulas as
their Python originals, moved from per-flow Redis round-trips (01/02/
06/13) or per-flow Python dict/set rebuilds (05) into in-process,
EXACT (not approximate) Rust counters. Python still builds the final
`Alert` — only the counting/threshold check that runs on every flow
moved. Graceful fallback to the original Redis/MemoryStore or
in-process Python path if the native module isn't built
(`STEALTHTAP_FORCE_PYTHON_ENG01`/`02`/`05`/`06`/`13=1` to force it).

The remaining engines (03/04/07/09/11) weren't ported: they're already
cheap — stateless, exact-match against a small threat-intel list, or
bounded by real ONNX inference cost that native code wouldn't reduce.

Validated per-engine: `scripts/validate_native_eng01.py` through
`..._eng13.py` replay every real sample capture through both the
Python reference and the native path and compare every alert exactly.
All five: byte-for-byte equivalent on every real capture, plus
synthetic tests for firing conditions the samples didn't exercise.

Measured: ENG-01 alone, isolated — 76,022 flows/sec (Python+
MemoryStore) → 633,615 flows/sec (native), **8.3x**. Full pipeline,
same profiler before/after all five: **6.66s → 2.36s** on the same
48,150-packet capture — **2.83x** from this round alone.

## Multi-core engine pool (`src/capture/engine_pool.py`)

Built and correctness-validated, opt-in (`num_workers=1` default is
byte-identical to the original single-process path). Shards assembled
records (not raw packets — see the module docstring for why that
distinction matters for flow-assembly correctness) across worker
*processes* by source IP, matching what `ENG-05`'s in-process
correlation state needs. Requires a real Redis for `num_workers > 1`
(cross-process shared state); auto-downgrades to 1 otherwise.

**Not yet a net throughput win as of the last measurement**, and this
is disclosed rather than glossed over: splitting Redis-bound work
across processes doesn't parallelize a single-threaded server, it adds
process/IPC overhead on top of the same serialized command stream.
That measurement predates the native engine fast-paths above, which
remove the Redis-round-trip cost from the default path entirely —
worth re-measuring now that the engines it would parallelize are
genuinely CPU-bound instead; not yet done.

## Building

```
pip install maturin
cd native/stealthtap_core
maturin develop --release      # installs into the active venv
```

On Windows with a from-source Python build (no standard `libs/`
directory), set `LIB` to include the directory containing
`python3XX.lib` before building.

**Packaging note**: the PyInstaller spec (`packaging/stealthtap.spec`)
does not yet declare this module as a binary to bundle, and a frozen
build has not been produced or tested. A build today would likely fall
back to the slower Python parser silently rather than fail loudly —
fix before shipping a frozen executable.
