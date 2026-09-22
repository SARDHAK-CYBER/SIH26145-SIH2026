# native/stealthtap_core — Rust upload-path parser

A validated, drop-in accelerator for `pcap_parser.py`'s `conn`/`dns`
extraction. Not a rewrite of the detection logic — every threshold, every
fix from this project's accuracy work stays in Python, unchanged.

## Status

- **Scope**: classic-pcap files (Ethernet + Linux-cooked-capture link
  types), `conn` (TCP/UDP flow) and `dns` (query) records only.
- **Not yet native**: `ssl`/JA4 and `modbus` extraction — `pcap_parser.py`
  falls back to its own scapy pass for those when needed. This is a
  disclosed limitation, not a silent one (see `pcap_parser.parse_pcap`'s
  docstring). pcapng files aren't supported yet either — `parse_pcap`
  raises and `pcap_parser.py` falls back to the Python parser automatically.
- **Not yet integrated with live capture** — this only speeds up the
  upload-PCAP path (`pcap_parser.py`). `src/capture/flow_assembler.py`
  (the live-capture path) is untouched; live throughput is still bounded
  by the Python pipeline measured in `scripts/bench_throughput.py`.

## Validated, not asserted

`scripts/validate_native_parser.py` compares this crate's output against
`pcap_parser.py`'s own (the reference implementation) on real captures,
field-by-field, order included. Last full run: **26/26 real captures
(`archive (2)`) byte-for-byte identical** — same flow UIDs, same byte
counts, same DNS records, same processing order.

`scripts/eval_real_traffic.py` (the accuracy harness) run twice — once
forced onto the Python parser (`STEALTHTAP_FORCE_PYTHON_PARSER=1`), once
on the native path — produced **identical accuracy tables**: same recall,
specificity, precision, F1, and false-positive rate, to the decimal place.

Two real bugs were found and fixed during that validation, not assumed
away:
1. The DNS-port check only covered port 53, missing mDNS (5353) — a
   packet type well-represented in real desktop-traffic captures. A
   missed DNS packet doesn't just lose a DNS record, it also gets
   double-counted as a spurious generic UDP flow.
2. `std::collections::HashMap`'s randomized iteration order (not a bug,
   a deliberate DoS-resistance feature) silently changed which flow
   several stateful, order-sensitive rule engines saw "first" in a
   window, changing detection results despite byte-identical parsed
   output. Fixed with `indexmap::IndexMap`, which preserves the same
   insertion order Python's `dict` guarantees.

## Measured performance (26 real captures, `archive (2)`)

Total parse time: Python 477.2s -> Rust 5.7s -- **84.3x** aggregate
speedup. Per-file range: 55x-540x, larger files benefiting most
(`mirai.pcap`, 564,832 flows: 286s -> 2.6s).

## Building

```
pip install maturin
cd native/stealthtap_core
maturin develop --release      # installs into the active venv
```

On Windows with a from-source Python build (no standard `libs/`
directory), set `LIB` to include the directory containing
`python3XX.lib` before building.
