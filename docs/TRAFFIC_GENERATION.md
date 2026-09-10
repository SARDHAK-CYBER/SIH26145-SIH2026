# Traffic Generation & Benchmark Harness

Generates known traffic against your own lab StealthTap deployment and measures the operational numbers a jury actually asks for: **detection latency**, **sustained flows/sec**, and **live precision/recall** (using each generator's own ground truth as the reference).

**Run everything here only against hosts and networks you own or explicitly control.** Every tool below is a standard, widely-used security-testing utility, but that doesn't change the rule.

## What's tested and verified vs. what needs your environment

| File | Tested here? | Notes |
|---|---|---|
| `c2_emulator.py` | Yes — real client/server run, 5 successful check-ins with correct ground-truth logging | Zero real C2 capability, safe to run anywhere in your own lab |
| `dns_query_generator.py` | Yes — real DNS queries issued and logged correctly | |
| `benchmark_harness.py` | Yes — latency-matching logic verified against a mocked API response | Needs your live `/alerts` API to produce real numbers |
| `traffic_gen.sh` (hping3/iperf3/nmap/iodine) | **No** — needs real network privileges and installed tools my sandbox doesn't have | Standard, well-documented invocations; verify each works in your lab before trusting the numbers |

## Workflow per threat class

**C2 beaconing (ENG02):**
```bash
python3 c2_emulator.py server --port 4444        # on a "victim" host
python3 c2_emulator.py client --target <victim_ip> --port 4444 \
    --interval 30 --jitter 2 --count 40           # on an "attacker" host -- 40 matches ENG02's WINDOW_SIZE
python3 benchmark_harness.py latency \
    --ground-truth c2_emulator_ground_truth.json \
    --api http://localhost:8000 --threat-class C2_BEACONING \
    --window-before 5 --window-after 120
```

**DGA / DNS tunnelling (ENG03):**
```bash
python3 dns_query_generator.py --mode dga --count 30 --rate 1
python3 benchmark_harness.py latency \
    --ground-truth dns_dga_ground_truth.json \
    --api http://localhost:8000 --threat-class DGA_DOMAIN \
    --window-before 5 --window-after 60
```

**Volumetric DDoS (ENG01):**
```bash
./traffic_gen.sh ddos <target_ip> 443 30
python3 benchmark_harness.py latency \
    --ground-truth traffic_gen_ddos_ground_truth.json \
    --api http://localhost:8000 --threat-class VOLUMETRIC_DDOS \
    --window-before 2 --window-after 30
```

**Sustained throughput (flows/sec):**
```bash
# on the target: iperf3 -s
./traffic_gen.sh baseline <target_ip> 5201 60 &
python3 benchmark_harness.py throughput --api http://localhost:8000 --duration 60
```
Note `measure_throughput()`'s honest limitation, documented in its own docstring: it measures how fast the API indexes alerts, not raw packet throughput through Zeek/Redpanda. Pair it with a real load generator (iperf3 above, or Ostinato/TRex for higher rates) running concurrently — the throughput number that matters is what the whole pipeline sustains, not just the API's own responsiveness.

## Computing live Precision/Recall/F1/ROC-AUC

Each generator's ground-truth JSON already tells you exactly what was sent and when — that's your label set. To compute these against live traffic:
1. Run a generator for a mix of malicious (known-bad, e.g. `c2_emulator.py`) and benign traffic (ordinary browsing, `iperf3` baseline load) over the same time window.
2. Pull all alerts from `/alerts` for that window.
3. For each ground-truth event, check whether a matching alert exists (true positive) or not (false negative); for benign traffic, check whether any alert incorrectly fired against it (false positive).
4. Standard precision/recall/F1 formulas from there. This isn't built into `benchmark_harness.py` yet as a single command — worth adding once you've run a few of these and know what a realistic mixed-traffic test window looks like for your setup.
