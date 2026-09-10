#!/usr/bin/env python3
"""
Real throughput/latency benchmark against StealthTap's proven /analyze/pcap
endpoint. Run this against your live docker compose stack.

Methodology: sends each real pcap you point it at REPEAT_RUNS times,
records real wall-clock request time AND the API's own self-reported
timing.parse_seconds / timing.detection_seconds from each response, then
reports honest percentiles -- not a single anecdotal run.

Usage:
    python benchmark_pipeline.py http://localhost:8000 file1.pcap file2.pcap ...
"""
import sys, time, json, statistics
import requests

REPEAT_RUNS = 5  # per file -- gives real min/median/p95, not one lucky/unlucky sample


def benchmark_file(api_base: str, filepath: str) -> dict:
    results = []
    for i in range(REPEAT_RUNS):
        t0 = time.time()
        with open(filepath, "rb") as f:
            resp = requests.post(f"{api_base}/analyze/pcap", files={"file": f}, timeout=300)
        wall_time = time.time() - t0
        if resp.status_code != 200:
            print(f"  [run {i+1}] FAILED: HTTP {resp.status_code} -- {resp.text[:200]}")
            continue
        data = resp.json()
        flows = data["packet_summary"]["conn_flows"]
        parse_s = data["timing"]["parse_seconds"]
        detect_s = data["timing"]["detection_seconds"]
        results.append({
            "wall_time": wall_time, "parse_s": parse_s, "detect_s": detect_s,
            "flows": flows, "flows_per_sec_detection_only": flows / detect_s if detect_s > 0 else 0,
        })
        print(f"  [run {i+1}] wall={wall_time:.2f}s parse={parse_s:.2f}s detect={detect_s:.2f}s flows={flows}")

    if not results:
        return {"file": filepath, "error": "all runs failed"}

    wall_times = [r["wall_time"] for r in results]
    detect_times = [r["detect_s"] for r in results]
    flows_per_sec = [r["flows_per_sec_detection_only"] for r in results]
    return {
        "file": filepath, "runs": len(results), "flows": results[0]["flows"],
        "wall_time_median": statistics.median(wall_times),
        "wall_time_p95": sorted(wall_times)[int(len(wall_times)*0.95)] if len(wall_times) > 1 else wall_times[0],
        "detection_seconds_median": statistics.median(detect_times),
        "flows_per_sec_median": statistics.median(flows_per_sec),
    }


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    api_base, files = sys.argv[1], sys.argv[2:]

    all_results = []
    for filepath in files:
        print(f"\n=== {filepath} ===")
        result = benchmark_file(api_base, filepath)
        all_results.append(result)

    print("\n" + "="*70)
    print("SUMMARY -- real, measured, multi-run results")
    print("="*70)
    for r in all_results:
        if "error" in r:
            print(f"{r['file']}: {r['error']}")
            continue
        print(f"{r['file']}:")
        print(f"  {r['flows']} flows, {r['runs']} runs")
        print(f"  Median wall-clock latency: {r['wall_time_median']:.2f}s (p95: {r['wall_time_p95']:.2f}s)")
        print(f"  Median detection-only throughput: {r['flows_per_sec_median']:.0f} flows/sec")

    with open("benchmark_results.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print("\nFull results written to benchmark_results.json")


if __name__ == "__main__":
    main()
