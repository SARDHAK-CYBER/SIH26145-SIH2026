#!/usr/bin/env bash
# Traffic generator wrapper scripts for StealthTap benchmarking.
#
# These need real network privileges and cannot be tested in a sandboxed
# environment -- they're standard invocations of established, widely-used
# tools, but you should verify each one runs correctly in your own lab
# before relying on the numbers it produces. Run all of these only
# against hosts/networks you own or explicitly control.
#
# Usage: source this file, then call the function you need, e.g.:
#   ./traffic_gen.sh ddos 10.0.0.5 443 30
set -euo pipefail

TARGET_IP="${2:-10.0.0.5}"
TARGET_PORT="${3:-443}"
DURATION="${4:-30}"

log_ground_truth() {
    local kind="$1"
    local start_ts
    start_ts=$(date +%s.%N)
    echo "{\"kind\": \"$kind\", \"start_ts\": $start_ts, \"target\": \"$TARGET_IP\", \"port\": $TARGET_PORT}" \
        > "traffic_gen_${kind}_ground_truth.json"
    echo "[traffic_gen] logged start time for $kind -> traffic_gen_${kind}_ground_truth.json"
}

# ENG01 (Volumetric DDoS): SYN flood with randomized source IPs.
# Matches the pattern in your own README's harness table.
run_ddos() {
    log_ground_truth "ddos"
    echo "[traffic_gen] SYN flood -> ${TARGET_IP}:${TARGET_PORT} for ${DURATION}s"
    timeout "$DURATION" hping3 --flood --rand-source -S -p "$TARGET_PORT" "$TARGET_IP" || true
}

# ENG01 (Slowloris variant): many slow, low-and-slow connections.
run_slowloris() {
    log_ground_truth "slowloris"
    echo "[traffic_gen] Slowloris-style low-and-slow -> ${TARGET_IP}:${TARGET_PORT}"
    # Requires slowloris.py or similar installed separately -- hping3
    # alone isn't well suited to this pattern. Example if you have it:
    # python3 slowloris.py "$TARGET_IP" -p "$TARGET_PORT" -s 1000
    echo "[traffic_gen] NOTE: install a slowloris tool separately, this is a placeholder invocation"
}

# ENG05 (Reconnaissance): port scan across many destination ports.
run_recon() {
    log_ground_truth "recon"
    echo "[traffic_gen] port scan -> ${TARGET_IP}"
    nmap -sS -p 1-1000 --max-rate 200 "$TARGET_IP" || true
}

# Baseline sustained load, for the flows/sec throughput number.
# Run 'iperf3 -s' on the target first.
run_baseline_load() {
    log_ground_truth "baseline"
    echo "[traffic_gen] sustained iperf3 load -> ${TARGET_IP} for ${DURATION}s"
    iperf3 -c "$TARGET_IP" -t "$DURATION" -P 4
}

# ENG03 (DNS tunnelling), via iodine -- requires iodined running on a
# server you control with a matching NS delegation. This is a heavier
# setup than the pure-Python dns_query_generator.py's tunnel mode; use
# that instead unless you specifically need a fully realistic tunnel
# with actual IP-over-DNS traffic.
run_dns_tunnel_iodine() {
    log_ground_truth "dns_tunnel"
    echo "[traffic_gen] iodine DNS tunnel client -- requires iodined server + NS delegation already configured"
    echo "[traffic_gen] example: sudo iodine -f -P <shared_secret> tunnel.yourdomain.test"
    echo "[traffic_gen] NOTE: this is a setup-heavy option; dns_query_generator.py --mode tunnel is the simpler path"
}

case "${1:-}" in
    ddos) run_ddos ;;
    slowloris) run_slowloris ;;
    recon) run_recon ;;
    baseline) run_baseline_load ;;
    dns_tunnel) run_dns_tunnel_iodine ;;
    *)
        echo "Usage: $0 {ddos|slowloris|recon|baseline|dns_tunnel} <target_ip> <target_port> <duration_s>"
        exit 1
        ;;
esac
