#!/usr/bin/env bash
# Watches /incoming for uploaded pcap files, runs Zeek (with ICSNPP +
# file extraction, see batch_policy.zeek) against each, and writes
# results to /outgoing/<job_id>/. This is the bridge between the
# FastAPI upload endpoint (which has no Zeek installed) and real Zeek
# processing, without giving the API container Docker socket access.
set -uo pipefail

INCOMING_DIR="${INCOMING_DIR:-/incoming}"
OUTGOING_DIR="${OUTGOING_DIR:-/outgoing}"
POLICY_SCRIPT="${POLICY_SCRIPT:-/batch_policy.zeek}"
POLL_INTERVAL="${POLL_INTERVAL:-1}"

mkdir -p "$INCOMING_DIR" "$OUTGOING_DIR"
echo "[zeek-batch] watching $INCOMING_DIR, policy=$POLICY_SCRIPT"

while true; do
    for pcap_file in "$INCOMING_DIR"/*.pcap "$INCOMING_DIR"/*.pcapng; do
        [ -e "$pcap_file" ] || continue  # glob didn't match anything

        job_id=$(basename "$pcap_file")
        job_id="${job_id%.*}"
        job_out="$OUTGOING_DIR/$job_id"

        # Skip if already processed or currently in progress
        [ -d "$job_out" ] && continue

        mkdir -p "$job_out"
        echo "[zeek-batch] processing job $job_id"

        (
            cd "$job_out" || exit 1
            zeek -r "$pcap_file" "$POLICY_SCRIPT" > zeek_stdout.log 2> zeek_stderr.log
            echo $? > exit_code.txt
        )

        exit_code=$(cat "$job_out/exit_code.txt" 2>/dev/null || echo "1")
        if [ "$exit_code" = "0" ]; then
            touch "$job_out/DONE"
            echo "[zeek-batch] job $job_id complete"
        else
            touch "$job_out/ERROR"
            echo "[zeek-batch] job $job_id FAILED (exit $exit_code) -- see $job_out/zeek_stderr.log"
        fi

        # Remove the source pcap once processed -- job_out retains
        # everything needed; no reason to keep two copies.
        rm -f "$pcap_file"
    done
    sleep "$POLL_INTERVAL"
done
