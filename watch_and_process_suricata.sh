#!/usr/bin/env bash
# Same job-queue pattern as watch_and_process.sh (zeek-batch): watches
# /incoming for uploaded pcaps, runs Suricata against each, writes
# eve.json results to /outgoing/<job_id>/. Separate incoming/outgoing
# volumes from zeek-batch's -- kept as two independent services rather
# than sharing state, consistent with this project's existing pattern.
set -uo pipefail

INCOMING_DIR="${INCOMING_DIR:-/incoming}"
OUTGOING_DIR="${OUTGOING_DIR:-/outgoing}"
CONFIG_FILE="${CONFIG_FILE:-/suricata.yaml}"
POLL_INTERVAL="${POLL_INTERVAL:-1}"

mkdir -p "$INCOMING_DIR" "$OUTGOING_DIR"
echo "[suricata-batch] watching $INCOMING_DIR, config=$CONFIG_FILE"

while true; do
    for pcap_file in "$INCOMING_DIR"/*.pcap "$INCOMING_DIR"/*.pcapng; do
        [ -e "$pcap_file" ] || continue

        job_id=$(basename "$pcap_file")
        job_id="${job_id%.*}"
        job_out="$OUTGOING_DIR/$job_id"

        [ -d "$job_out" ] && continue

        mkdir -p "$job_out"
        echo "[suricata-batch] processing job $job_id"

        (
            suricata -r "$pcap_file" -c "$CONFIG_FILE" -l "$job_out" -k none \
                > "$job_out/suricata_stdout.log" 2> "$job_out/suricata_stderr.log"
            echo $? > "$job_out/exit_code.txt"
        )

        exit_code=$(cat "$job_out/exit_code.txt" 2>/dev/null || echo "1")
        if [ "$exit_code" = "0" ]; then
            touch "$job_out/DONE"
            echo "[suricata-batch] job $job_id complete"
        else
            touch "$job_out/ERROR"
            echo "[suricata-batch] job $job_id FAILED (exit $exit_code) -- see $job_out/suricata_stderr.log"
        fi

        rm -f "$pcap_file"
    done
    sleep "$POLL_INTERVAL"
done
