#!/bin/sh
# Scheduled logical backups of the alert store (PostgreSQL custom format, restorable with pg_restore).
#   BACKUP_INTERVAL_HOURS (default 24)   BACKUP_KEEP (default 14 newest dumps kept)   BACKUP_DIR (default /backups)
# A dump is written to a temp name and renamed only when pg_dump exits 0, so a crash never leaves a truncated "good" file.
set -eu
DIR="${BACKUP_DIR:-/backups}"; KEEP="${BACKUP_KEEP:-14}"; EVERY=$(( ${BACKUP_INTERVAL_HOURS:-24} * 3600 ))
mkdir -p "$DIR"
while true; do
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  if pg_dump -h postgres -U stealthtap -d stealthtap -Fc -f "$DIR/.stealthtap-$STAMP.tmp"; then
    mv "$DIR/.stealthtap-$STAMP.tmp" "$DIR/stealthtap-$STAMP.dump"
    echo "[backup] wrote $DIR/stealthtap-$STAMP.dump ($(wc -c < "$DIR/stealthtap-$STAMP.dump") bytes)"
    ls -1t "$DIR"/stealthtap-*.dump | tail -n +$((KEEP + 1)) | xargs -r rm -f
  else
    echo "[backup] pg_dump FAILED at $STAMP" >&2; rm -f "$DIR/.stealthtap-$STAMP.tmp"
  fi
  sleep "$EVERY"
done
