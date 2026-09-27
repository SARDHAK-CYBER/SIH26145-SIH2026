#!/bin/sh
# PostgreSQL hot-standby for the alert store (profile "ha"). First start: pg_basebackup from the primary, then run as a streaming replica.
# The primary must allow replication connections from this network (scripts/pg_enable_replication.sh does that once).
set -eu
export PGPASSWORD="${PGPASSWORD:?}"
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  until pg_isready -h postgres -U stealthtap -d stealthtap >/dev/null 2>&1; do sleep 2; done
  rm -rf "$PGDATA"/* 2>/dev/null || true
  pg_basebackup -h postgres -U stealthtap -D "$PGDATA" -R -X stream -P
  chmod 700 "$PGDATA"
fi
exec docker-entrypoint.sh postgres -c hot_standby=on
