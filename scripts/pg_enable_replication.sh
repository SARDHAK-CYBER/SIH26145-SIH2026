#!/bin/sh
# One-time: let the standby connect to the primary for streaming replication (adds a pg_hba rule, reloads; no restart).
#   docker compose exec -T postgres sh /scripts/pg_enable_replication.sh   (or run the two commands by hand)
set -eu
grep -q "replication stealthtap" "$PGDATA/pg_hba.conf" || echo "host replication stealthtap all scram-sha-256" >> "$PGDATA/pg_hba.conf"
psql -U stealthtap -d stealthtap -c "select pg_reload_conf()" >/dev/null
echo "replication enabled for user stealthtap"
