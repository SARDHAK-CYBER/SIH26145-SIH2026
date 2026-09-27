#!/bin/sh
# MANUAL failover: promote the standby to primary and point the API replicas at it.  Use when the primary is lost.
#   sh scripts/pg_failover.sh
# After promotion the old primary must NOT be started again (it would diverge): rebuild it as a new standby from the promoted node.
set -eu
docker compose --profile ha exec -T -u postgres postgres-replica sh -c 'pg_ctl promote -D "$PGDATA"'
until docker compose --profile ha exec -T postgres-replica psql -U stealthtap -d stealthtap -Atc "select not pg_is_in_recovery()" | grep -q t; do sleep 1; done
echo "promoted. Restarting the API replicas against it:"
DATABASE_HOST_OVERRIDE=postgres-replica docker compose --profile ha up -d --no-deps --force-recreate api api2
