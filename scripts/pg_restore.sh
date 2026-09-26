#!/bin/sh
# Restore a backup into the running stack.   scripts/pg_restore.sh [dump-file-name] [target-db]
#   default: newest dump in the backups volume, target database "stealthtap" (existing alerts table is replaced).
# Restoring into a scratch database first ("stealthtap_verify") is the way to prove a backup is usable.
set -eu
DUMP="${1:-}"; DB="${2:-stealthtap}"
if [ -z "$DUMP" ]; then DUMP=$(docker compose exec -T backup sh -c 'ls -1t /backups/stealthtap-*.dump | head -n 1'); else DUMP="/backups/$DUMP"; fi
[ "$DB" = "stealthtap" ] || docker compose exec -T postgres psql -U stealthtap -d postgres -c "DROP DATABASE IF EXISTS $DB" -c "CREATE DATABASE $DB"
docker compose exec -T backup pg_restore -h postgres -U stealthtap -d "$DB" --clean --if-exists --no-owner "$DUMP"
echo "restored $DUMP into $DB"
