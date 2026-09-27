# Operations

Access control, tenancy, backup and resilience: what each control does, where it lives in the codebase, and how it was
verified. For install steps see [`INSTALLATION.md`](INSTALLATION.md); for architecture see [`TECHNICAL.md`](TECHNICAL.md).

## 1. Access control

| Control | Implementation | Verification |
|---|---|---|
| API key required on every route except `GET /health` and CORS pre-flight | `src/security.py` — pure-ASGI middleware, constant-time comparison; applied to both the API and the sensor | `tests/test_security.py`; live on the Docker stack: 401 without the key, 200 with it |
| Key accepted as `X-API-Key`, `Authorization: Bearer`, or `?api_key=` (query parameter only for SSE streams and file downloads, since `EventSource` and `<a download>` cannot set headers) | same | tests |
| Refuses to start on a non-loopback address without a key, or with a key shorter than 16 characters | `security.require_key_for_bind` (sensor); `docker compose` refuses to render without `STEALTHTAP_API_KEY` | tests, `docker compose config` |
| Datastores (PostgreSQL, Redis, OpenSearch, Redpanda, OpenSearch Dashboards) published to `127.0.0.1` only; API and dashboard bind to `${STEALTHTAP_BIND:-127.0.0.1}` | `docker-compose.yml` | CI `compose` job, `docker compose ps` |
| Dashboard prompts for the key on a 401 response and stores it only in that browser | `dashboard-app/src/lib/auth.ts`, `components/AuthGate.tsx` | type-check, build |

Generate a key with `python -c "import secrets;print(secrets.token_urlsafe(32))"` and set it as `STEALTHTAP_API_KEY` in `.env`.

### TLS

The compose stack includes a Caddy 2 reverse proxy (`deploy/Caddyfile`): dashboard on `https://<host>/` (443), API on
`https://<host>:8443` (8443), with HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, the `Server` header
removed, uploads up to 1 GB, and Server-Sent Events unbuffered. Plaintext API/dashboard ports remain bound to `127.0.0.1`
regardless of this configuration; the proxy is the only thing that publishes on `${STEALTHTAP_BIND}`.

| Deployment target | `.env` settings |
|---|---|
| Local use (default) | none — `https://localhost` with Caddy's own certificate authority |
| LAN | `STEALTHTAP_BIND=0.0.0.0`, `STEALTHTAP_HOST=<dns name>`, `STEALTHTAP_PUBLIC_API=https://<dns name>:8443`, `STEALTHTAP_CORS_ORIGINS=https://<dns name>` |
| Public certificate | additionally `STEALTHTAP_TLS=<email address>` (Let's Encrypt; requires ports 80/443 reachable from the internet) |

**Verified on the Docker stack**: TLS returns 200; the API returns 401 without a key and 200 with one, over TLS; a capture
upload through the proxy was analysed end to end; response headers match the configuration above; both TLS ports refuse
connections addressed to the host's LAN interface while bound to loopback. Certificate-chain verification: with only Caddy's
exported root certificate (`docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt .`) as the trust anchor, a
client verifies the connection successfully — trusting that one root in a browser is sufficient.

The live sensor (host process, port 8100) is not behind this proxy by default: it binds to loopback and refuses to bind
elsewhere without a key configured. Place it behind the same proxy if a remote dashboard needs to reach it directly.

## 2. Accounts, roles, and audit

Implementation: `src/accounts.py`.

- **Users** — scrypt-hashed passwords in `config/users.json`, managed with `scripts/manage_users.py add|list|passwd|remove`
  (minimum 12 characters, never stored or logged in clear text). `POST /auth/login` returns an HMAC-signed token (8-hour
  lifetime, signed with `STEALTHTAP_TOKEN_SECRET`) presented the same way as an API key. Removing a user or changing a role
  invalidates that user's existing tokens on the next request. Five failed login attempts for one (client address, user)
  pair lock it for five minutes; unknown users are checked with the same computational cost as known ones, to avoid timing
  disclosure.
- **Roles** — `viewer` (read-only), `analyst` (viewer plus upload/analyse and flow scoring), `sensor` (alert ingestion and
  health check only, for a machine account), `admin` (everything, including capture control and network discovery). API keys
  also carry a role: `STEALTHTAP_TENANT_KEYS="acme=<key>,globex/viewer=<key>,plant7/sensor=<key>"`. The server enforces every
  rule (403 on violation); the dashboard additionally disables controls a role cannot use.
- **Two-factor authentication (TOTP, RFC 6238)** — a user with a configured secret must present a 6-digit code (one-time
  use per 30-second step, ±1 step of clock skew tolerated; validated against the RFC's published test vector). Self-service
  enrolment: `POST /auth/mfa/setup` then `POST /auth/mfa/enable`; administered with `scripts/manage_users.py mfa-setup` /
  `mfa-reset`. `STEALTHTAP_REQUIRE_MFA_ROLES=admin` makes two-factor mandatory for that role. The dashboard sign-in form
  requests the code when the server indicates it is required.
- **Password change** — `POST /auth/password` (current and new password, ≥12 characters, distinct from the username and the
  current password); invalidates all existing sessions for that user. Administrators can also reset with
  `scripts/manage_users.py passwd`.
- **Audit log** — one JSON record per request (`STEALTHTAP_AUDIT_LOG`; Docker volume `stealthtap_audit`, rotated at 10 MB ×
  5 files): timestamp, user, tenant, role, method, request path without the query string, response status, and client
  address (resolved through `X-Forwarded-For`, trusted only from private/loopback peers), plus every login attempt. No
  password, token, or API key value is written to the log.
- **Per-tenant limits** — request rate (`STEALTHTAP_RATE_LIMIT_PER_MIN`, default 1200; HTTP 429 with `Retry-After`) and
  concurrent analysis jobs (`STEALTHTAP_TENANT_MAX_ANALYSES`, default 3), so one tenant cannot exhaust the shared analysis
  queue.

**Verified end to end on the running Docker stack, through TLS** (20 checks plus a positive control): authenticated login;
incorrect credentials rejected; unauthenticated requests rejected; a viewer account can read but not upload or control
capture; a sensor-role key can ingest alerts but not read them; an analyst in one tenant uploads and analyses a capture; a
viewer in the same tenant can read that capture's packets; an administrator in a different tenant receives 404 for the same
capture, its packets, its packet detail, and its export; an alert ingested for one tenant is visible to that tenant only, and
a direct lookup by another tenant returns 404; audit log entries are present and contain no credentials.

**Scope.** Single sign-on / OIDC is not implemented; the standard integration path is an OIDC-aware reverse proxy (for
example oauth2-proxy) in front of the existing TLS termination. There is no self-service password recovery by email — an
administrator resets a forgotten password. The host-side sensor process runs its own copy of this middleware and requires
the same user store and token secret to accept dashboard sessions.

## 3. Multi-tenant isolation

`STEALTHTAP_TENANT_KEYS="acme=<key>,globex=<key>"` assigns each tenant its own key (`STEALTHTAP_API_KEY` is the `default`
tenant). The key presented on a request determines its tenant, which scopes:

- **Stored alerts** — an `alerts.tenant` column (added automatically on upgrade; existing rows assigned to `default`);
  `/alerts/ingest`, `/alerts`, `/alerts/{id}`, and the dashboard's stored-alert view return only that tenant's rows.
- **Uploaded captures and the packet inspector** — a capture belongs to its uploading tenant; another tenant receives 404
  (not 403, so an identifier cannot be probed).
- **Asynchronous analysis jobs** — same isolation rule.

A sensor forwards alerts with its own tenant key (`STEALTHTAP_SENSOR_KEY` in the compose file, or `STEALTHTAP_API_KEY`
otherwise), so alerts from a given deployment's sensor land in that deployment's partition.

**Scope.** Isolation applies to the primary PostgreSQL-backed alert/capture path. It does not extend to the
OpenSearch/Zeek/Suricata batch path (a shared index with no tenant field) or to raw compute beyond the rate and
concurrency limits above — there is no per-tenant CPU or memory cgroup. This model suits a small number of trusted tenants
sharing one deployment, not mutually adversarial multi-tenancy.

## 4. Backup and restore

- The `backup` service writes a PostgreSQL custom-format dump every `BACKUP_INTERVAL_HOURS` (default 24) to the
  `stealthtap_backups` volume, retaining the newest `BACKUP_KEEP` dumps (default 14). A dump is renamed into place only
  after `pg_dump` completes successfully, so a failed dump never overwrites a good one.
- Restore with `scripts/pg_restore.sh [dump] [target-db]` (defaults to the newest dump and the `stealthtap` database).
  Restoring into a separate scratch database first is the recommended way to validate a backup without touching production
  data.
- **Restore drill performed**: a dump of the live database was restored into a fresh database
  (`pg_restore --clean --if-exists`); row count, tenant count, and latest timestamp were identical to the source.
- Recovery point objective equals the backup interval (24 hours by default; set `BACKUP_INTERVAL_HOURS=1` for hourly
  backups). For a near-zero RPO, use the PostgreSQL streaming replica described in §6.
- Not covered by this backup: uploaded captures (`data/captures`, evicted on a TTL by design), model files (version
  controlled), and Redis state (soft state that rebuilds from traffic).

## 5. Resilience of the alert path

- **On-disk alert spool** — if the API or database is unreachable, the sensor's forwarder writes each failed batch to disk
  (`STEALTHTAP_SPOOL_DIR`, default `data/spool`; capped by `STEALTHTAP_SPOOL_MAX_MB`, oldest entries evicted first) and
  replays it in order once the API responds again, so a later batch never overtakes an earlier one. Verified with a
  simulated API outage and recovery (`tests/test_forwarder_spool.py`).
- **Sensor auto-restart** — Docker: `restart: unless-stopped`. Linux: `packaging/systemd/stealthtap-sensor.service`, running
  with only `CAP_NET_RAW` and `CAP_NET_ADMIN`, `Restart=always`. Windows: `packaging/windows/install_sensor_task.ps1`
  registers a scheduled task that starts at boot, runs as `NT AUTHORITY\SYSTEM` (so Npcap's Administrators-only mode never
  prompts for elevation), and supervises the sensor process itself, relaunching it within seconds of any exit.
- **Verified**: the Windows task was installed, confirmed running as `SYSTEM`, capturing without a prompt, and relaunching a
  manually terminated sensor process within roughly fifteen seconds. It was also verified across an actual reboot of the
  deployment machine: the sensor and the full 13-container Docker stack returned automatically within two minutes of boot,
  with zero manual intervention and zero packet loss on resumption. Docker Desktop's own "start at login" preference was
  disabled at the time of that test and had no bearing on the result — the stack's startup did not depend on it.
- Container-level `restart: unless-stopped` applies throughout the compose stack; the API exposes a health check; PostgreSQL,
  Redis and Redpanda gate their dependents on health.
- **Scope.** The Linux systemd unit is syntax-validated but has not been exercised on a running Linux host in this
  environment.

## 6. High availability

A second API replica and a PostgreSQL hot standby, behind the same TLS proxy:

```bash
# one-time: allow the standby to connect to the primary for replication
docker compose exec -T postgres sh -c 'grep -q "replication stealthtap" $PGDATA/pg_hba.conf || echo "host replication stealthtap all scram-sha-256" >> $PGDATA/pg_hba.conf; psql -U stealthtap -c "select pg_reload_conf()"'

STEALTHTAP_API_UPSTREAMS="api:8000 api2:8000" docker compose --profile ha up -d
python scripts/ha_failover_test.py
```

| Tier | Design | Rationale |
|---|---|---|
| Sensor | One instance per tap/mirror; a redundant pair on the same tap can run active/standby, with the API de-duplicating alerts on `(source, destination, ports, timestamp, class)` | Holds only soft state (flow table, detector windows); losing one loses at most the in-flight window |
| API | N stateless replicas behind a load balancer; models are read-only files, state lives in PostgreSQL/Redis | `/alerts/ingest` is idempotent (`ON CONFLICT (alert_id) DO NOTHING`), so retries and spool replays cannot duplicate an alert |
| PostgreSQL | Primary plus a streaming replica; automatic failover via Patroni or a managed service for a fully automated setup | The only durable state in the system |
| Redis | Sentinel, a managed HA Redis, or the in-process store (single-process deployments do not require Redis) | Soft state only |

**Measured**: with two API replicas behind the proxy (active health checks every 3 seconds, client-IP affinity, 15-second
ejection of a failed replica), a continuous request stream through the TLS proxy succeeded on 235 of 235 requests while
each replica was stopped in turn, with a longest gap of 0.5 seconds. The PostgreSQL standby, created with `pg_basebackup`
and streaming replication, reflected a newly ingested alert 0.42 seconds after ingestion. A failover drill — stopping the
primary, promoting the standby with `scripts/pg_failover.sh`, and re-pointing the API replicas — completed in 20 seconds
from primary loss to a working API on the promoted node, with prior data intact and new writes accepted.

Failover is a manual, scripted operation; automatic failover requires an orchestrator such as Patroni. After a promotion,
the former primary must be rebuilt as a fresh standby rather than restarted directly, to avoid a diverged replica.

**Scope.** These mechanisms were built and measured on a single physical host running multiple containers; this validates
the mechanisms themselves, not resilience to loss of an entire host, rack, or network segment. Replication is asynchronous,
so a primary lost in the final fraction of a second before replication could lose that data. In-memory state (asynchronous
job results, login-lockout counters, the rate limiter, one-time-code replay tracking) is held per replica rather than
shared. Redis, Redpanda, and OpenSearch each run as a single instance. Sensors are not clustered.

## 7. Long-duration testing

The longest continuous run performed against a real network interface is 1.76 hours (`docs/reports/live_soak_wifi_fixed.json`),
with zero kernel, record, or user-space packet drops and flat memory after warm-up. A replay-based soak against the full real
capture corpus ran for 4 hours at reduced rate (`docs/reports/soak_mixed_4h.json`). A multi-day run on a mirrored production
link is the standard acceptance test before a production rollout and requires that physical deployment.
