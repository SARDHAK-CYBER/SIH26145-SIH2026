# Operations: security, tenancy, backup, resilience

What is implemented and verified, what is a documented design only, and how to check each.

## 1. Access control

| Control | Where | Verified by |
|---|---|---|
| API key on every route except `GET /health` and CORS pre-flight | `src/security.py` (pure-ASGI middleware, constant-time compare) on the API and on the sensor | `tests/test_security.py`; live: Docker API returns 401 without the key, 200 with it |
| Key accepted as `X-API-Key`, `Authorization: Bearer`, or `?api_key=` (the last only for SSE / file downloads, because `EventSource` and `<a download>` cannot set headers) | same | tests |
| Refuses to start on a non-loopback address with no key, or with a key shorter than 16 chars | `security.require_key_for_bind` (sensor); `docker compose` refuses to render without `STEALTHTAP_API_KEY` | tests, `docker compose config` |
| Datastores (Postgres, Redis, OpenSearch, Redpanda, OpenSearch Dashboards) published on `127.0.0.1` only; API and dashboard on `${STEALTHTAP_BIND:-127.0.0.1}` | `docker-compose.yml` | CI job `compose` + `docker compose ps` |
| Dashboard asks for the key when the server answers 401 and keeps it in that browser only | `dashboard-app/src/lib/auth.ts`, `components/AuthGate.tsx` | type-check + build |

Generate a key: `python -c "import secrets;print(secrets.token_urlsafe(32))"` and put it in `.env` as `STEALTHTAP_API_KEY`.

### TLS (Caddy proxy, `deploy/Caddyfile`)
The compose stack includes a `proxy` service (Caddy 2): dashboard on **https://HOST/** (443), API on **https://HOST:8443**, HSTS + `nosniff` + `X-Frame-Options: DENY`, `Server` header removed, uploads up to 1 GB, SSE not buffered. The plaintext API/dashboard ports stay bound to `127.0.0.1` only; the proxy publishes on `${STEALTHTAP_BIND:-127.0.0.1}`.

| Goal | Settings in `.env` |
|---|---|
| Local use (default) | nothing: `https://localhost` with Caddy's own CA (browsers warn until you trust it: `docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt .` and import it) |
| Serve the LAN | `STEALTHTAP_BIND=0.0.0.0`, `STEALTHTAP_HOST=<dns name>`, `STEALTHTAP_PUBLIC_API=https://<dns name>:8443`, `STEALTHTAP_CORS_ORIGINS=https://<dns name>` |
| Public certificate | additionally `STEALTHTAP_TLS=<your e-mail>` (Let's Encrypt; ports 80/443 must be reachable from the internet) |

Verified 2026-09-27 on the Docker stack: TLS 200, API 401 without / 200 with key over TLS, a pcap upload through the proxy analysed, headers present, and both TLS ports refuse connections addressed to the machine's LAN IP while bound to loopback. Not verified: a Let's Encrypt issuance, and the browser trust-store step. The live **sensor** (host process, port 8100) is not behind this proxy: it binds loopback by default and refuses to bind elsewhere without a key; put it behind the same proxy if a remote dashboard must reach it. Certificate chain check done 2026-09-27: with only Caddy's exported root (`docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt .`) as trust anchor, `curl --cacert root.crt https://localhost/` verifies (200, verify result 0), so trusting that one root in a browser is sufficient; I did not modify this machine's trust store. Public-certificate mode was only validated at config level: `caddy validate` accepts `STEALTHTAP_TLS=<email>` with a public host and `caddy adapt` shows an `acme` issuer for that host and e-mail; no certificate was actually issued (needs a public DNS name reachable on ports 80/443).

## 1b. Users, roles, audit, limits (`src/accounts.py`)

* **Named users** with scrypt-hashed passwords in `config/users.json`, managed by `scripts/manage_users.py add|list|passwd|remove` (passwords >= 12 chars, never stored or logged in clear). `POST /auth/login` returns an HMAC-signed token (8 h; `STEALTHTAP_TOKEN_SECRET`) used exactly like an API key. Removing a user or changing a role invalidates that user's tokens on the next request. Five failed logins for one (client address, user) lock that pair for five minutes; unknown users cost the same work as known ones. The dashboard has a sign-in form (username/password, with "use an API key instead").
* **Roles:** `viewer` (all GET/HEAD), `analyst` (+ upload/analyse, score), `sensor` (`POST /alerts/ingest` and `/health` only), `admin` (everything, including starting/stopping capture and discovery). API keys carry roles too: `STEALTHTAP_TENANT_KEYS="acme=<key>,globex/viewer=<key>,plant7/sensor=<key>"`. The server enforces this (403); the dashboard does not hide buttons a role cannot use.
* **Audit log** (`STEALTHTAP_AUDIT_LOG`, Docker volume `stealthtap_audit`, rotated 10 MB x 5): one JSON line per request with time, user, tenant, role, method, path **without the query string**, status, client address (the real client behind the proxy via `X-Forwarded-For`, trusted only from private/loopback peers), and login successes/failures. Checked: no password, token or `api_key` value appears in it. Under Docker Desktop the address seen is the host's NAT gateway (172.18.0.1), not the LAN client.
* **Limits per tenant:** request rate (`STEALTHTAP_RATE_LIMIT_PER_MIN`, default 1200, HTTP 429 + `Retry-After`) and analysis slots (`STEALTHTAP_TENANT_MAX_ANALYSES`, default 3) so one tenant cannot fill the shared analysis queue. This is a fairness guard, not hard compute isolation: a tenant can still use the CPU its 3 slots allow.

**Verified end to end on the running Docker stack through the TLS proxy (2026-09-27, 20/20 checks + a positive control):** logins over TLS; wrong password 401; no credential 401; viewer reads but cannot upload/start capture (403); a sensor key cannot read alerts and can only ingest; acme's analyst uploads and analyses a capture; acme's viewer reads its packets while a globex admin gets 404 for the capture, its packets, its packet detail and its export; an alert ingested for acme is visible to acme, invisible to plant7 and globex, and a direct fetch by globex is 404; audit lines present, no secrets. Test users and keys were removed afterwards.

**Still not there:** no SSO/OIDC, no password-reset flow, no MFA; the sensor process (host) has its own copy of the same middleware and needs the same users file and token secret to accept dashboard logins; a compromised admin credential is a compromised tenant.

## 2. Multi-tenant isolation (implemented at the storage/API layer)

`STEALTHTAP_TENANT_KEYS="acme=<key>,globex=<key>"` gives each tenant its own key (`STEALTHTAP_API_KEY` is tenant `default`).
The key a request presents decides its tenant, and that tenant scopes:

* stored alerts: `alerts.tenant` column (added automatically, existing rows become `default`); `/alerts/ingest`, `/alerts`, `/alerts/{id}`, and the dashboard's stored-alert view only see their own tenant's rows;
* uploaded captures and the packet inspector: a capture belongs to the uploading tenant; another tenant gets `404` (not `403`, so ids are not confirmable);
* async analysis jobs: same rule.

A sensor forwards with its tenant's key (`STEALTHTAP_SENSOR_KEY` in compose, otherwise `STEALTHTAP_API_KEY`), so alerts from a customer's sensor land in that customer's partition.

**Not isolated:** the OpenSearch/Zeek/Suricata side-path (shared index, no tenant field), the live sensor's own in-memory views (one sensor = one tenant: run one sensor per tenant), and raw compute (per-tenant request-rate and analysis-slot limits exist, section 1b, but no CPU/memory cgroup isolation). Treat this as data-partitioning for a small number of trusted tenants, not hostile multi-tenancy.

## 3. Backup and restore

* Service `backup` (compose) writes a PostgreSQL custom-format dump every `BACKUP_INTERVAL_HOURS` (default 24) into volume `stealthtap_backups`, keeps the newest `BACKUP_KEEP` (default 14). A dump is renamed into place only when `pg_dump` succeeds.
* Restore: `scripts/pg_restore.sh [dump] [target-db]` (defaults: newest dump, database `stealthtap`). Restore into a scratch database first to prove a backup.
* **Drill performed** (2026-09-27, Docker stack): dump of the live database restored into a fresh database with `pg_restore --clean --if-exists`, exit 0, row count / tenant count / newest timestamp identical (323 alerts, 1 tenant, same `max(ts)`).
* RPO = the backup interval (24 h by default; set `BACKUP_INTERVAL_HOURS=1` for hourly). For RPO near zero use Postgres streaming replication (section 5).
* Not backed up: uploaded captures (`data/captures`, evicted by TTL by design), model files (in git), Redis (detector state is soft state that rebuilds).

## 4. Resilience of the alert path

* **Alert spool.** If the API/DB is down, the sensor's forwarder writes each failed batch to an on-disk spool (`STEALTHTAP_SPOOL_DIR`, default `data/spool`; a named volume in the compose sensor; capped by `STEALTHTAP_SPOOL_MAX_MB`, oldest evicted first) and re-sends in order when the API answers, never letting a new batch overtake older ones. Tested with a fake API that is down, then up (`tests/test_forwarder_spool.py`).
* **Auto-restart of the sensor.** Docker: `restart: unless-stopped`. Linux: `packaging/systemd/stealthtap-sensor.service` (capabilities `CAP_NET_RAW`+`CAP_NET_ADMIN` only, `Restart=always`). Windows: `packaging/windows/install_sensor_task.ps1` registers an at-boot scheduled task that runs as SYSTEM (so Npcap's Administrators-only mode never prompts) and supervises the sensor itself in a loop (relaunch 3 s after any exit; Task Scheduler alone did not restart it when the wrapper exited cleanly, which the first install on 2026-09-27 showed). **Executed and proved on this machine:** installed with one UAC approval; the sensor on port 8100 ran as `NT AUTHORITY\SYSTEM`, captured on Wi-Fi without any prompt, and after `Stop-Process -Force` on it was back within ~15 s under a new PID. Not verified: behaviour across an actual reboot. The systemd unit was only syntax-checked (no Linux host here; verifying it needs a systemd image, which was not downloaded). **Reboot persistence is unverified:** after rebooting run `powershell -ExecutionPolicy Bypass -File scripts\verify_after_reboot.ps1` — it checks uptime, that the sensor answers and runs as SYSTEM, that capture works without a prompt, that Docker services and TLS came back, and exits non-zero if anything needed a manual step.
* Containers use `restart: unless-stopped`; the API has a health check; Postgres/Redis/Redpanda health-gate their dependents.

## 5. High availability: design (not built here)

Everything above keeps a single node honest; it is not HA. The intended topology, and why each piece is safe to replicate:

| Tier | Approach | Why it works |
|---|---|---|
| Sensors | one per tap/mirror, each with its own `sensor id`/tenant key; for a redundant pair on the same tap run both and let the API de-duplicate on `(src,dst,ports,ts,class)`, or run active/standby behind the platform's supervisor | a sensor holds only soft state (flow table, detector windows); losing one loses at most the in-flight window |
| API | N stateless replicas behind a load balancer (models are read-only files; state is in Postgres/Redis) | `/alerts/ingest` is idempotent (`ON CONFLICT (alert_id) DO NOTHING`) so retries and spool replays cannot duplicate |
| PostgreSQL | primary + streaming replica with automatic failover (Patroni / a managed service); backups as above | the only durable state |
| Redis | Sentinel or a managed HA Redis, or leave the in-process store (single-process detectors do not need Redis) | soft state only |

Nothing in this table has been exercised on a multi-node deployment; only single-node Docker and single-host Windows were available.

## 6. Long-duration testing

See `docs/reports/soak_mixed_4h.json` (replay of the 27-capture real corpus through the full native pipeline for 4 h at reduced rate, sampling RSS/CPU/drops each second) and `docs/reports/soak_mixed_15min.json` for the earlier full-rate run. A 24-72 h run on a mirrored production link is still the acceptance test before relying on the sensor.
