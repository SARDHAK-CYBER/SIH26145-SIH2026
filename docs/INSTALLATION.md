# Installation and Deployment

Step-by-step setup, on Linux and Windows. For what the product does and its measured results, see [`README.md`](../README.md).
For architecture and internals, see [`TECHNICAL.md`](TECHNICAL.md).

StealthTap ships as a **service**, not a frozen executable, in two forms:

- **Docker stack** — the full pipeline (Zeek + ICSNPP, Suricata, YARA, Postgres, Redis, OpenSearch, Redpanda, TLS proxy,
  React dashboard). Recommended for anything beyond a quick local test.
- **Bare service** — just the API/sensor and the dashboard, no Docker. Fastest way to point at a live NIC like Wireshark.

## Contents
- [Prerequisites](#prerequisites)
- [Option A: Docker stack](#option-a-docker-stack-recommended)
- [Option B: bare service](#option-b-bare-service-no-docker)
- [Live sensor as an auto-restarting service](#live-sensor-as-an-auto-restarting-service)
- [TLS](#tls)
- [Accounts, roles and two-factor login](#accounts-roles-and-two-factor-login)
- [Multi-tenant keys](#multi-tenant-keys)
- [Backups](#backups)
- [High availability](#high-availability-optional)
- [Environment variable reference](#environment-variable-reference)
- [Post-install checklist](#post-install-checklist)
- [Uninstall / teardown](#uninstall--teardown)

## Prerequisites

| Need | Docker stack | Bare service |
|---|---|---|
| Docker + Docker Compose v2 | Required | — |
| Python 3.11 | — | Required |
| Rust toolchain + `maturin` | — | Optional (≈10× faster; falls back to pure Python without it) |
| [Npcap](https://npcap.com/) (Windows only) | Only for the optional live-tap sensor | Required for live capture |
| Administrator / root privileges | Only for the live-tap sensor container | Required for live capture (`CAP_NET_RAW` on Linux, elevated on Windows) |

Windows needs Npcap installed **separately**, with "WinPcap API-compatible Mode" checked — its free licence forbids
redistribution, so it is never bundled with this project.

## Option A: Docker stack (recommended)

```bash
git clone <this repo>
cd stealthtap-ntro
cp .env.example .env
```

Edit `.env` and set:
- `POSTGRES_PASSWORD`, `OPENSEARCH_ADMIN_PASSWORD` — real passwords, not the placeholders.
- `STEALTHTAP_API_KEY` — generate with `python -c "import secrets;print(secrets.token_urlsafe(32))"`. The stack **refuses to
  start** without this.
- `STEALTHTAP_TOKEN_SECRET` — generate with `python -c "import secrets;print(secrets.token_urlsafe(48))"`. Without it, login
  tokens are only valid until the API process restarts.

Never commit `.env`.

```bash
docker compose up -d --build     # every service restarts on failure and is health-gated
python scripts/system_check.py   # full-stack check -> docs/reports/LATEST.md
```

- **Dashboard**: `https://localhost` (Caddy's own local certificate authority — your browser will warn until you trust it;
  see [TLS](#tls) below). Asks for a sign-in.
- **API**: `https://localhost:8443`, header `X-API-Key: <your key>` or a signed-in session token.
- Plaintext ports (4173, 8000) stay bound to `127.0.0.1` only — they are not meant to be reached directly.

To also run the **live-capture tap** inside Docker (an alternative to the bare-service sensor below):

```bash
CAPTURE_IFACE=eth0 docker compose --profile tap up -d sensor
```

`CAPTURE_IFACE` must be connected to a switch mirror/SPAN port or a network TAP, not an ordinary access port — see
[`MIRROR_PORT_SETUP.md`](MIRROR_PORT_SETUP.md) for switch configuration by vendor, TAP/data-diode options, and how to
verify the deployment is genuinely one-directional.

## Option B: bare service (no Docker)

```bash
pip install -r requirements.txt
pip install maturin && maturin develop --release -m native/stealthtap_core/Cargo.toml   # optional but ~10x faster
python stealthtap_app.py            # http://127.0.0.1:8100
```

Live capture needs elevated privileges: Administrator on Windows, `root` or `CAP_NET_RAW` on Linux. Linux sensors can add
`--features afxdp` to the `maturin` build for AF_XDP kernel-bypass capture (see [`TECHNICAL.md`](TECHNICAL.md) for what that
buys you).

On Windows, a one-off elevated run (one UAC prompt) looks like:

```powershell
powershell -File scripts\start_sensor.ps1 -Port 8100
```

For a sensor that survives reboots and crashes without a repeated UAC prompt, see the next section instead.

The PyInstaller single-executable path is retired in favour of this service deployment (`packaging/` kept for reference
only).

## Live sensor as an auto-restarting service

### Windows
```powershell
# From an elevated PowerShell:
packaging\windows\install_sensor_task.ps1 -Port 8100
```
Registers a scheduled task that starts at boot, runs as `NT AUTHORITY\SYSTEM` (so Npcap's Administrators-only mode never
prompts for a UAC approval), and supervises the sensor process itself — relaunching it 3 seconds after any exit, whether from
a crash, a kill, or a reboot. **Verified on a real reboot**: the sensor was back and capturing within ~2 minutes of boot, with
zero kernel packet drops, no manual step. Remove with:
```powershell
Unregister-ScheduledTask StealthTapSensor -Confirm:$false
```

### Linux
```bash
sudo cp packaging/systemd/stealthtap-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now stealthtap-sensor
```
Configure in `/etc/stealthtap/sensor.env`:
```
STEALTHTAP_API_KEY=...
STEALTHTAP_API_URL=http://api-host:8000
CAPTURE_IFACE=eth1
```
Runs as an unprivileged user with only `CAP_NET_RAW`/`CAP_NET_ADMIN` granted — never root. **Not yet verified on a real Linux
reboot** (no Linux host was available to test this specific unit); the file itself is syntax-checked.

### After any deployment, confirm it survived a reboot
```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify_after_reboot.ps1
```
Checks: system uptime, the sensor answers and runs as SYSTEM, capture works without a prompt, Docker services and TLS came
back. Exits non-zero if anything needed a manual step.

## TLS

The Docker stack includes a Caddy reverse proxy (`deploy/Caddyfile`) terminating TLS on `:443` (dashboard) and `:8443` (API).
Plaintext ports stay on loopback regardless of this configuration.

| Goal | Settings in `.env` |
|---|---|
| Local use (default) | nothing — `https://localhost` with Caddy's own local CA |
| Trust the local CA in your browser | `docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt .` then import that file into your browser's trust store |
| Serve a LAN | `STEALTHTAP_BIND=0.0.0.0`, `STEALTHTAP_HOST=<dns name>`, `STEALTHTAP_PUBLIC_API=https://<dns name>:8443`, `STEALTHTAP_CORS_ORIGINS=https://<dns name>` |
| Public certificate | additionally `STEALTHTAP_TLS=<your e-mail>` (Let's Encrypt; ports 80/443 must be reachable from the internet) |

The live sensor (bare-service, port 8100) is **not** behind this proxy by default — it stays loopback-bound and refuses to
bind elsewhere without an API key configured.

## Accounts, roles and two-factor login

Named users (not just the shared API key) live in `config/users.json`, managed with:

```bash
python scripts/manage_users.py add alice --role analyst --tenant default   # prompts for a password (>=12 chars)
python scripts/manage_users.py list
python scripts/manage_users.py passwd alice        # change a password (invalidates that user's existing sessions)
python scripts/manage_users.py mfa-setup alice     # enrol two-factor (TOTP); prints the secret + otpauth:// URI once
python scripts/manage_users.py remove alice
```

Roles: `viewer` (read-only) · `analyst` (+ upload/analyse captures) · `sensor` (alert ingestion only, for a machine account) ·
`admin` (everything, including starting/stopping capture). The dashboard's own sign-in form supports both a username/password
(with a 6-digit code if that account has two-factor enabled) and, as a fallback, the shared API key.

Self-service for a signed-in user: `POST /auth/password` to change your own password, `POST /auth/mfa/setup` +
`POST /auth/mfa/enable` to turn on two-factor yourself. Force it for a role with `STEALTHTAP_REQUIRE_MFA_ROLES=admin` in
`.env`.

Every request is written to an audit log (`data/audit/audit.jsonl` in the Docker volume `stealthtap_audit`) — who, what,
when, from where, never a password or token.

## Multi-tenant keys

Optional, for isolating multiple customers/sites on one deployment:

```
STEALTHTAP_TENANT_KEYS=acme=<key>,globex/viewer=<key>,plant7/sensor=<key>
```

Format: `tenant[/role]=key` (role defaults to `admin`). Each tenant's stored alerts, uploaded captures and analysis jobs are
isolated from every other tenant's — verified end to end (a viewer in one tenant gets a 404, not a 403, for another tenant's
capture, so ids can't be probed). **Not isolated**: raw compute beyond a per-tenant rate limit and analysis-slot cap
(`STEALTHTAP_RATE_LIMIT_PER_MIN`, `STEALTHTAP_TENANT_MAX_ANALYSES`), and the OpenSearch/Zeek/Suricata side path.

## Backups

A scheduled `pg_dump` of the alert store runs automatically in the `backup` service (Docker), writing to the
`stealthtap_backups` volume every `BACKUP_INTERVAL_HOURS` (default 24), keeping the newest `BACKUP_KEEP` (default 14).
Restore:

```bash
sh scripts/pg_restore.sh [dump-file-name] [target-db]   # default: newest dump, into "stealthtap"
```

Restoring into a scratch database first (a second argument other than `stealthtap`) is the way to prove a backup is usable
without touching the live data.

## High availability (optional)

A second API replica and a PostgreSQL hot standby, behind the same TLS proxy, on one Docker host:

```bash
# one-time: let the standby connect to the primary
docker compose exec -T postgres sh -c 'grep -q "replication stealthtap" $PGDATA/pg_hba.conf || echo "host replication stealthtap all scram-sha-256" >> $PGDATA/pg_hba.conf; psql -U stealthtap -c "select pg_reload_conf()"'

STEALTHTAP_API_UPSTREAMS="api:8000 api2:8000" docker compose --profile ha up -d
```

Database failover is **manual** — run `sh scripts/pg_failover.sh` if the primary is lost; it promotes the standby and
re-points the API replicas at it. The old primary must not be restarted afterward without first rebuilding it as a fresh
standby (it would otherwise diverge). Full numbers from a real failover drill on this stack: [`OPERATIONS.md`](OPERATIONS.md)
§6.

## Environment variable reference

| Variable | Purpose | Default |
|---|---|---|
| `POSTGRES_PASSWORD`, `OPENSEARCH_ADMIN_PASSWORD` | Real passwords for the datastores | none — required |
| `STEALTHTAP_API_KEY` | Shared API key; also the "default" tenant's admin key | none — required for non-loopback binds |
| `STEALTHTAP_TOKEN_SECRET` | Signs login tokens | none — a random per-process secret if unset (tokens die on restart) |
| `STEALTHTAP_TENANT_KEYS` | Extra `tenant[/role]=key` pairs | unset |
| `STEALTHTAP_BIND` | Address the TLS proxy publishes on | `127.0.0.1` |
| `STEALTHTAP_HOST` | Hostname the proxy serves | `localhost` |
| `STEALTHTAP_TLS` | `internal` (default, local CA) or an e-mail address (public Let's Encrypt certificate) | `internal` |
| `STEALTHTAP_PUBLIC_API` / `STEALTHTAP_CORS_ORIGINS` | Dashboard's API base / allowed origins when serving a LAN or the internet | loopback defaults |
| `STEALTHTAP_RATE_LIMIT_PER_MIN` | Per-tenant API request rate limit | `1200` |
| `STEALTHTAP_TENANT_MAX_ANALYSES` | Per-tenant concurrent analysis-job cap | `3` |
| `STEALTHTAP_REQUIRE_MFA_ROLES` | Comma-separated roles that must have two-factor enabled to log in | unset |
| `CAPTURE_IFACE`, `CAPTURE_BPF` | Interface and BPF filter for the Docker-profile `sensor` service | `eth0`, `ip or ip6` |
| `BACKUP_INTERVAL_HOURS`, `BACKUP_KEEP` | Backup schedule | `24`, `14` |
| `ML_FLOW_STANDALONE_CONFIDENCE`, `ML_MODBUS_STANDALONE_CONFIDENCE` | Threshold at which the flow/Modbus ML models may alert without rule corroboration | effectively "never" — see [`TECHNICAL.md`](TECHNICAL.md) |

## Post-install checklist

1. `python scripts/system_check.py` reports 0 FAIL.
2. `https://localhost/` loads and asks for a sign-in (or `http://127.0.0.1:8100/health` for the bare service).
3. A test upload (`samples/simulated_attack_traffic.pcap`) through the dashboard produces alerts.
4. If running the live sensor: `GET /capture/status` shows `kernel_drop: 0` after a minute of real traffic.
5. If you set up auto-restart: reboot once and run `scripts\verify_after_reboot.ps1`.
6. Read [`docs/SITE_ONBOARDING.md`](SITE_ONBOARDING.md) before trusting alerts on a **new** network — every site needs its
   own short calibration pass.

## Uninstall / teardown

```bash
docker compose down -v          # stops everything and removes the named volumes (alerts, backups, captures)
```
Remove the Windows sensor task with `Unregister-ScheduledTask StealthTapSensor -Confirm:$false` (elevated), or
`sudo systemctl disable --now stealthtap-sensor` on Linux.
