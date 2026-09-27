# StealthTap — Status

How this file works: the status block below is regenerated from a real system check by `python scripts/update_priorities.py`
(only the marked region is ever touched). The rest is a hand-maintained, plain summary of what is implemented and measured —
see [`PRD.md`](PRD.md) for the full methodology and history behind every number, and [`TECHNICAL.md`](TECHNICAL.md) for
architecture and internals.

## Automated status

<!-- AUTO-STATUS:BEGIN -->
_Last automated check: **2026-09-27 02:30:46** · PASS 27 · WARN 0 · FAIL 0 · tests 266 · live pipeline 364,825 pps · hybrid recall 83.0% · flow FPR 0.167%_

No FAIL or WARN in the latest run.

Full report: `docs/reports/LATEST.md` (history: `docs/reports/history.csv`)
<!-- AUTO-STATUS:END -->

## What's implemented and measured

**Detection.** 14 rule/statistical engines (DDoS/Slowloris, C2 beaconing, DGA/DNS tunnelling, JA4 malware fingerprinting,
reconnaissance, exfiltration, OT/ICS across 7 protocols, malicious files, HTTP threats, Suricata signatures, Kerberoasting,
BZAR lateral-movement notices, brute force, plain-text service attacks) plus 3 trained ML models and a live-learning,
no-pre-trained-data baseline. 25/25 real attack captures detected in the labelled corpus; out-of-sample confirmation with
real attack tools (nmap NSE, curl, smtplib) against real and isolated-lab targets. Full numbers: `PRD.md` §7, §13, §14;
`TECHNICAL.md`.

**False positives.** Found and fixed on a real live network over a multi-hour continuous run: broadcast/beacon
misclassification, TLS-keepalive Slowloris, OCSP/certificate-infrastructure noise, DDoS-flood over-sensitivity, low-volume
exfiltration over-sensitivity, an OS connectivity-check domain misclassified as a DGA, and SSDP/mDNS device-discovery traffic
misclassified by the unsupervised baseline — each with a regression test, the last one live-reconfirmed after the fix
(1,866 real SSDP + 16,187 real mDNS packets, 0 false alerts). 343 real industrial-control captures from public sources: 1
generic-engine alert in 5,497 flows. A false-positive-triage tool (`scripts/site_calibration.py`) and an operator allowlist
(`config/allowlist.json`) are provided for calibrating a new network — see `SITE_ONBOARDING.md`.

**Throughput.** ~950,000 pps / 6.0 Gbit/s sustained on real traffic through the full native pipeline (15-minute / 127 GB
soak, 0 drops); a 1.76-hour continuous run on a real Wi-Fi link with 0 kernel/record/user-space packet drops and flat memory.
Detection latency p95 0.91 ms. Full methodology: `TECHNICAL.md`.

**Access control and resilience.** API keys, named user accounts with two-factor login (TOTP), roles, audit logging,
per-tenant isolation and rate limits, TLS termination, scheduled backups with a verified restore, an on-disk alert spool for
API/database outages, and an auto-restarting sensor — verified end to end, including through a real reboot of the deployment
machine (sensor and all 13 containers came back automatically, zero manual steps). Two API replicas behind the TLS proxy and
a PostgreSQL hot standby were tested on one host: 235/235 requests succeeded while each replica was stopped in turn; a
database failover drill took 20 seconds. Full detail: `OPERATIONS.md`, `INSTALLATION.md`.

**CI.** Every commit runs Linux + Windows tests, a dashboard build, and a Docker Compose validation
(`.github/workflows/ci.yml`).

## Scope and constraints

A few things are outside what this deployment has been able to exercise directly, because they need infrastructure or time
this environment doesn't have — not because the capability is unbuilt:

- **A 24–72 hour run on a mirrored production link** — the longest continuous real-link run performed is 1.76 hours; the
  mechanism (auto-restart, alert spool, backups) is proven, a multi-day run needs an actual mirror-port/TAP deployment.
- **Linux systemd unit and a public TLS certificate** — both are written and validated at the config level (`systemd-analyze`
  equivalent syntax checks; Caddy's ACME configuration accepts a real e-mail + hostname), but neither was exercised on an
  actual Linux host or a publicly reachable domain in this environment.
- **Single-sign-on (SSO/OIDC)** — not built; the documented route is an OIDC-aware reverse proxy in front of the existing TLS
  termination.
- **High availability across separate machines** — the replica/standby/failover mechanisms were proven on one Docker host;
  nothing here has run on physically separate hosts.
- **Serial industrial fieldbuses** (PROFIBUS, Foundation Fieldbus H1, wired HART, Modbus RTU) are not visible on any Ethernet
  capture by physical definition — they need a protocol gateway, not a software fix, regardless of vendor.
