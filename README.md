# StealthTap

**Passive network threat detection — SIH 2026, Problem Statement 26145 (NTRO), Team XOR.**

StealthTap watches network traffic — a live network card, an uploaded capture file, or a stream of logs — and raises alerts
when it sees something dangerous: a DDoS flood, malware phoning home, a port scan, data quietly leaking out, someone probing
an industrial control system, or an intrusion attempt against a plain web/mail/build service. It never stores the actual
packet contents, only what it needs to explain an alert.

It runs as an ordinary background service on Linux or Windows — not a special executable — so it deploys the same way any
other server software does, in Docker or directly with Python.

## Why it's worth a look

Most security tools like this claim "99% accuracy" without showing their work. This project measured its own numbers against
real attacks and real everyday network traffic — not synthetic test data — and kept fixing what the measurements found wrong,
including on a real live network run over multiple hours, and confirmed the fixes hold after rebooting the machine the
software runs on.

| | |
|---|---|
| **Detects** | 25 of 25 real attack captures tested (Hydra brute force, BlackEnergy, Mirai, UnrealIRCd, distcc/SMTP/Tomcat intrusions, and more) |
| **False alarms** | 1 alert per 8,593 real flows on a live home network, after finding and fixing five separate causes of false alarms |
| **Speed** | ~950,000 packets/second (6.0 Gbit/s) sustained on real traffic through the full pipeline |
| **Survives a reboot** | Verified live: the sensor and the entire service stack came back on their own after rebooting the machine, with zero data loss |

Full numbers and methodology are in [`docs/TECHNICAL.md`](docs/TECHNICAL.md) — nothing here is asserted without a
measurement behind it.

## What it looks for

- **Volumetric attacks** — DDoS floods, Slowloris
- **Malware behaviour** — command-and-control beaconing, DGA domains, DNS tunnelling, encrypted-malware fingerprints
- **Reconnaissance and intrusion** — port scans, brute-force login attempts, Kerberoasting, exploitation of plain-text
  services (SMTP, distcc, Tomcat and similar)
- **Data loss** — unusual outbound data volumes, including slow, low-and-slow exfiltration
- **Industrial control systems** — dangerous commands over Modbus, DNP3, S7, IEC-104, EtherNet/IP, BACnet, OPC UA, PROFINET
- **Anything unusual for *your* network specifically** — a self-learning baseline with no pre-trained data, tuned to what's
  normal on the network it's actually watching

A React dashboard shows live alerts, a Wireshark-style packet inspector, host/flow inventories, and lets you build your own
live charts — no synthetic demo data anywhere in it.

## Get started

```bash
git clone <this repo>
cd stealthtap-ntro
cp .env.example .env             # set a real password and an API key — see docs/INSTALLATION.md
docker compose up -d --build
```

Full setup, including the bare-service (no Docker) path, live-capture sensor setup, TLS, user accounts, and multi-site
deployment: **[`docs/INSTALLATION.md`](docs/INSTALLATION.md)**.

## Documentation

- **[`docs/INSTALLATION.md`](docs/INSTALLATION.md)** — install and deploy, step by step
- **[`docs/TECHNICAL.md`](docs/TECHNICAL.md)** — architecture, detection engines, ML models, OS-level capture internals, and
  every accuracy/speed/latency measurement in full
- [`docs/SITE_ONBOARDING.md`](docs/SITE_ONBOARDING.md) — calibrating false alarms on a new network
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — access control, accounts, backups, and high availability
- [`docs/PRD.md`](docs/PRD.md) — full requirements, methodology, and project history
- [`docs/PRIORITIES.md`](docs/PRIORITIES.md) — living status, auto-refreshed from a real system check
- [`CHANGES.md`](CHANGES.md) — dated change log

## Open source, no paid components

Zeek (BSD), Suricata (GPLv2), YARA (BSD), ICSNPP (BSD-3), XGBoost/scikit-learn/ONNX (Apache-2/BSD), React (MIT). Windows live
capture uses [Npcap](https://npcap.com/), which is free (not open-source) for up to 5 systems and is never bundled or
redistributed by this project.
