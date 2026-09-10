# StealthTap — Live Capture & Tap Deployment

Two ways to run detection: **upload a PCAP** (offline, full Zeek + Suricata
+ YARA + engines + ML) or **tap a live NIC** (in-process kernel capture +
the same ENG01–13 engines + the same ONNX models). Both land alerts in the
same PostgreSQL `alerts` table, so the dashboard shows one unified history.

```
                         ┌─────────────── UPLOAD PATH ───────────────┐
  browser ── /analyze/pcap ─▶ api ─▶ zeek-batch ∥ suricata-batch ─▶ engines+ML ─▶ Postgres
                         └───────────────────────────────────────────┘
                         ┌──────────────── LIVE PATH ────────────────┐
  NIC ─▶ kernel ring (AF_PACKET mmap+FANOUT / Npcap) ─▶ FlowAssembler ─▶ engines+ML
                                    │                                        │
                              in-kernel BPF                      /alerts/ingest ─▶ Postgres
                         └───────────────────────────────────────────┘
```

---

## 1. Run the live capture locally (dev, no Docker)

```bash
# what can this host do?
python -m src.capture.live_agent caps
python -m src.capture.live_agent list                 # the Wireshark-style picker

# capture + analyse, alerts to the console
python -m src.capture.live_agent run --iface "eth0" --bpf "ip or ip6"

# replay a pcap THROUGH the live pipeline (no NIC needed - demos/CI)
python -m src.capture.live_agent run --pcap samples/simulated_attack_traffic.pcap

# control + SSE server for the dashboard's "Live Capture" tab
python -m src.capture.live_agent serve --port 8100
```

Privileges: Linux needs root or `setcap cap_net_raw,cap_net_admin+eip` on
the python binary. Windows needs Npcap (npcap.com) installed with
"WinPcap API-compatible mode".

The dashboard's **Live Capture** tab talks to `VITE_LIVE_API_BASE`
(defaults to the main API origin). Point it at the sensor:
`VITE_LIVE_API_BASE=http://<sensor-host>:8100`.

---

## 2. Deploy the stealth tap (Docker, on the monitoring host)

The `sensor` service is behind the `tap` compose profile.

```bash
# .env additions
CAPTURE_IFACE=eth1                 # the mirror / SPAN / diode-fed port
CAPTURE_BPF=ip or ip6             # compiled INTO the kernel
STEALTHTAP_API_URL=http://127.0.0.1:8000    # where to POST alerts
SENSOR_REDIS_URL=redis://127.0.0.1:6379/0   # optional; enables ENG-02/06 cross-flow state
LIVE_HIGHSPEED_PPS=50000
LIVE_HIGHSPEED_MBPS=200

# bring up the core stack, then the sensor
docker compose up -d
docker compose --profile tap up -d --build sensor
docker compose logs -f sensor
```

### Why it's "stealth" / read-only-safe

Enforced by the `sensor` service definition:

| Property | How |
|---|---|
| No routable identity on the capture port | `CAPTURE_IFACE` carries **no IP** — see §3. Capture is receive-only; scapy/AF_PACKET never transmits. |
| Minimal privilege | `cap_drop: ALL`, then only `NET_RAW` + `NET_ADMIN`; `no-new-privileges` |
| No inbound surface | **no `ports:`** — the control/SSE API binds `127.0.0.1:8100` only |
| Immutable | `read_only` root filesystem, `tmpfs:/tmp` |
| One-way data out | alerts leave only via `POST STEALTHTAP_API_URL/alerts/ingest` (batched, drop-on-fail) — never back toward the monitored link |
| No decryption | JA4 from the ClientHello, DNS names, OT function codes — cleartext protocol metadata only, matching PS constraint (b) |

### Full air-gap (optional, strongest)

Put Zeek/AF_PACKET's capture NIC in an IP-less namespace so a compromised
sensor still cannot reach anything:

```bash
sudo MIRROR_IF=eth1 scripts/setup_netns.sh up      # creates ns 'capture', no IP, ARP off, promisc
sudo scripts/setup_netns.sh status                  # verify: no addresses, empty route table
# then attach the sensor container to it:
#   docker run --network=ns:/var/run/netns/capture --cap-drop=ALL \
#     --cap-add=NET_RAW --cap-add=NET_ADMIN ... stealthtap-sensor \
#     run --iface eth1 --json
```

---

## 3. Prepare the capture NIC (no address, promiscuous)

```bash
sudo ip link set eth1 up
sudo ip addr flush dev eth1
sudo ip link set eth1 promisc on
sudo sysctl -w net.ipv6.conf.eth1.disable_ipv6=1     # optional
```

A hardware data diode or a switch SPAN/mirror port feeding `eth1` is the
intended source. The sensor never needs the NIC to have an address.

---

## 4. High-speed streams — throughput & latency

The sensor is built for a fast link and **reports the numbers PS
constraint (d) asks for**, live, in `GET /capture/status`:

| Field | Meaning |
|---|---|
| `throughput.pps` / `.mbps` / `.peak_*` | current + peak packet & bit rate |
| `throughput.kernel_drop_total` / `_delta` | frames the **kernel ring** dropped because user space fell behind — the ground-truth "can't keep up" signal (`pcap_stats` / `PACKET_STATISTICS`) |
| `dropped` | frames the userspace queue shed (bounded-latency backpressure: newest kept, oldest dropped) |
| `detection_latency.p50_ms/p95_ms/p99_ms/max_ms` | packet-arrival → alert-emission, per alert, for immediately-detectable classes (DGA, tunnelling, JA4, OT commands, HTTP, Kerberos) |
| `throughput.high_speed` + `high_speed_flags` | set when pps/Mbps cross `LIVE_HIGHSPEED_*` **or** the kernel starts dropping |

What keeps latency bounded and throughput high:

- **In-kernel BPF** (`CAPTURE_BPF`) — non-matching frames never cross to user space.
- **Kernel ring buffer** — AF_PACKET `PACKET_RX_RING` (sized from `--buffer-mb`, split across `PACKET_FANOUT` workers) on Linux; `pcap_setbuff` on Npcap.
- **`PACKET_FANOUT`** — N worker sockets load-balance one interface across CPU cores (Linux).
- **Bounded userspace queue** — drops oldest rather than growing unboundedly, so alert latency can't drift.
- **Near-real-time flow scoring** — active flows are re-scored every `LIVE_SNAPSHOT_INTERVAL` s (default 2 s) for the rate/fan-out engines; per-flow byte-ratio and cross-flow periodicity run when the flow completes.
- **Batched ONNX** — one inference call per model over a batch of flows, never per-flow.

### Measuring it

```bash
# replay a real capture at wire speed and read the reported numbers
python -m src.capture.live_agent run --pcap <big.pcap> --realtime --status-every 2
# or, against a running sensor:
watch -n1 'curl -s localhost:8100/capture/status | jq "{throughput,detection_latency,active_flows,dropped}"'
```

If `kernel_drop_total` climbs: raise `--buffer-mb`, tighten `CAPTURE_BPF`,
or add cores (FANOUT scales with them).

---

## 5. Accuracy vs. the problem statement

Same engines and models as the PCAP path, so the evaluated numbers carry
over (see `docs/PRD.md` §8 and `models/MANIFEST.json`):

| PS threat class | Live detector | Basis |
|---|---|---|
| Volumetric / protocol DDoS | ENG-01 (rate + source-IP HLL entropy) | rule, verified vs. real flood pcaps |
| C2 beaconing | ENG-02 (inter-arrival CV) | rule |
| DGA / DNS tunnelling | ENG-03: trained `dns` XGBoost (P 0.94 / R 0.88 / ROC-AUC 0.97) + deterministic lexical fallback; mDNS/LLMNR/`.local` filtered | model + rule |
| Malware in encrypted sessions | ENG-04: **real JA4** from the ClientHello vs. FoxIO threat intel | rule, metadata-only |
| Reconnaissance | ENG-05 (fan-out) | rule |
| Data exfiltration | ENG-06 (per-flow + accumulated byte ratio), scored on completed flows | rule |
| OT (Modbus + DNP3 + EtherNet/IP) | ENG-07 dangerous function/service codes | rule, byte-level verified |

Not on the live path (no Zeek/containers in-process): Suricata's 20k
signatures, YARA file scanning, BZAR. Those stay on the upload path — send
a pcap slice through `/analyze/pcap` when you need them.
