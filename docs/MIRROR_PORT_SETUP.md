# Mirror Port, Network TAP, and Data-Diode Configuration

How to feed StealthTap traffic the way the problem statement's monitoring enclave is meant to receive it: a **one-directional
copy** of a gateway or peering link, with no physical or protocol-level path back into the production network. This document
covers the switch/TAP side of that boundary; [`LIVE_CAPTURE_DEPLOYMENT.md`](LIVE_CAPTURE_DEPLOYMENT.md) covers how the sensor
itself is hardened once traffic reaches it, and [`DEPLOYMENT_COVERAGE.md`](DEPLOYMENT_COVERAGE.md) covers how to measure what
a given placement actually lets the sensor see.

## Contents
- [Why the tap point matters](#why-the-tap-point-matters)
- [Choosing a topology](#choosing-a-topology)
- [Switch mirror/SPAN configuration by vendor](#switch-mirrorspan-configuration-by-vendor)
- [Remote SPAN (RSPAN/ERSPAN)](#remote-span-rspanerspan)
- [Passive network TAPs and hardware data diodes](#passive-network-taps-and-hardware-data-diodes)
- [Hardening the capture host as a one-directional receiver](#hardening-the-capture-host-as-a-one-directional-receiver)
- [Verifying the deployment is genuinely one-directional](#verifying-the-deployment-is-genuinely-one-directional)
- [Sizing the tap for the traffic rate](#sizing-the-tap-for-the-traffic-rate)

## Why the tap point matters

The problem statement's background is explicit: the monitoring enclave sees everything crossing the link but has **no
physical or protocol-level path back into the production network** — by design, so a compromised sensor can never become a
pivot into the network it watches. That property is set by *where and how* traffic is copied to the sensor, before a single
line of detection code runs. Getting the tap configuration right is as much a part of "stealth" as the sensor never sending
a packet.

## Choosing a topology

| Topology | Directionality guarantee | Typical use |
|---|---|---|
| Switch mirror / SPAN port | Logical — the switch is configured not to accept traffic from the mirror destination port, but the port is physically capable of transmitting | Fastest to deploy on existing infrastructure; sufficient for most enclave deployments |
| Passive (aggregating) network TAP | Physical — a TAP splits the optical or electrical signal onto separate monitor ports; the monitor side carries no return path in the cabling itself | Preferred when the traffic source and the enclave boundary must be provably separate hardware |
| Hardware data diode / one-strand fiber TAP | Physical and absolute — the monitor port's transmit fiber is disconnected or the diode hardware physically cannot pass light in the return direction | Matches the problem statement's own example ("hardware data diodes") for the highest-assurance deployments |
| Gateway/router host running the sensor in-process | Logical, via host network isolation only | Convenient for a pilot; weaker guarantee than a dedicated tap — the host that captures also routes production traffic |

A mirror/SPAN port is adequate for the large majority of deployments and is what the rest of this document configures in
detail. Where the strongest guarantee is required, a passive TAP or a true one-directional fiber connection removes the
question entirely at the hardware layer.

## Switch mirror/SPAN configuration by vendor

In every case: mirror the **uplink or trunk port** (or the specific VLAN(s) of interest) to the port the sensor's capture
NIC is connected to. Mirroring the uplink, not individual access ports, is what gives visibility into everything crossing
the gateway, matching the problem statement's "gateway and peering links" framing.

### Cisco IOS / IOS-XE
```
enable
configure terminal
monitor session 1 source interface GigabitEthernet1/0/1          ! the uplink to mirror
monitor session 1 destination interface GigabitEthernet1/0/24    ! the sensor's NIC
end
show monitor session 1
```
Mirror an entire VLAN instead of one interface:
```
monitor session 1 source vlan 10
```

### Cisco NX-OS (Nexus)
```
configure terminal
monitor session 1
  source interface Ethernet1/1
  destination interface Ethernet1/48
  no shut
end
show monitor session 1
```

### Juniper Junos
```
set forwarding-options analyzer STEALTHTAP input ingress interface ge-0/0/1.0
set forwarding-options analyzer STEALTHTAP input egress interface ge-0/0/1.0
set forwarding-options analyzer STEALTHTAP output interface ge-0/0/24.0
commit
```

### Arista EOS
```
configure
monitor session STEALTHTAP source Ethernet1
monitor session STEALTHTAP destination Ethernet48
end
show monitor session STEALTHTAP
```

### HPE / Aruba (ArubaOS-Switch)
```
mirror-port a24
interface a1 monitor
write memory
```

### Generic Linux bridge or Open vSwitch (lab and virtualized environments)
```bash
# Linux bridge, using tc mirred to copy ingress traffic on br0 to a monitor interface
tc qdisc add dev br0 handle ffff: ingress
tc filter add dev br0 parent ffff: matchall action mirred egress mirror dev mon0

# Open vSwitch equivalent
ovs-vsctl -- set Bridge br0 mirrors=@m \
  -- --id=@m create Mirror name=stealthtap select-all=true output-port=@out \
  -- --id=@out get Port mon0
```

Every vendor's mirror/SPAN feature is a **read-only copy**: the destination port receives frames but the switch does not
forward frames arriving on it back into the production VLANs. Confirm this with the vendor's own documentation for the
specific platform and software version in use, since default behavior can vary by hardware generation.

## Remote SPAN (RSPAN/ERSPAN)

When the switch carrying the traffic of interest is not co-located with the monitoring enclave, RSPAN (a dedicated VLAN
carried over the existing switch fabric) or ERSPAN (GRE-encapsulated, routable) extend a mirror across the network instead
of a single cable run.

StealthTap's native capture path expects standard Ethernet-framed input at the capture NIC (see
[`TECHNICAL.md`](TECHNICAL.md#os-level-capture-windows-and-linux-apis-used)). For RSPAN this requires no extra step — the
traffic arrives as ordinary Ethernet frames on the RSPAN VLAN. For ERSPAN, terminate the GRE encapsulation before the
sensor's NIC — either on the destination switch itself (most platforms de-encapsulate ERSPAN automatically at the
configured destination) or with a network packet broker sitting between the ERSPAN destination and the sensor, so the
sensor's NIC always receives de-encapsulated, standard Ethernet frames.

## Passive network TAPs and hardware data diodes

A dedicated TAP appliance sits inline on the link being monitored and produces one or two separate monitor ports carrying a
copy of each direction of traffic — the link itself is never interrupted, and the monitor ports have no path back onto the
production cabling.

- **Copper TAPs** split each direction of a full-duplex link onto its own monitor port; feed both monitor ports into
  separate NICs on the sensor (or into an aggregating TAP/packet broker that combines them onto one NIC, matching what the
  sensor expects on a single interface).
- **Optical (fiber) TAPs** split a fraction of the optical signal onto a monitor fiber using a passive splitter — no power,
  no active component, and nothing on the monitor side can transmit back onto the production fiber, since a passive splitter
  has no receive path in that direction.
- **A one-directional hardware guarantee**, matching the problem statement's own "hardware data diode" example, is achieved
  by physically disconnecting or never connecting the transmit strand into the monitor port — a fiber TAP or dedicated data
  diode appliance where the enclave-side connector has no fiber, or no transceiver, in the transmit position. At that point
  the property is enforced by physics, not configuration.

## Hardening the capture host as a one-directional receiver

The switch or TAP configuration establishes that the *link* is one-directional. The capture host must not undo that by
giving the capture interface an identity or a reason to transmit.

### Linux
```bash
sudo ip link set eth1 up
sudo ip addr flush dev eth1                          # no IP address: nothing to route to
sudo ip link set eth1 promisc on                      # receive every frame, not just this host's own
sudo sysctl -w net.ipv6.conf.eth1.disable_ipv6=1
sudo ethtool -K eth1 gro off lro off tso off gso off   # disable NIC offload features that can merge/alter captured frames
```
For the strongest isolation, run the capture interface in its own network namespace with no route table at all:
```bash
sudo MIRROR_IF=eth1 scripts/setup_netns.sh up
sudo scripts/setup_netns.sh status     # confirms: no addresses, empty route table
```

### Windows
```powershell
# Unbind IPv4/IPv6 from the capture adapter (Adapter Properties, or PowerShell):
Disable-NetAdapterBinding -Name "CaptureNIC" -ComponentID ms_tcpip, ms_tcpip6
Disable-NetAdapterLso -Name "CaptureNIC"                 # large send offload off
Disable-NetAdapterChecksumOffload -Name "CaptureNIC"
Set-NetAdapterAdvancedProperty -Name "CaptureNIC" -DisplayName "Receive Side Scaling" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
```
Npcap already places the adapter into promiscuous mode for capture and, with "WinPcap API-compatible Mode" enabled during
installation, never transmits on the capture path.

### The compose `sensor` service

When deployed via `docker compose --profile tap up -d sensor`, the container itself enforces the same properties in
software: `cap_drop: ALL` with only `NET_RAW`/`NET_ADMIN` added, `no-new-privileges`, a read-only root filesystem, no
published ports (the control API binds to `127.0.0.1` only), and alerts leave exclusively via an outbound
`POST .../alerts/ingest` call — never back toward the monitored link. See
[`LIVE_CAPTURE_DEPLOYMENT.md`](LIVE_CAPTURE_DEPLOYMENT.md) for the full property table.

## Verifying the deployment is genuinely one-directional

After wiring the tap and starting capture, confirm the capture interface never transmits:

```bash
# Linux: TX counters on the capture interface should stay at 0 indefinitely
ip -s link show eth1 | grep -A2 TX
```
```powershell
# Windows
Get-NetAdapterStatistics -Name "CaptureNIC" | Select-Object SentBytes, SentUnicastPackets
```

Both should report zero transmitted traffic for the lifetime of the capture. Combined with `GET /capture/coverage` (see
[`DEPLOYMENT_COVERAGE.md`](DEPLOYMENT_COVERAGE.md)) to confirm the expected hosts are actually visible from this tap point,
this is the complete verification: the link is one-directional at the hardware/switch layer, the capture host adds no
transmit path of its own, and the resulting visibility matches what the deployment intends to monitor.

## Sizing the tap for the traffic rate

Mirror-port oversubscription drops packets **on the switch**, before they ever reach the sensor — this shows up as a gap
between the switch's own mirror-port counters and StealthTap's `kernel_drop_total` staying at zero, which means the switch,
not the sensor, is the bottleneck. A SPAN destination port must be provisioned at least as fast as the sum of monitored
traffic (for example, mirroring two 1 Gbit/s access ports to one 1 Gbit/s SPAN destination will drop under sustained load
from both sources at once); a dedicated TAP or packet broker avoids this by design, since its monitor ports are sized for
the link being tapped rather than shared with other switch traffic. The sensor's own measured throughput —
~950,000 packets/second (6.0 Gbit/s) sustained, up to 1.58M pps with capture sharding — is documented in
[`TECHNICAL.md`](TECHNICAL.md#throughput-and-latency--measured-not-asserted); provision the tap/SPAN destination at or
above the traffic rate the deployment expects, not the sensor's own ceiling.
