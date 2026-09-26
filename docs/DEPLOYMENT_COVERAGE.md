# Seeing the whole network — where to place the sensor

A passive sensor can only inspect traffic that physically reaches its interface. StealthTap reports what it
actually sees (`/capture/coverage`, the *Hosts* page banner) instead of assuming.

| Placement | Sees | How |
|---|---|---|
| **Switch mirror / SPAN port** | every host on the mirrored ports/VLANs | configure the switch to mirror the uplink (or all ports) to the sensor's NIC; capture with promiscuous mode (default) and a BPF such as `ip or ip6 or arp` |
| **Network TAP** (passive or aggregating) | everything crossing the tapped link | put the TAP inline on the uplink/gateway link; connect its monitor port(s) to the sensor. Use a NIC per direction or an aggregating TAP |
| **Gateway / router host** | all routed traffic of the segments behind it | run the sensor on the gateway (Linux router/bridge), or on a Windows PC sharing its connection (*Mobile Hotspot* / ICS): every client's traffic traverses that PC's interfaces |
| **Linux bridge in front of a segment** | traffic between the segment and the rest | `ip link add br0 type bridge`, enslave both NICs, capture on `br0` |
| **Wi-Fi/Ethernet client (no mirror)** | this machine's traffic + broadcast/multicast/ARP of the segment | nothing to configure — visibility will read *own-traffic-only* |

Notes
* Mirror-port oversubscription drops packets on the switch, not in the sensor — compare *kernel drops* with the switch counters.
* Encrypted traffic (TLS, SignAndEncrypt OPC UA) is classified by metadata (SNI, JA4, sizes, timing), not decrypted.
* On Windows with Npcap in *Administrators only* mode the sensor must run elevated (`scripts/start_sensor.ps1`).
* `POST /network/discover` (ARP sweep of the local /24) lists devices that exist but send nothing the sensor can see;
  pass them to `/capture/coverage?known=ip,ip` to quantify the blind spot.
