#!/usr/bin/env bash
set -euo pipefail

# Demo-mode traffic injection: feeds a PCAP into the SAME capture
# namespace/code path used in production, via a veth pair. This veth
# pair connects only the traffic generator to the capture namespace --
# it is unrelated to, and does not bridge, the capture<->soc isolation
# boundary set up by setup_netns.sh. A veth pair IS bidirectional at
# layer 2; that's fine here, it is just how synthetic packets get in.
#
# Usage: sudo ./setup_pcap_replay.sh
# Then:  sudo tcpreplay --intf1=veth-gen --multiplier=1.0 samples/c2_beaconing.pcap

if [[ $EUID -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

ip link add veth-gen type veth peer name veth-cap 2>/dev/null \
  || echo "[i] veth pair already exists"
ip link set veth-gen up
ip link set veth-cap netns capture
ip netns exec capture ip link set veth-cap up promisc on

echo "[+] veth-cap is live inside the capture namespace."
echo "[+] Point Zeek/streaming_engine.py at --interface veth-cap."
echo "[+] Replay, matching timing to what the engine under test needs:"
echo "      real-time (required for ENG-02 / Slowloris):"
echo "        sudo tcpreplay --intf1=veth-gen --multiplier=1.0 samples/c2_beaconing.pcap"
echo "      timing-insensitive engines:"
echo "        sudo tcpreplay --intf1=veth-gen --topspeed samples/syn_flood.pcap"
