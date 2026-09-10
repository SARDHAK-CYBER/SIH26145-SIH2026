#!/usr/bin/env bash
#
# StealthTap capture-zone network isolation.
#
# Implements PS constraint (a) -- read-only ingest, no return path -- at
# the operating-system level:
#
#   * network namespace "capture": holds ONLY the mirror/tap interface.
#     It gets NO IP address, NO default route, ARP disabled, promiscuous
#     mode on. Zeek runs inside this namespace. From here there is no
#     routable path to anything -- a compromised Zeek cannot reach the
#     production network, the broker, or the SOC.
#
#   * network namespace "soc": normal addressing, where the streaming
#     engine / relay / storage run (or, in the docker-compose setup, the
#     default bridge network plays this role).
#
#   * NO veth pair is created between "capture" and "soc". The only
#     sanctioned crossing is the one-way Unix-domain-socket relay at
#     $RELAY_SOCKET, whose real security control is Alert-schema
#     validation (see src/relay/relay.py), not the transport.
#
# This script is idempotent -- safe to re-run. Requires root (ip netns).
#
# Usage:
#   sudo MIRROR_IF=eth1 scripts/setup_netns.sh up
#   sudo scripts/setup_netns.sh down
#   sudo scripts/setup_netns.sh status
#
# Then launch Zeek attached to the capture namespace, e.g.:
#   sudo ip netns exec capture zeek -i "$MIRROR_IF" zeek/local.zeek
# or, with Docker:
#   docker run --network=ns:/var/run/netns/capture \
#     --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -v stealthtap_zeek_logs:/zeek-logs stealthtap-zeek

set -euo pipefail

CAPTURE_NS="${CAPTURE_NS:-capture}"
SOC_NS="${SOC_NS:-soc}"
MIRROR_IF="${MIRROR_IF:-eth1}"
RELAY_SOCKET_DIR="${RELAY_SOCKET_DIR:-/var/run/stealthtap}"
NETNS_DIR="/var/run/netns"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "error: must run as root (needs 'ip netns')." >&2
        exit 1
    fi
}

cmd_up() {
    require_root
    mkdir -p "$NETNS_DIR"

    # --- capture namespace: the air-gapped sniffing zone ---
    if ! ip netns list | grep -qw "$CAPTURE_NS"; then
        ip netns add "$CAPTURE_NS"
        echo "[+] created namespace '$CAPTURE_NS'"
    else
        echo "[=] namespace '$CAPTURE_NS' already exists"
    fi

    # loopback only -- deliberately no other addressable interface
    ip netns exec "$CAPTURE_NS" ip link set lo up

    # Move the mirror interface into the capture namespace, if present.
    if ip link show "$MIRROR_IF" >/dev/null 2>&1; then
        ip link set "$MIRROR_IF" netns "$CAPTURE_NS"
        # No IP, no ARP, promiscuous -- pure passive receive.
        ip netns exec "$CAPTURE_NS" ip link set "$MIRROR_IF" arp off
        ip netns exec "$CAPTURE_NS" ip link set "$MIRROR_IF" promisc on
        ip netns exec "$CAPTURE_NS" ip link set "$MIRROR_IF" up
        ip netns exec "$CAPTURE_NS" ip addr flush dev "$MIRROR_IF" || true
        echo "[+] '$MIRROR_IF' moved into '$CAPTURE_NS' (no IP, arp off, promisc on)"
    else
        echo "[!] mirror interface '$MIRROR_IF' not found on host --"
        echo "    set MIRROR_IF=<iface> and re-run once the SPAN/tap NIC is attached."
    fi

    # Explicitly assert: no default route inside capture.
    ip netns exec "$CAPTURE_NS" ip route flush table main 2>/dev/null || true

    # --- soc namespace (optional; docker-compose's bridge covers this) ---
    if [ "${WITH_SOC_NS:-0}" = "1" ]; then
        if ! ip netns list | grep -qw "$SOC_NS"; then
            ip netns add "$SOC_NS"
            ip netns exec "$SOC_NS" ip link set lo up
            echo "[+] created namespace '$SOC_NS'"
        fi
    fi

    # --- the ONLY sanctioned crossing: the one-way relay socket dir ---
    mkdir -p "$RELAY_SOCKET_DIR"
    chmod 0755 "$RELAY_SOCKET_DIR"
    echo "[+] relay socket dir ready at $RELAY_SOCKET_DIR (bind-mount this into"
    echo "    both the streaming-engine and relay containers)"

    echo
    echo "[i] NO veth pair links '$CAPTURE_NS' to anything. Verify:"
    echo "      ip netns exec $CAPTURE_NS ip -o link"
    echo "      ip netns exec $CAPTURE_NS ip route        # expect: nothing"
}

cmd_down() {
    require_root
    # Return the mirror interface to the host before deleting the ns, so
    # a re-run can find it again.
    if ip netns list 2>/dev/null | grep -qw "$CAPTURE_NS"; then
        if ip netns exec "$CAPTURE_NS" ip link show "$MIRROR_IF" >/dev/null 2>&1; then
            ip netns exec "$CAPTURE_NS" ip link set "$MIRROR_IF" promisc off || true
            ip netns exec "$CAPTURE_NS" ip link set "$MIRROR_IF" netns 1 || true
            echo "[+] '$MIRROR_IF' returned to host namespace"
        fi
        ip netns del "$CAPTURE_NS"
        echo "[+] deleted namespace '$CAPTURE_NS'"
    fi
    if ip netns list 2>/dev/null | grep -qw "$SOC_NS"; then
        ip netns del "$SOC_NS"
        echo "[+] deleted namespace '$SOC_NS'"
    fi
}

cmd_status() {
    echo "== namespaces =="
    ip netns list || true
    echo
    if ip netns list 2>/dev/null | grep -qw "$CAPTURE_NS"; then
        echo "== $CAPTURE_NS links =="
        ip netns exec "$CAPTURE_NS" ip -o link || true
        echo "== $CAPTURE_NS routes (expect empty) =="
        ip netns exec "$CAPTURE_NS" ip route || true
    fi
    echo
    echo "== relay socket dir =="
    ls -ld "$RELAY_SOCKET_DIR" 2>/dev/null || echo "(absent)"
}

case "${1:-up}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    *) echo "usage: $0 {up|down|status}" >&2; exit 1 ;;
esac
