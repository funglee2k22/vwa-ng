#!/bin/bash
#
# This script sets up a TUN interface and routes traffic to it.
#

set -euo pipefail

# --- Configuration ---
IFACE="tun0"
INGRESS_NIC="enp1s3"

# --- Helper Functions ---
log() {
    echo "[*] $@"
}

error_exit() {
    echo "[!] ERROR: $@" >&2
    exit 1
}

# Check if we are running as root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "This script must be run with sudo or as root."
fi

# --- Main Functions ---
cleanup() {
    log "Cleaning up TUN interface '$IFACE' and routes..."
    ip link del "$IFACE" 2>/dev/null || true
    tc qdisc del dev ${INGRESS_NIC} clsact
    log "Cleanup complete."
}

setup() {
    log "Setting up TUN interface '$IFACE'..."

    ip tuntap add dev "$IFACE" mode tun user "$(whoami)"

    ip link set dev "$IFACE" up

    tc qdisc add dev ${INGRESS_NIC} clsact
    tc filter add dev ${INGRESS_NIC} ingress prio 1 protocol ip u32 \
        match ip protocol 17 0xff \
        match ip dst 192.168.222.0/24 \
	    action mirred egress redirect dev $IFACE

    echo "Any UDP packet sent to $IFACE will be captured."
}

# --- Script Entrypoint ---
action="${1:-}"

case "$action" in
    setup)
        setup
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "Usage: $0 <setup|cleanup>"
        exit 1
        ;;
esac
