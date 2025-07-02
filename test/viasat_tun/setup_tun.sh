#!/bin/bash
#
# This script sets up a TUN interface and routes traffic to it.
#

set -euo pipefail

# --- Configuration ---
IFACE="tun0"
IP_ADDR="10.10.10.1/24"
# We will intercept traffic destined for this IP address
TARGET_IP="8.8.8.8"

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
    tc qdisc del dev enp8s0 clsact
    log "Cleanup complete."
}

setup() {
    log "Setting up TUN interface '$IFACE'..."

    ip tuntap add dev "$IFACE" mode tun user "$(whoami)"

    ip link set dev "$IFACE" up

    tc qdisc add dev enp8s0 clsact
    tc filter add dev enp8s0 ingress prio 1 protocol ip u32 match ip protocol 17 0xff \
	    action mirred egress mirror dev $IFACE

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
