#!/bin/sh

# Configure the shared/LAN interface with a static IP address.
# To be used to enable the shared LAN as a test network.

# Use args or defaults if not provided.
IFACE="${1:-eth0}"
STATIC_IP="${2:-192.168.42.5/24}"

# Check if running as root.
if [ "$(id -u)" -ne 0 ]; then
    echo "usage: sudo $0 [network_interface] [static_ip/cidr]" >&2
    exit 1
fi

# Flush existing IP addresses on the interface, only for global scope to avoid removing link-local addresses.
ip addr flush dev "$IFACE" scope global

# Add static IP address.
ip addr add "$STATIC_IP" dev "$IFACE"

# Bring the interface up.
ip link set "$IFACE" up

# SSH on Kali must be enabled manually.
systemctl enable ssh
systemctl start ssh
