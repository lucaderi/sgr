#!/bin/sh

# Enable NAT after adding a new NAT network adapter to the VM in the VMWare Fusion settings.
# To be used to enable NAT to download needed packages.

# Use args or defaults if not provided.
IFACE="${1:-eth1}"
# This on MacOS with VMWare Fusion are in /Library/Preferences/VMware Fusion/vmnet8/nat.conf
STATIC_IP="${2:-172.16.2.11/24}"
GATEWAY_IP="${3:-172.16.2.2}"

# Check if running as root.
if [ "$(id -u)" -ne 0 ]; then
    echo "usage: sudo $0 [network_interface] [static_ip/cidr] [gateway_ip]" >&2
    exit 1
fi

# Ensure a basic DNS resolver is available.
if [ ! -f /etc/resolv.conf ]; then
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
elif ! grep -q "8\\.8\\.8\\.8" /etc/resolv.conf; then
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
fi

# Flush existing IP addresses on the interface, only for global scope to avoid removing link-local addresses.
ip addr flush dev "$IFACE" scope global

# Add static IP address and bring the interface up.
ip addr add "$STATIC_IP" dev "$IFACE"

# Bring the interface up.
ip link set "$IFACE" up

# Add default route via the NAT gateway.
ip route add default via "$GATEWAY_IP" dev "$IFACE"
