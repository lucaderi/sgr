#!/bin/sh

# Stop DHCP client, remove leases, flush IP addresses, and restart DHCP client to get a new IP address on the specified interface.

# Use arg or default to ens160 if not provided.
IFACE="${1:-ens160}"
DHCPCD_TIMEOUT="${DHCPGET_DHCPCD_TIMEOUT_SECS:-}"

# Check if running as root.
if [ "$(id -u)" -ne 0 ]; then
    echo "usage: sudo $0 [network_interface]" >&2
    exit 1
fi

# Stop DHCP client and release lease.
/sbin/dhcpcd -k "$IFACE"
pkill -9 dhcpcd
rm -f /var/lib/dhcpcd/*.lease /var/lib/dhcpcd/"$IFACE".*

# Flush existing IP addresses on the interface, only for global scope to avoid removing link-local addresses.
ip addr flush dev "$IFACE" scope global

# Restart DHCP client to obtain a new IP address.
if [ -n "$DHCPCD_TIMEOUT" ]; then
    /sbin/dhcpcd -4 -1 -L -t "$DHCPCD_TIMEOUT" "$IFACE"
else
    /sbin/dhcpcd -4 -1 -L "$IFACE"
fi

# Show the new IP address assigned to the interface.
ip -4 addr show dev "$IFACE"
