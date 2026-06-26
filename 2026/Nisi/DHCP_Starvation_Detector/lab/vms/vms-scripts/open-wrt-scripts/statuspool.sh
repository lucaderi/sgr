#!/bin/sh

# Get the number of used and available DHCP leases on the LAN interface.

LEASEFILE="$(uci -q get dhcp.@dnsmasq[0].leasefile)"
LIMIT="$(uci -q get dhcp.lan.limit)"
USED=0

if [ -f "$LEASEFILE" ]; then
    USED="$(wc -l < "$LEASEFILE")"
fi

echo "Used: $USED / $LIMIT - Available: $((LIMIT - USED))"
