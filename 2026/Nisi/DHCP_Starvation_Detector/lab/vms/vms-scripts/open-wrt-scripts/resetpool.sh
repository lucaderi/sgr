#!/bin/sh

# Reset DHCP leases and disable whitelist-only mitigation mode.

# Remove host entries created by the NETCONF whitelist handler.
uci show dhcp 2>/dev/null |
    sed -n "s/^dhcp\.@host\[\([0-9][0-9]*\)\]\.name='dhcp-starvation-.*/\1/p" |
    sort -rn |
    while read -r idx; do
        uci delete "dhcp.@host[$idx]" 2>/dev/null || true
    done

uci set dhcp.lan.dynamicdhcp='1'
uci -q del_list dhcp.@dnsmasq[0].addnhosts='/dev/null' 2>/dev/null || true
uci -q delete dhcp.@dnsmasq[0].dhcpscript 2>/dev/null || true
uci commit dhcp

sed -i '/^dhcp-ignore=tag:!known$/d' /etc/dnsmasq.conf 2>/dev/null || true

# Get and truncate the lease file, then restart dnsmasq to apply changes.
LEASEFILE="$(uci -q get dhcp.@dnsmasq[0].leasefile)"
: > "$LEASEFILE"

/etc/init.d/dnsmasq restart
