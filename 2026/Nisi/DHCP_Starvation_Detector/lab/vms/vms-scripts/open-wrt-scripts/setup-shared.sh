#!/bin/sh

# Configure the shared/LAN interface with a static IP address.
# To be used to enable the shared LAN as a test network.
# Unlike the shared.sh scripts, this one is persistent and only needs to be run once after VM creation.

# Use args or defaults if not provided.
NETMASK="${1:-255.255.255.0}"
STATIC_IP="${2:-192.168.42.4}"

uci set network.lan.ipaddr="$STATIC_IP"
uci set network.lan.netmask="$NETMASK"
uci commit network

/etc/init.d/network restart
