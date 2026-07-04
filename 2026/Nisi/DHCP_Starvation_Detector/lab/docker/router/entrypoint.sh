#!/bin/bash
set -e

DNSMASQ_PID=/var/run/dnsmasq.pid
DHCPD_PID=/run/dhcpd.pid
DHCP_TYPE=${DHCP_TYPE:-dnsmasq}
DHCP_IFACE=${DHCP_IFACE:-eth0}

start_dnsmasq() {
    ln -sf /usr/local/bin/netconf-handler-dnsmasq /usr/local/bin/netconf-handler
    rm -f "$DNSMASQ_PID"
    dnsmasq --pid-file="$DNSMASQ_PID"
}

start_isc() {
    ln -sf /usr/local/bin/netconf-handler-isc /usr/local/bin/netconf-handler
    mkdir -p /var/lib/dhcp /run
    touch /etc/dhcp/dhcpd.whitelist-policy.conf
    touch /etc/dhcp/dhcpd.whitelist-hosts.conf
    touch /var/lib/dhcp/dhcpd.leases
    rm -f "$DHCPD_PID"
    dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf -lf /var/lib/dhcp/dhcpd.leases -pf "$DHCPD_PID" "$DHCP_IFACE"
}

ssh-keygen -A 2>/dev/null
/usr/sbin/sshd

case "$DHCP_TYPE" in
    dnsmasq)
        start_dnsmasq
        ;;
    isc)
        start_isc
        ;;
    *)
        echo "unsupported DHCP_TYPE=$DHCP_TYPE" >&2
        exit 2
        ;;
esac

while true; do
    sleep 3600 &
    wait $!
done
