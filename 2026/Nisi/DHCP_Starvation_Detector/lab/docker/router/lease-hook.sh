#!/bin/sh

# Used only for dnsmasq. By default dnsmasq writes leases in a raw format, this script, called at each lease update keeps an updated readable normalized file.

set -u

TRACK_FILE=/var/lib/misc/dnsmasq.leases
WHITELIST_CONF=/etc/dnsmasq.d/whitelist.conf
LEASE_SECS=43200

action=${1:-}
mac=${2:-}
ip=${3:-}
host=${4:-*}

lower_mac() {
    printf '%s' "$1" | tr 'A-F' 'a-f'
}

# Returns true only if whitelist is enabled.
is_whitelist_only() {
    [ -f "$WHITELIST_CONF" ] &&
        grep -q '^dhcp-ignore=tag:!known$' "$WHITELIST_CONF" 2>/dev/null
}

# Returns true if exist a lease for the given MAC.
is_known_mac() {
    known_mac=$(lower_mac "$1")
    grep -qi "^dhcp-host=${known_mac},set:known" "$WHITELIST_CONF" 2>/dev/null
}

# Remove a lease by MAC or IP.
rewrite_without_lease() {
    remove_mac=$(lower_mac "$1")
    remove_ip=$2
    tmp=$(mktemp "${TRACK_FILE}.XXXXXX") || exit 0

    if [ -f "$TRACK_FILE" ]; then
        awk -v mac="$remove_mac" -v ip="$remove_ip" '
            {
                lease_mac = tolower($2)
                lease_ip = $3
                if ((mac != "" && lease_mac == mac) ||
                    (ip != "" && lease_ip == ip)) {
                    next
                }
                print
            }
        ' "$TRACK_FILE" > "$tmp" || {
            rm -f "$tmp"
            exit 0
        }
    fi

    mv "$tmp" "$TRACK_FILE" 2>/dev/null || rm -f "$tmp"
}

# Update or insert a lease.
upsert_lease() {
    add_mac=$(lower_mac "$1")
    add_ip=$2
    add_host=${3:-*}
    client_id=${DNSMASQ_CLIENT_ID:-*}
    expires=$(( $(date +%s) + LEASE_SECS ))
    tmp=$(mktemp "${TRACK_FILE}.XXXXXX") || exit 0

    if [ -f "$TRACK_FILE" ]; then
        awk -v mac="$add_mac" -v ip="$add_ip" '
            {
                lease_mac = tolower($2)
                lease_ip = $3
                if ((mac != "" && lease_mac == mac) ||
                    (ip != "" && lease_ip == ip)) {
                    next
                }
                print
            }
        ' "$TRACK_FILE" > "$tmp" || {
            rm -f "$tmp"
            exit 0
        }
    fi

    printf '%s %s %s %s %s\n' \
        "$expires" "$add_mac" "$add_ip" "$add_host" "$client_id" >> "$tmp"
    mv "$tmp" "$TRACK_FILE" 2>/dev/null || rm -f "$tmp"
}

case "$action" in
    add|old)
        [ -n "$mac" ] && [ -n "$ip" ] || exit 0
        if is_whitelist_only && ! is_known_mac "$mac"; then
            rewrite_without_lease "$mac" "$ip"
            exit 0
        fi
        upsert_lease "$mac" "$ip" "$host"
        ;;
    del)
        rewrite_without_lease "$mac" "$ip"
        ;;
    *)
        ;;
esac

exit 0
