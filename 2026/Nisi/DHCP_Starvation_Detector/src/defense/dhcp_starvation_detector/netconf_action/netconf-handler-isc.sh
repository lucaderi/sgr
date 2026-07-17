#!/bin/bash

# NETCONF 1.0 SSH subsystem handler — ISC DHCP backend.
# Install: sshd Subsystem netconf /usr/local/bin/netconf-handler

EOM=']]>]]>'
NS='urn:ietf:params:xml:ns:netconf:base:1.0'
DHCPD_CONF=/etc/dhcp/dhcpd.conf
LEASE_FILE=/var/lib/dhcp/dhcpd.leases
LEASE_BACKUP=/var/lib/dhcp/dhcpd.leases~
WHITELIST_POLICY=/etc/dhcp/dhcpd.whitelist-policy.conf
WHITELIST_HOSTS=/etc/dhcp/dhcpd.whitelist-hosts.conf
DHCPD_PID=/run/dhcpd.pid
DHCP_IFACE=${DHCP_IFACE:-eth0}

POOL_SIZE=$(awk '
    /^[[:space:]]*range[[:space:]]+/ {
        start=$2
        end=$3
        gsub(/;/, "", end)
        split(start, s, ".")
        split(end, e, ".")
        sv=s[1]*16777216+s[2]*65536+s[3]*256+s[4]
        ev=e[1]*16777216+e[2]*65536+e[3]*256+e[4]
        print ev-sv+1
        exit
    }
' "$DHCPD_CONF" 2>/dev/null)
[ -n "$POOL_SIZE" ] || POOL_SIZE=151

send_nc() { printf '%s%s' "$1" "$EOM"; }

read_nc() {
    msg=; tail=; nl='
'
    while IFS= read -r -n 1 ch; do
        [ -n "$ch" ] || ch=$nl
        msg=$msg$ch; tail=$tail$ch
        [ ${#tail} -gt 6 ] && tail=${tail#?}
        if [ "$tail" = "$EOM" ]; then
            printf '%s' "${msg%??????}"
            return 0
        fi
    done
    return 1
}

rpc_message_id() { sed -n "s/.*message-id=['\"]\\([^'\"]*\\)['\"].*/\\1/p" | head -n 1; }
xml_escape()     { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
xml_value()      { sed -n "s#.*<$1>\\([^<]*\\)</$1>.*#\\1#p" | head -n 1; }

rpc_ok()    { send_nc "<rpc-reply xmlns=\"$NS\" message-id=\"$1\"><ok/></rpc-reply>"; }
rpc_error() { send_nc "<rpc-reply xmlns=\"$NS\" message-id=\"$1\"><rpc-error><error-type>application</error-type><error-tag>operation-failed</error-tag><error-severity>error</error-severity><error-message>$2</error-message></rpc-error></rpc-reply>"; }

active_leases() {
    awk '
        /^lease[[:space:]]+[0-9.]+[[:space:]]*[{]/ {
            inlease=1
            ip=$2
            mac=""
            state=""
            next
        }
        inlease && $1 == "hardware" && $2 == "ethernet" {
            mac=tolower($3)
            sub(/;$/, "", mac)
            next
        }
        inlease && $1 == "binding" && $2 == "state" {
            state=$3
            sub(/;$/, "", state)
            next
        }
        inlease && /^}/ {
            if (state == "active" && mac != "") {
                active[ip]=mac
            } else {
                delete active[ip]
            }
            inlease=0
            ip=""
            mac=""
            state=""
            next
        }
        END {
            for (ip in active) {
                print "0 " active[ip] " " ip " * *"
            }
        }
    ' "$LEASE_FILE" 2>/dev/null
}

stop_dhcpd() {
    local pids=

    pids=$(pidof dhcpd 2>/dev/null || true)
    for pid in $pids; do
        kill "$pid" 2>/dev/null || true
    done

    for _ in 1 2 3 4 5 6 7 8 9 10; do
        pidof dhcpd >/dev/null 2>&1 || break
        sleep 0.1
    done

    pids=$(pidof dhcpd 2>/dev/null || true)
    for pid in $pids; do
        kill -9 "$pid" 2>/dev/null || true
    done
    rm -f "$DHCPD_PID"
}

start_dhcpd() {
    mkdir -p /var/lib/dhcp /run
    touch "$LEASE_FILE"
    dhcpd -4 -q -cf "$DHCPD_CONF" -lf "$LEASE_FILE" -pf "$DHCPD_PID" "$DHCP_IFACE"
}

dhcp_config_ok() {
    mkdir -p /var/lib/dhcp /run
    touch "$LEASE_FILE" "$WHITELIST_POLICY" "$WHITELIST_HOSTS"
    dhcpd -t -cf "$DHCPD_CONF" >/tmp/dhcpd-test.log 2>&1
}

dhcp_reload() {
    dhcp_config_ok || return 1
    stop_dhcpd
    start_dhcpd
}

rewrite_leases_keep_macs() {
    local allowed=$1 tmp
    tmp=$(mktemp "${LEASE_FILE}.keep.XXXXXX") || return 1
    awk -v allowed="$(printf '%s' "$allowed" | tr 'A-F' 'a-f')" '
        BEGIN {
            n = split(allowed, arr, /[[:space:]]+/)
            for (i = 1; i <= n; i++) {
                if (arr[i] != "") keep[arr[i]]=1
            }
        }
        /^lease[[:space:]]+[0-9.]+[[:space:]]*[{]/ {
            inlease=1
            block=$0 ORS
            mac=""
            next
        }
        inlease {
            block=block $0 ORS
            if ($1 == "hardware" && $2 == "ethernet") {
                mac=tolower($3)
                sub(/;$/, "", mac)
            }
            if ($0 ~ /^}/) {
                if (mac in keep) {
                    printf "%s", block
                }
                inlease=0
                block=""
                mac=""
            }
            next
        }
        { print }
    ' "$LEASE_FILE" > "$tmp" || {
        rm -f "$tmp"
        return 1
    }
    mv "$tmp" "$LEASE_FILE" || {
        rm -f "$tmp"
        return 1
    }
    rm -f "$LEASE_BACKUP"
}

rewrite_leases_without() {
    local mac=$1 ip=$2 tmp
    tmp=$(mktemp "${LEASE_FILE}.rel.XXXXXX") || return 1
    awk -v wanted_mac="$(printf '%s' "$mac" | tr 'A-F' 'a-f')" -v wanted_ip="$ip" '
        /^lease[[:space:]]+[0-9.]+[[:space:]]*[{]/ {
            inlease=1
            block=$0 ORS
            lease_ip=$2
            lease_mac=""
            next
        }
        inlease {
            block=block $0 ORS
            if ($1 == "hardware" && $2 == "ethernet") {
                lease_mac=tolower($3)
                sub(/;$/, "", lease_mac)
            }
            if ($0 ~ /^}/) {
                if ((wanted_mac != "" && lease_mac == wanted_mac) ||
                    (wanted_ip != "" && lease_ip == wanted_ip)) {
                    inlease=0
                    block=""
                    lease_ip=""
                    lease_mac=""
                    next
                }
                printf "%s", block
                inlease=0
                block=""
                lease_ip=""
                lease_mac=""
            }
            next
        }
        { print }
    ' "$LEASE_FILE" > "$tmp" || {
        rm -f "$tmp"
        return 1
    }
    mv "$tmp" "$LEASE_FILE" || {
        rm -f "$tmp"
        return 1
    }
    rm -f "$LEASE_BACKUP"
}

reply_pool_stats() {
    local mid=$1 used lf_xml leases_xml=
    used=$(active_leases | wc -l)
    lf_xml=$(printf '%s' "$LEASE_FILE" | xml_escape)
    while read -r _exp mac ip _rest; do
        [ -n "$mac" ] && [ -n "$ip" ] || continue
        local m i
        m=$(printf '%s' "$mac" | xml_escape)
        i=$(printf '%s' "$ip" | xml_escape)
        leases_xml="${leases_xml}<lease><mac>${m}</mac><ip>${i}</ip></lease>"
    done <<EOF_LEASES
$(active_leases)
EOF_LEASES
    send_nc "<rpc-reply xmlns=\"$NS\" message-id=\"$mid\"><data><dhcp-defense xmlns=\"urn:dhcp-starvation-detector\"><pool><used>${used}</used><total>${POOL_SIZE}</total><lease-file>${lf_xml}</lease-file>${leases_xml}</pool></dhcp-defense></data></rpc-reply>"
}

apply_whitelist_on() {
    local macs safe
    macs=$(printf '%s' "$1" | grep -o '<mac>[^<]*</mac>' | sed 's#<mac>##g; s#</mac>##g')
    : > "$WHITELIST_HOSTS" || return 1
    for mac in $macs; do
        safe=$(printf '%s' "$mac" | tr ':A-F' '-a-f')
        printf 'host dhcp-starvation-%s { hardware ethernet %s; }\n' "$safe" "$mac" >> "$WHITELIST_HOSTS" || return 1
    done
    printf '%s\n' 'deny unknown-clients;' > "$WHITELIST_POLICY" || return 1
    dhcp_config_ok || return 1
    stop_dhcpd
    rewrite_leases_keep_macs "$macs" || return 1
    start_dhcpd
}

apply_whitelist_off() {
    : > "$WHITELIST_HOSTS" || return 1
    : > "$WHITELIST_POLICY" || return 1
    dhcp_reload
}

release_lease() {
    local rpc=$1 mac ip
    mac=$(printf '%s' "$rpc" | xml_value mac | tr 'A-F' 'a-f')
    ip=$(printf '%s' "$rpc" | xml_value ip)
    [ -n "$mac$ip" ] || return 1
    dhcp_config_ok || return 1
    stop_dhcpd
    rewrite_leases_without "$mac" "$ip" || return 1
    start_dhcpd
}

reset_pool() {
    : > "$WHITELIST_HOSTS" || return 1
    : > "$WHITELIST_POLICY" || return 1
    dhcp_config_ok || return 1
    stop_dhcpd
    : > "$LEASE_FILE" || return 1
    rm -f "$LEASE_BACKUP"
    start_dhcpd
}

send_nc "<hello xmlns=\"$NS\"><capabilities>\
<capability>urn:ietf:params:netconf:base:1.0</capability>\
<capability>urn:ietf:params:xml:ns:yang:ietf-netconf?module=ietf-netconf&amp;revision=2013-09-29&amp;features=writable-running</capability>\
<capability>urn:dhcp-starvation-detector?module=dhcp-whitelist</capability>\
</capabilities><session-id>1</session-id></hello>"

read_nc >/dev/null || exit 1

while :; do
    rpc=$(read_nc) || exit 0
    mid=$(printf '%s' "$rpc" | rpc_message_id)
    [ -n "$mid" ] || mid=1

    case "$rpc" in
        *'<close-session'*)
            rpc_ok "$mid"; exit 0 ;;
        *'<edit-config'*)
            case "$rpc" in
                *'<whitelist-only>true</whitelist-only>'*)
                    apply_whitelist_on "$rpc" && rpc_ok "$mid" || rpc_error "$mid" "failed to enable ISC whitelist" ;;
                *'<whitelist-only>false</whitelist-only>'*)
                    apply_whitelist_off && rpc_ok "$mid" || rpc_error "$mid" "failed to disable ISC whitelist" ;;
                *)
                    rpc_error "$mid" "missing whitelist-only value" ;;
            esac ;;
        *'<get'*)
            reply_pool_stats "$mid" ;;
        *'<release-lease'*)
            release_lease "$rpc" && rpc_ok "$mid" || rpc_error "$mid" "failed to release ISC lease" ;;
        *'<reset-pool'*)
            reset_pool && rpc_ok "$mid" || rpc_error "$mid" "failed to reset ISC pool" ;;
        *)
            rpc_error "$mid" "unsupported rpc" ;;
    esac
done
