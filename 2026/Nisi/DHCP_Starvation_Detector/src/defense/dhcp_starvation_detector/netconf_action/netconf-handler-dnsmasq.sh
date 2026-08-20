#!/bin/sh

# Generic NETCONF 1.0 SSH subsystem handler for dnsmasq-backed routers.
# It supports OpenWrt/UCI and plain dnsmasq containers.
# Install: sshd Subsystem netconf /usr/local/bin/netconf-handler

if [ -z "${BASH_VERSION:-}" ] &&
   command -v bash >/dev/null 2>&1 &&
   [ "${NETCONF_HANDLER_NO_BASH:-0}" != "1" ]; then
    exec bash "$0" "$@"
fi

EOM=']]>]]>'
NS_NETCONF='urn:ietf:params:xml:ns:netconf:base:1.0'

DNSMASQ_MODE=${NETCONF_DNSMASQ_MODE:-}
PLAIN_LEASE_FILE=${DNSMASQ_LEASE_FILE:-/var/lib/misc/dnsmasq.leases}
PLAIN_RAW_LEASE_FILE=${DNSMASQ_RAW_LEASE_FILE:-/var/lib/misc/dnsmasq.leases.raw}
PLAIN_WHITELIST_CONF=${DNSMASQ_WHITELIST_CONF:-/etc/dnsmasq.d/whitelist.conf}
PLAIN_DNSMASQ_PID=${DNSMASQ_PID:-/var/run/dnsmasq.pid}
PLAIN_DNSMASQ_CONF=${DNSMASQ_CONF:-/etc/dnsmasq.conf}
PLAIN_POOL_TOTAL_DEFAULT=${DNSMASQ_POOL_TOTAL_DEFAULT:-151}

detect_dnsmasq_mode()
{
    if [ -n "$DNSMASQ_MODE" ]; then
        printf '%s\n' "$DNSMASQ_MODE"
    elif command -v uci >/dev/null 2>&1 && [ -x /etc/init.d/dnsmasq ]; then
        printf '%s\n' openwrt
    else
        printf '%s\n' plain
    fi
}

DNSMASQ_MODE=$(detect_dnsmasq_mode)

is_openwrt()
{
    [ "$DNSMASQ_MODE" = "openwrt" ]
}

send_nc()
{
    printf '%s%s' "$1" "$EOM"
}

read_nc()
{
    # NETCONF 1.0 frames messages with the literal marker ]]>]]>, with no
    # required trailing newline. read -n is available in BusyBox ash and Bash;
    # on Debian containers this script re-execs itself under Bash above.
    msg=
    tail=
    nl='
'

    while IFS= read -r -n 1 ch; do
        [ -n "$ch" ] || ch=$nl

        msg=$msg$ch
        tail=$tail$ch
        [ ${#tail} -gt 6 ] && tail=${tail#?}

        if [ "$tail" = "$EOM" ]; then
            printf '%s' "${msg%??????}"
            return 0
        fi
    done

    return 1
}

rpc_message_id()
{
    sed -n "s/.*message-id=['\"]\\([^'\"]*\\)['\"].*/\\1/p" | head -n 1
}

rpc_ok()
{
    mid=$1
    send_nc "<rpc-reply xmlns=\"$NS_NETCONF\" message-id=\"$mid\"><ok/></rpc-reply>"
}

rpc_error()
{
    mid=$1
    msg=$2
    send_nc "<rpc-reply xmlns=\"$NS_NETCONF\" message-id=\"$mid\"><rpc-error><error-type>application</error-type><error-tag>operation-failed</error-tag><error-severity>error</error-severity><error-message>$msg</error-message></rpc-error></rpc-reply>"
}

xml_escape()
{
    sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

xml_value()
{
    tag=$1
    sed -n "s#.*<$tag>\\([^<]*\\)</$tag>.*#\\1#p" | head -n 1
}

dhcp_lease_file()
{
    if is_openwrt; then
        uci -q get dhcp.@dnsmasq[0].leasefile 2>/dev/null || echo /tmp/dhcp.leases
    else
        printf '%s\n' "$PLAIN_LEASE_FILE"
    fi
}

dhcp_pool_total()
{
    if is_openwrt; then
        uci -q get dhcp.lan.limit 2>/dev/null ||
            uci -q get dhcp.@dhcp[0].limit 2>/dev/null ||
            echo 0
        return
    fi

    total=$(
        awk -F'[=,.]' '/^dhcp-range=/{
            s=$2*16777216+$3*65536+$4*256+$5
            e=$6*16777216+$7*65536+$8*256+$9
            if (e >= s) print e-s+1
            exit
        }' "$PLAIN_DNSMASQ_CONF" 2>/dev/null
    )
    [ -n "$total" ] || total=$PLAIN_POOL_TOTAL_DEFAULT
    printf '%s\n' "$total"
}

dhcp_pool_used()
{
    leasefile=$1

    if [ -f "$leasefile" ]; then
        wc -l < "$leasefile"
    else
        echo 0
    fi
}

dnsmasq_restart_plain()
{
    dnsmasq --test >/tmp/dnsmasq-test.log 2>&1 || return 1

    pids=$(pidof dnsmasq 2>/dev/null || true)
    for pid in $pids; do
        kill "$pid" 2>/dev/null || true
    done

    for _ in 1 2 3 4 5 6 7 8 9 10; do
        pidof dnsmasq >/dev/null 2>&1 || break
        sleep 0.1
    done

    pids=$(pidof dnsmasq 2>/dev/null || true)
    for pid in $pids; do
        kill -9 "$pid" 2>/dev/null || true
    done

    rm -f "$PLAIN_DNSMASQ_PID"

    for _ in 1 2 3 4 5; do
        if dnsmasq --pid-file="$PLAIN_DNSMASQ_PID" >/proc/1/fd/1 2>/proc/1/fd/2; then
            return 0
        fi
        pids=$(pidof dnsmasq 2>/dev/null || true)
        for pid in $pids; do
            kill "$pid" 2>/dev/null || true
        done
        sleep 0.2
    done

    return 1
}

dnsmasq_restart()
{
    if is_openwrt; then
        /etc/init.d/dnsmasq restart >/dev/null 2>&1
    else
        dnsmasq_restart_plain
    fi
}

reply_pool_stats()
{
    mid=$1
    leasefile=$(dhcp_lease_file)
    used=$(dhcp_pool_used "$leasefile")
    total=$(dhcp_pool_total)
    leasefile_xml=$(printf '%s' "$leasefile" | xml_escape)
    leases_xml=

    if [ -f "$leasefile" ]; then
        while read -r _expires mac ip _rest; do
            [ -n "$mac" ] || continue
            [ -n "$ip" ] || continue

            mac_xml=$(printf '%s' "$mac" | tr 'A-F' 'a-f' | xml_escape)
            ip_xml=$(printf '%s' "$ip" | xml_escape)
            leases_xml=$leases_xml"<lease><mac>$mac_xml</mac><ip>$ip_xml</ip></lease>"
        done < "$leasefile"
    fi

    send_nc "<rpc-reply xmlns=\"$NS_NETCONF\" message-id=\"$mid\"><data><dhcp-defense xmlns=\"urn:dhcp-starvation-detector\"><pool><used>$used</used><total>$total</total><lease-file>$leasefile_xml</lease-file>$leases_xml</pool></dhcp-defense></data></rpc-reply>"
}

release_lease()
{
    rpc=$1
    leasefile=$(dhcp_lease_file)
    mac=$(printf '%s' "$rpc" | xml_value mac | tr 'A-F' 'a-f')
    ip=$(printf '%s' "$rpc" | xml_value ip)
    tmp="$leasefile.netconf.$$"

    [ -n "$mac$ip" ] || return 1

    if [ ! -f "$leasefile" ]; then
        : > "$leasefile" || return 1
        return 0
    fi

    awk -v mac="$mac" -v ip="$ip" '
        {
            lease_mac = tolower($2)
            lease_ip = $3
            if ((mac != "" && lease_mac == mac) ||
                (ip != "" && lease_ip == ip)) {
                next
            }
            print
        }
    ' "$leasefile" > "$tmp" || {
        rm -f "$tmp"
        return 1
    }

    mv "$tmp" "$leasefile" || {
        rm -f "$tmp"
        return 1
    }

    dnsmasq_restart
}

delete_managed_hosts_openwrt()
{
    # Remove only host entries created by this handler. Delete from the end so
    # UCI section indexes remain stable while we are removing entries.
    indexes=$(uci show dhcp 2>/dev/null |
        sed -n "s/^dhcp\.@host\[\([0-9][0-9]*\)\]\.name='dhcp-starvation-.*/\1/p" |
        sort -rn)

    for idx in $indexes; do
        uci delete "dhcp.@host[$idx]" 2>/dev/null
    done
}

prune_untrusted_leases()
{
    allowed_macs=$(printf '%s\n' "$1" | tr 'A-F' 'a-f')
    leasefile=$(dhcp_lease_file)
    tmp="$leasefile.netconf-prune.$$"

    [ -f "$leasefile" ] || return 0
    : > "$tmp" || return 1

    while IFS= read -r line; do
        set -- $line
        lease_mac=$(printf '%s' "$2" | tr 'A-F' 'a-f')
        keep=0

        for mac in $allowed_macs; do
            if [ "$lease_mac" = "$mac" ]; then
                keep=1
                break
            fi
        done

        [ "$keep" -eq 1 ] && printf '%s\n' "$line" >> "$tmp"
    done < "$leasefile"

    mv "$tmp" "$leasefile" || {
        rm -f "$tmp"
        return 1
    }
}

apply_whitelist_on_openwrt()
{
    macs=$1

    delete_managed_hosts_openwrt

    for mac in $macs; do
        safe=$(printf '%s' "$mac" | tr ':A-F' '-a-f')
        sec=$(uci add dhcp host) || return 1
        uci set "dhcp.$sec.name=dhcp-starvation-$safe" || return 1
        uci set "dhcp.$sec.mac=$mac" || return 1
    done

    # Keep the dynamic pool enabled. The host entries above make these MACs
    # "known"; dnsmasq-ignore below drops every unknown client.
    uci set dhcp.lan.dynamicdhcp='1' || return 1
    uci -q del_list dhcp.@dnsmasq[0].addnhosts='/dev/null' 2>/dev/null || true
    uci -q delete dhcp.@dnsmasq[0].dhcpscript 2>/dev/null || true

    uci commit dhcp || return 1

    # Inject the only raw dnsmasq option we need. Remove stale copies first so
    # repeated NETCONF edits are idempotent.
    sed -i '/^dhcp-ignore=tag:!known$/d' /etc/dnsmasq.conf 2>/dev/null || true
    echo 'dhcp-ignore=tag:!known' >> /etc/dnsmasq.conf

    prune_untrusted_leases "$macs" || return 1
    dnsmasq_restart
}

apply_whitelist_on_plain()
{
    macs=$1
    conf=$PLAIN_WHITELIST_CONF
    conf_dir=${conf%/*}

    [ "$conf_dir" != "$conf" ] && mkdir -p "$conf_dir" 2>/dev/null || true

    {
        echo 'dhcp-ignore=tag:!known'
        for mac in $macs; do
            lower=$(printf '%s' "$mac" | tr 'A-F' 'a-f')
            echo "dhcp-host=${lower},set:known"
        done
    } > "$conf" || return 1

    prune_untrusted_leases "$macs" || return 1
    dnsmasq_restart
}

apply_whitelist_on()
{
    macs=$(printf '%s' "$1" |
        grep -o '<mac>[^<]*</mac>' |
        sed 's#<mac>##g; s#</mac>##g')

    if is_openwrt; then
        apply_whitelist_on_openwrt "$macs"
    else
        apply_whitelist_on_plain "$macs"
    fi
}

apply_whitelist_off()
{
    if is_openwrt; then
        delete_managed_hosts_openwrt

        uci set dhcp.lan.dynamicdhcp='1' || return 1
        uci -q del_list dhcp.@dnsmasq[0].addnhosts='/dev/null' 2>/dev/null || true
        uci -q delete dhcp.@dnsmasq[0].dhcpscript 2>/dev/null || true
        uci commit dhcp || return 1

        # Remove dhcp-ignore injected by apply_whitelist_on.
        sed -i '/^dhcp-ignore=tag:!known$/d' /etc/dnsmasq.conf 2>/dev/null || true
    else
        rm -f "$PLAIN_WHITELIST_CONF"
    fi

    dnsmasq_restart
}

reset_pool()
{
    leasefile=$(dhcp_lease_file)

    if is_openwrt; then
        delete_managed_hosts_openwrt

        uci set dhcp.lan.dynamicdhcp='1' || return 1
        uci -q del_list dhcp.@dnsmasq[0].addnhosts='/dev/null' 2>/dev/null || true
        uci -q delete dhcp.@dnsmasq[0].dhcpscript 2>/dev/null || true
        uci commit dhcp || return 1

        sed -i '/^dhcp-ignore=tag:!known$/d' /etc/dnsmasq.conf 2>/dev/null || true
    else
        rm -f "$PLAIN_WHITELIST_CONF"
        : > "$PLAIN_RAW_LEASE_FILE" || return 1
    fi

    : > "$leasefile" || return 1
    dnsmasq_restart
}

send_nc "<hello xmlns=\"$NS_NETCONF\"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:xml:ns:yang:ietf-netconf?module=ietf-netconf&amp;revision=2013-09-29&amp;features=writable-running</capability><capability>urn:dhcp-starvation-detector?module=dhcp-whitelist</capability></capabilities><session-id>1</session-id></hello>"

# Consume client hello.
read_nc >/dev/null || exit 1

while :; do
    rpc=$(read_nc) || exit 0
    mid=$(printf '%s' "$rpc" | rpc_message_id)
    [ -n "$mid" ] || mid=1

    case "$rpc" in
        *"<close-session"*)
            rpc_ok "$mid"
            exit 0
            ;;
        *"<edit-config"*)
            case "$rpc" in
                *"<whitelist-only>true</whitelist-only>"*)
                    if apply_whitelist_on "$rpc"; then
                        rpc_ok "$mid"
                    else
                        rpc_error "$mid" "failed to enable DHCP whitelist mode"
                    fi
                    ;;
                *"<whitelist-only>false</whitelist-only>"*)
                    if apply_whitelist_off; then
                        rpc_ok "$mid"
                    else
                        rpc_error "$mid" "failed to disable DHCP whitelist mode"
                    fi
                    ;;
                *)
                    rpc_error "$mid" "missing whitelist-only value"
                    ;;
            esac
            ;;
        *"<get"*)
            reply_pool_stats "$mid"
            ;;
        *"<release-lease"*)
            if release_lease "$rpc"; then
                rpc_ok "$mid"
            else
                rpc_error "$mid" "failed to release DHCP lease"
            fi
            ;;
        *"<reset-pool"*)
            if reset_pool; then
                rpc_ok "$mid"
            else
                rpc_error "$mid" "failed to reset DHCP pool"
            fi
            ;;
        *)
            rpc_error "$mid" "unsupported rpc"
            ;;
    esac
done
