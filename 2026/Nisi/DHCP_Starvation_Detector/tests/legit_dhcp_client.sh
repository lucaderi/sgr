#!/bin/sh

# DHCP legit client loop, utility script used in tests.

set -u

mode=${LEGIT_DHCP_CLIENT_MODE:-vms}
iface=${LEGIT_DHCP_CLIENT_IFACE:-}
log_file=${LEGIT_DHCP_CLIENT_LOG:-}
attempts=${LEGIT_DHCP_CLIENT_ATTEMPTS:-50}
prefix=${LEGIT_DHCP_CLIENT_IPV4_PREFIX:-192.168.42.}
valid_sleep=${LEGIT_DHCP_CLIENT_VALID_SLEEP_SECS:-30}
retry_sleep=${LEGIT_DHCP_CLIENT_RETRY_SLEEP_SECS:-8}
retry_backoff=${LEGIT_DHCP_CLIENT_RETRY_BACKOFF_SECS:-}
dhcpcd_timeout=${LEGIT_DHCP_CLIENT_DHCPCD_TIMEOUT_SECS:-}
dhcpget=${LEGIT_DHCP_CLIENT_DHCPGET:-}
static_cidr=${LEGIT_DHCP_CLIENT_STATIC_CIDR:-}
static_ip=${LEGIT_DHCP_CLIENT_STATIC_IP:-}
retry_index=1
had_valid=0

# Usage.
if [ -z "$iface" ] || [ -z "$log_file" ]; then
    echo "usage: set env vars LEGIT_DHCP_CLIENT_IFACE and LEGIT_DHCP_CLIENT_LOG" >&2
    exit 2
fi

# Logging.
log_dir=${log_file%/*}
if [ "$log_dir" != "$log_file" ]; then
    mkdir -p "$log_dir"
fi
: >> "$log_file" || exit 1
exec >> "$log_file" 2>&1

# Get first dynamic IPv4 IP.
dynamic_ip() {
    ip -4 addr show dev "$iface" scope global dynamic 2>/dev/null |
        awk '/inet /{split($2,a,"/"); print a[1]; exit}'
}

# Remove all iface dynamic IPv4.
drop_dynamic_addrs() {
    ip -4 -o addr show dev "$iface" scope global 2>/dev/null |
        while read -r _ _ _ cidr rest; do
            case "$rest" in
                *dynamic*) ip addr del "$cidr" dev "$iface" 2>/dev/null || true ;;
            esac
        done
}

# Sleep between each DHCP retry, each time a different value like 5 10 20.
retry_sleep_for_attempt() {
    if [ -z "$retry_backoff" ]; then
        printf '%s\n' "$retry_sleep"
        return
    fi

    idx=$retry_index
    chosen=
    last=
    for value in $retry_backoff; do
        last=$value
        if [ "$idx" -eq 1 ]; then
            chosen=$value
            break
        fi
        idx=$((idx - 1))
    done
    [ -n "$chosen" ] || chosen=$last
    [ -n "$chosen" ] || chosen=$retry_sleep
    printf '%s\n' "$chosen"
}

# Make a DHCP request attempt in Docker environment.
run_docker_attempt() {
    if [ -n "$dhcpcd_timeout" ]; then
        printf '[cmd to be executed] pkill dhcpcd; flush stale dynamic address if needed; dhcpcd -4 -1 -L -t %s %s\n' "$dhcpcd_timeout" "$iface"
    else
        printf '[cmd to be executed] pkill dhcpcd; flush stale dynamic address if needed; dhcpcd -4 -1 -L %s\n' "$iface"
    fi
    pkill -f '[d]hcpcd' >/dev/null 2>&1 || true

    cur_dyn=$(dynamic_ip)
    case "$cur_dyn" in
        "$prefix"*) printf '[state] keeping existing DHCP address: %s\n' "$cur_dyn" ;;
        *) drop_dynamic_addrs ;;
    esac

    set -- -4 -1 -L
    if [ -n "$dhcpcd_timeout" ]; then
        set -- "$@" -t "$dhcpcd_timeout"
    fi
    printf '[info] DUID/IAID lines below are dhcpcd identifiers: DHCP client identity and interface identity used for client_id\n'
    dhcpcd "$@" "$iface"
    dhcp_rc=$?
    printf '[exit] dhcpcd rc=%s\n' "$dhcp_rc"

    printf '\n[cmd to be executed] ip -4 addr show dev %s scope global dynamic\n' "$iface"
    ip_out=$(ip -4 addr show dev "$iface" scope global dynamic 2>&1)
    printf '%s\n' "$ip_out"
    cur=$(printf '%s\n' "$ip_out" |
        awk '/inet /{split($2,a,"/"); print a[1]; exit}')
    return "$dhcp_rc"
}

# Make a DHCP request attempt in VMs environment.
run_vm_attempt() {
    if [ -z "$dhcpget" ]; then
        echo "LEGIT_DHCP_CLIENT_DHCPGET is required in vms mode" >&2
        return 2
    fi

    if [ -n "$dhcpcd_timeout" ]; then
        printf '[cmd to be executed] DHCPGET_DHCPCD_TIMEOUT_SECS=%s %s %s\n' "$dhcpcd_timeout" "$dhcpget" "$iface"
        export DHCPGET_DHCPCD_TIMEOUT_SECS="$dhcpcd_timeout"
    else
        printf '[cmd to be executed] %s %s\n' "$dhcpget" "$iface"
    fi
    printf '[info] DUID/IAID lines below are dhcpcd identifiers: DHCP client identity and interface identity used for client_id\n'
    "$dhcpget" "$iface"
    dhcp_rc=$?
    printf '[exit] dhcpget rc=%s\n' "$dhcp_rc"

    printf '\n[cmd to be executed] ip -4 addr show dev %s scope global\n' "$iface"
    ip_out=$(ip -4 addr show dev "$iface" scope global 2>&1)
    printf '%s\n' "$ip_out"
    cur=$(printf '%s\n' "$ip_out" |
        awk '/inet /{split($2,a,"/"); print a[1]; exit}')

    if [ -n "$static_cidr" ]; then
        ip addr add "$static_cidr" dev "$iface" 2>/dev/null || true
        printf '[state] management address ensured: %s\n' "${static_ip:-$static_cidr}"
    fi
    return "$dhcp_rc"
}

# Some cleaning in Docker mode.
if [ "$mode" = "docker" ]; then
    pkill -f '[d]hcpcd' >/dev/null 2>&1 || true
    rm -f /var/lib/dhcpcd/*.lease /var/lib/dhcpcd/*/*.lease 2>/dev/null || true
    drop_dynamic_addrs
fi

# Main loop, tries more DHCP attempts based on the Docker or VMs mode.
i=0
while [ "$i" -lt "$attempts" ]; do
    now=$(date '+%Y-%m-%d %H:%M:%S %Z')
    printf '\n===== legit DHCP client attempt %s BEGIN  [%s] =====\n' "$i" "$now"

    cur=
    attempt_rc=0
    case "$mode" in
        docker) run_docker_attempt || attempt_rc=$? ;;
        vms)    run_vm_attempt || attempt_rc=$? ;;
        *)
            echo "unsupported LEGIT_DHCP_CLIENT_MODE=$mode" >&2
            exit 2
            ;;
    esac
    if [ "$attempt_rc" -ne 0 ]; then
        case "$attempt_rc" in
            2|126|127)
                printf '[FAIL] fatal DHCP client command error rc=%s\n' "$attempt_rc"
                exit "$attempt_rc"
                ;;
            *)
                printf '[WARN] DHCP client attempt command returned rc=%s; checking lease state before retry\n' "$attempt_rc"
                ;;
        esac
    fi

    case "$cur" in
        "$prefix"*)
            had_valid=1
            printf '[result] valid DHCP lease: %s\n' "$cur"
            printf '===== legit DHCP client attempt %s END  [valid] =====\n' "$i"
            sleep "$valid_sleep"
            ;;
        *)
            printf '[result] no valid DHCP lease on %s0/24 (current=%s)\n\n' \
                "$prefix" "${cur:-none}"
            printf '===== legit DHCP client attempt %s END  [retry] =====\n' "$i"
            sleep_for=$(retry_sleep_for_attempt)
            printf '[state] retry sleep: %ss\n' "$sleep_for"
            retry_index=$((retry_index + 1))
            sleep "$sleep_for"
            ;;
    esac

    i=$((i + 1))
done

if [ "$had_valid" -eq 1 ]; then
    exit 0
fi

printf '\n[FAIL] no valid DHCP lease obtained after %s attempts\n' "$attempts"
exit 1
