#!/usr/bin/env bash
set -u

# Rimuove solo le chain create dai nostri script mark.
# Non fa flush globale della tabella mangle, cosi' e' piu' sicuro su una macchina
# dove potrebbero esserci altre regole iptables non collegate al progetto.

# Permette override, ad esempio:
#   IPTABLES=iptables-legacy sudo ./scripts/fw_mark_cleanup.sh
IPTABLES=${IPTABLES:-iptables}

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo ./scripts/fw_mark_cleanup.sh" >&2
    exit 1
fi

delete_jumps_to() {
    local chain=$1
    local target=$2
    local rules

    # Una chain custom non si puo' cancellare finche' una chain built-in
    # ci salta dentro. Qui cerchiamo tutte le regole tipo:
    #   -A OUTPUT ... -j FW_OUTPUT
    # e le convertiamo in:
    #   -D OUTPUT ... -j FW_OUTPUT
    # Ripetiamo in loop per gestire eventuali duplicati.
    while true; do
        mapfile -t rules < <("$IPTABLES" -t mangle -S "$chain" 2>/dev/null | grep -- " -j $target")
        [ "${#rules[@]}" -eq 0 ] && break

        for rule in "${rules[@]}"; do
            # Qui vogliamo volutamente espandere la regola in argomenti iptables.
            # shellcheck disable=SC2086
            "$IPTABLES" -t mangle ${rule/-A /-D }
        done
    done
}

# Scollega prima le chain custom dai punti di ingresso del kernel.
delete_jumps_to OUTPUT FW_OUTPUT
delete_jumps_to POSTROUTING FW_POSTROUTING

# Poi svuota e cancella le chain. Gli errori sono ignorati per rendere
# lo script idempotente: puoi lanciarlo anche se le chain non esistono.
"$IPTABLES" -t mangle -F FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -F FW_POSTROUTING 2>/dev/null || true
"$IPTABLES" -t mangle -X FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -X FW_POSTROUTING 2>/dev/null || true

# Stato finale: se tutto e' pulito dovresti vedere solo le policy built-in.
"$IPTABLES" -t mangle -S
