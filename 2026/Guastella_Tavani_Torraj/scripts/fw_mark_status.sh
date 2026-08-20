#!/usr/bin/env bash
set -u

# Stampa regole e contatori della tabella mangle.
# E' lo script da usare dopo ogni prova per capire il flow:
# - FW_OUTPUT / NFQUEUE indica quanti pacchetti sono entrati in userspace.
# - FW_OUTPUT / mark 0x1 o 0x2 indica quanti pacchetti sono stati gestiti
#   usando una decisione gia' salvata nel CONNMARK.
# - FW_POSTROUTING / CONNMARK save indica quanti packet mark sono stati
#   salvati nelle entry conntrack.

IPTABLES=${IPTABLES:-iptables}

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo ./scripts/fw_mark_status.sh" >&2
    exit 1
fi

echo "=== mangle rules ==="
# Forma compatta, utile per capire esattamente come ricreare/rimuovere regole.
"$IPTABLES" -t mangle -S

echo
echo "=== FW_OUTPUT counters ==="
# Contatori della chain dove avviene il restore-mark e l'eventuale salto NFQUEUE.
"$IPTABLES" -t mangle -L FW_OUTPUT -v -n --line-numbers 2>/dev/null || true

echo
echo "=== FW_POSTROUTING counters ==="
# Contatori della chain dove salviamo il mark e applichiamo il verdetto finale.
"$IPTABLES" -t mangle -L FW_POSTROUTING -v -n --line-numbers 2>/dev/null || true
