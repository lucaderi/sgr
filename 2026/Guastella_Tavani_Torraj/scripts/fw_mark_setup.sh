#!/usr/bin/env bash
set -eu

# Script di setup delle regole iptables per usare NFQUEUE insieme ai mark.
#
# Flow desiderato:
# 1. OUTPUT intercetta solo le porte di test e salta in FW_OUTPUT.
# 2. FW_OUTPUT recupera un eventuale CONNMARK gia' salvato sul flusso.
# 3. Se il mark e' gia' PASS/DROP, decide subito nel kernel.
# 4. Se non c'e' mark, manda il pacchetto in NFQUEUE.
# 5. Il programma C restituisce NF_ACCEPT con FW_MARK_PASS=0x1 o FW_MARK_DROP=0x2.
# 6. FW_POSTROUTING salva il packet mark nel CONNMARK e applica ACCEPT/DROP.
#
# Se si cambia protocollo, destinazione o insieme di porte tra due test,
# eseguire prima fw_mark_cleanup.sh per rimuovere i vecchi jump da OUTPUT.

# Permette di usare un binario iptables diverso, se serve:
#   IPTABLES=iptables-legacy sudo ./scripts/fw_mark_setup.sh -p tcp 80 23
IPTABLES=${IPTABLES:-iptables}

# La coda deve coincidere con quella creata da nfq_create_queue(..., 0, ...).
QUEUE_NUM=${QUEUE_NUM:-0}

# Protocollo e destinazione sono configurabili da CLI.
PROTO=tcp
DST_IP=""

usage() {
    echo "Usage: sudo $0 [-p tcp|udp] [-d dst_ip] port [port...]" >&2
    echo "Examples:" >&2
    echo "  sudo $0 -p tcp -d 127.0.0.1 80 23" >&2
}

while getopts "p:d:h" opt; do
    case "$opt" in
        p)
            PROTO="$OPTARG"
            ;;
        d)
            DST_IP="$OPTARG"
            ;;
        h)
            usage
            exit 0
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

shift $((OPTIND - 1))
PORTS=("$@")

# Le porte passate come argomenti limitano il traffico mandato a NFQUEUE.
# Non installiamo porte di default: chi lancia lo script deve scegliere il test.
if [ "$PROTO" != "tcp" ] && [ "$PROTO" != "udp" ]; then
    echo "Invalid protocol: $PROTO. Use tcp or udp." >&2
    exit 1
fi

if [ "${#PORTS[@]}" -eq 0 ]; then
    usage
    exit 1
fi

for port in "${PORTS[@]}"; do
    case "$port" in
        ''|*[!0-9]*)
            echo "Invalid port: $port" >&2
            exit 1
            ;;
    esac

    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "Invalid port: $port" >&2
        exit 1
    fi
done

DST_ARGS=()
if [ -n "$DST_IP" ]; then
    DST_ARGS=(-d "$DST_IP")
fi

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo $0 [-p tcp|udp] [-d dst_ip] port [port...]" >&2
    exit 1
fi

# Abilita accounting conntrack se il kernel lo espone.
# Non e' il meccanismo dei mark in se', ma rende le entry conntrack piu' osservabili.
if [ -e /proc/sys/net/netfilter/nf_conntrack_acct ]; then
    sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null || \
        echo "Warning: unable to enable nf_conntrack_acct; continuing." >&2
else
    echo "Warning: nf_conntrack_acct is not available; continuing without conntrack accounting." >&2
fi

# Creiamo chain custom nella tabella mangle.
# Se esistono gia', non falliamo: le svuotiamo subito dopo per ripartire puliti.
"$IPTABLES" -t mangle -N FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -N FW_POSTROUTING 2>/dev/null || true
"$IPTABLES" -t mangle -F FW_OUTPUT
"$IPTABLES" -t mangle -F FW_POSTROUTING

# Agganciamo OUTPUT alla nostra chain solo per protocollo/porte richiesti.
for port in "${PORTS[@]}"; do
    if ! "$IPTABLES" -t mangle -C OUTPUT -p "$PROTO" "${DST_ARGS[@]}" --dport "$port" -j FW_OUTPUT 2>/dev/null; then
        "$IPTABLES" -t mangle -I OUTPUT 1 -p "$PROTO" "${DST_ARGS[@]}" --dport "$port" -j FW_OUTPUT
    fi
done

# POSTROUTING e' il punto in cui salviamo il packet mark impostato da NFQUEUE
# nel CONNMARK e applichiamo il verdetto finale.
if ! "$IPTABLES" -t mangle -C POSTROUTING -j FW_POSTROUTING 2>/dev/null; then
    "$IPTABLES" -t mangle -I POSTROUTING 1 -j FW_POSTROUTING
fi

# FW_OUTPUT: prima proviamo a recuperare una decisione gia' salvata.
"$IPTABLES" -t mangle -A FW_OUTPUT -j CONNMARK --restore-mark

# Se restore-mark ha messo 0x1, il flusso era gia' stato permesso:
# evitiamo NFQUEUE e accettiamo subito.
"$IPTABLES" -t mangle -A FW_OUTPUT -m mark --mark 0x1 -j ACCEPT

# Se restore-mark ha messo 0x2, il flusso era gia' stato rifiutato:
# droppiamo direttamente nel kernel.
"$IPTABLES" -t mangle -A FW_OUTPUT -m mark --mark 0x2 -j DROP

# Se non avevamo decisioni cached, mandiamo il pacchetto a userspace.
# --queue-bypass evita freeze se ./firewall non e' acceso: in quel caso
# il kernel lascia passare invece di aspettare per sempre un verdict.
"$IPTABLES" -t mangle -A FW_OUTPUT -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass

# FW_POSTROUTING: qui il pacchetto e' tornato da NFQUEUE con mark 0x1/0x2.
# Salviamo il packet mark nel CONNMARK, cosi' i pacchetti successivi dello
# stesso flusso possono essere gestiti in FW_OUTPUT senza tornare in userspace.
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark ! --mark 0x0 -j CONNMARK --save-mark

# Gli ACCEPT tornano da NFQUEUE con mark 0x1.
# I DROP tornano da NFQUEUE con mark 0x2: qui vengono salvati e poi scartati.
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark --mark 0x2 -j DROP
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark --mark 0x1 -j ACCEPT

# Stampiamo regole e contatori subito dopo il setup: utile per debugging.
"$(dirname "$0")/fw_mark_status.sh"
