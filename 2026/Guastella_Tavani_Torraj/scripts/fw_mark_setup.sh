#!/usr/bin/env bash
set -eu

# Script di setup delle regole iptables per usare NFQUEUE insieme ai mark.
#
# Flow desiderato:
# 1. OUTPUT intercetta solo le porte di test e salta in FW_OUTPUT.
# 2. FW_OUTPUT recupera un eventuale CONNMARK gia' salvato sul flusso.
# 3. Se il mark e' gia' PASS/DROP, decide subito nel kernel.
# 4. Se non c'e' mark, manda il pacchetto in NFQUEUE.
# 5. Il programma C assegna FW_MARK_PASS=0x1 o FW_MARK_DROP=0x2.
# 6. POSTROUTING salva quel packet mark nel CONNMARK e applica ACCEPT/DROP.

# Permette di usare un binario iptables diverso, se serve:
#   IPTABLES=iptables-legacy sudo ./scripts/fw_mark_setup.sh
IPTABLES=${IPTABLES:-iptables}

# La coda deve coincidere con quella creata da nfq_create_queue(..., 0, ...).
QUEUE_NUM=${QUEUE_NUM:-0}

# Nei test locali intercettiamo solo loopback. Cambiabile con:
#   DST_IP=192.168.1.10 sudo ./scripts/fw_mark_setup.sh 80 23
DST_IP=${DST_IP:-127.0.0.1}

# Le porte passate come argomenti limitano il traffico mandato a NFQUEUE.
# Senza argomenti usiamo le due porte utili per il progetto: HTTP e TELNET.
PORTS=("$@")

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo ./scripts/fw_mark_setup.sh [ports...]" >&2
    exit 1
fi

if [ "${#PORTS[@]}" -eq 0 ]; then
    PORTS=(80 23)
fi

# Abilita accounting conntrack come richiesto dal prof.
# Non e' il meccanismo dei mark in se', ma rende le entry conntrack piu' osservabili.
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null

# Creiamo chain custom nella tabella mangle.
# Se esistono gia', non falliamo: le svuotiamo subito dopo per ripartire puliti.
"$IPTABLES" -t mangle -N FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -N FW_POSTROUTING 2>/dev/null || true
"$IPTABLES" -t mangle -F FW_OUTPUT
"$IPTABLES" -t mangle -F FW_POSTROUTING

# Agganciamo OUTPUT alla nostra chain solo per le porte richieste.
# Questa scelta evita il problema visto con VSCode/WSL: non mandiamo tutto
# il traffico TCP loopback in NFQUEUE, ma solo quello che vogliamo testare.
for port in "${PORTS[@]}"; do
    if ! "$IPTABLES" -t mangle -C OUTPUT -p tcp -d "$DST_IP" --dport "$port" -j FW_OUTPUT 2>/dev/null; then
        "$IPTABLES" -t mangle -I OUTPUT 1 -p tcp -d "$DST_IP" --dport "$port" -j FW_OUTPUT
    fi
done

# POSTROUTING e' il punto in cui salviamo il packet mark impostato da NFQUEUE
# nel CONNMARK della connessione/flusso.
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

# Applichiamo il verdetto reale dopo aver salvato il mark.
# Nel C anche i DROP tornano come NF_ACCEPT + MARK_DROP proprio per arrivare qui.
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark --mark 0x2 -j DROP
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark --mark 0x1 -j ACCEPT

# Stampiamo regole e contatori subito dopo il setup: utile per debugging.
"$(dirname "$0")/fw_mark_status.sh"
