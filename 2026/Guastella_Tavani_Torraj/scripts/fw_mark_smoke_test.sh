#!/usr/bin/env bash
set -u

# Smoke test reale per NFQUEUE + mark/CONNMARK.
#
# Fa tutto in automatico:
# 1. pulisce vecchie regole del progetto;
# 2. avvia ./firewall in background;
# 3. installa regole iptables TCP limitate a 127.0.0.1:80 e :23;
# 4. apre un server HTTP locale sulla porta 80;
# 5. genera traffico vero verso 80 e 23;
# 6. stampa log e contatori;
# 7. pulisce processi e regole anche in caso di Ctrl+C/errore.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

# Pid dei processi temporanei avviati dallo script.
FW_PID=""
HTTP_PID=""
CLEANUP_DONE=0

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo ./scripts/fw_mark_smoke_test.sh" >&2
    exit 1
fi

if [ ! -x ./firewall ]; then
    echo "Missing ./firewall. Build it first with: make firewall" >&2
    exit 1
fi

if ! command -v nc >/dev/null 2>&1; then
    echo "nc not found. Install netcat before running this smoke test." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found. It is used only to open a local TCP/80 server." >&2
    exit 1
fi

stop_process() {
    pid="$1"
    first_signal="$2"

    if [ -z "$pid" ]; then
        return 0
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null
        return 0
    fi

    kill "-$first_signal" "$pid" 2>/dev/null

    for _ in 1 2 3 4 5; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null
            return 0
        fi
        sleep 0.1
    done

    kill -TERM "$pid" 2>/dev/null

    for _ in 1 2 3 4 5; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null
            return 0
        fi
        sleep 0.1
    done

    kill -KILL "$pid" 2>/dev/null
}

cleanup() {
    set +e

    if [ "$CLEANUP_DONE" -eq 1 ]; then
        return
    fi
    CLEANUP_DONE=1
    trap - EXIT INT TERM

    # Chiude prima il server HTTP di test, se e' partito.
    stop_process "$HTTP_PID" TERM

    # Ferma il firewall con SIGINT; se resta bloccato in recv(), forza l'uscita.
    stop_process "$FW_PID" INT

    # Rimuove sempre le chain iptables create per il test.
    ./scripts/fw_mark_cleanup.sh >/dev/null 2>&1
}

# Garantisce cleanup su uscita normale, errore, Ctrl+C o kill TERM.
trap cleanup EXIT INT TERM

# Artefatti del test: stdout/stderr dei processi e log firewall.
mkdir -p build
rm -f firewall.log build/mark_*.out build/mark_*.err

# Parti da stato iptables pulito, anche se un test precedente e' stato interrotto.
./scripts/fw_mark_cleanup.sh >/dev/null 2>&1

# Avvia il firewall userspace. Deve restare vivo mentre installiamo NFQUEUE.
./firewall firewall.conf > build/mark_firewall.out 2> build/mark_firewall.err &
FW_PID=$!
sleep 1

# Se il firewall muore subito, probabilmente manca permesso/coda/libnetfilter.
if ! kill -0 "$FW_PID" 2>/dev/null; then
    echo "Firewall exited before the smoke test started." >&2
    cat build/mark_firewall.err >&2
    exit 1
fi

# Installa le regole per mandare solo TCP/80 e TCP/23 alla queue 0.
./scripts/fw_mark_setup.sh -p tcp -d 127.0.0.1 80 23 > build/mark_setup.out

# Porta 80: apriamo un server reale, cosi' il flusso ACCEPT puo' completarsi.
# Questo serve a vedere il riuso del CONNMARK sui pacchetti successivi.
python3 -m http.server 80 --bind 127.0.0.1 --directory . > build/mark_http.out 2> build/mark_http.err &
HTTP_PID=$!
sleep 1

if ! kill -0 "$HTTP_PID" 2>/dev/null; then
    echo "Local HTTP server on 127.0.0.1:80 failed to start." >&2
    cat build/mark_http.err >&2
    exit 1
fi

# Genera traffico vero:
# - HTTP verso 80 deve essere RULE_ALLOW;
# - TCP connect verso 23 deve essere RULE_DROP.
printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | timeout 3 nc 127.0.0.1 80 >/dev/null 2>&1 || true
timeout 1 nc -zv 127.0.0.1 23 >/dev/null 2>&1 || true

# Lasciamo tempo a NFQUEUE/log/iptables counters di aggiornarsi.
sleep 1

# Salva lo stato mark dopo il traffico.
./scripts/fw_mark_status.sh > build/mark_status.out

# Output leggibile per debugging.
echo "=== firewall output ==="
cat build/mark_firewall.out

echo
echo "=== firewall log ==="
cat firewall.log

echo
echo "=== mark counters ==="
cat build/mark_status.out

if ! grep -q "DPORT=80 PROTO=6 DECISION=ACCEPT REASON=RULE_ALLOW" firewall.log; then
    echo "Expected one TCP/80 RULE_ALLOW decision in firewall.log." >&2
    exit 1
fi

if ! grep -q "DPORT=23 PROTO=6 DECISION=DROP REASON=RULE_DROP" firewall.log; then
    echo "Expected one TCP/23 RULE_DROP decision in firewall.log." >&2
    exit 1
fi

# Nota: sui SYN droppati puo' capitare che alcune ritrasmissioni rientrino
# ancora in NFQUEUE perche' il flusso non viene confermato in conntrack.
# Il comportamento piu' importante da osservare e':
# - CONNMARK save > 0 in FW_POSTROUTING;
# - mark 0x1 ACCEPT in FW_OUTPUT per i pacchetti del flusso permesso.
echo
echo "Smoke test completed. Check FW_OUTPUT/FW_POSTROUTING counters above for mark reuse."
