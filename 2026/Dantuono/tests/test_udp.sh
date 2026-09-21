#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
NETMON="${NETMON:-$PROJECT_ROOT/netmon}"

if [[ ! -x "$NETMON" ]]; then
  echo "[ERROR] Binary netmon non trovato o non eseguibile: $NETMON" >&2
  echo "Eseguire 'make' nella root del progetto prima dei test." >&2
  exit 1
fi

command -v python3 >/dev/null || {
  echo "[ERROR] python3 non trovato." >&2
  exit 1
}

TMP_DIR="$(mktemp -d)"
METRICS_FILE="$TMP_DIR/netmon.prom"
NETMON_LOG="$TMP_DIR/netmon.log"
NETMON_PID=""
SERVICE_PID=""

cleanup() {
  set +e
  if [[ -n "${SERVICE_PID:-}" ]] && kill -0 "$SERVICE_PID" 2>/dev/null; then
    kill "$SERVICE_PID" 2>/dev/null
    wait "$SERVICE_PID" 2>/dev/null || true
  fi
  if [[ -n "${NETMON_PID:-}" ]] && kill -0 "$NETMON_PID" 2>/dev/null; then
    kill "$NETMON_PID" 2>/dev/null
    wait "$NETMON_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

"$NETMON" --interval 1 --output "$METRICS_FILE" --verbose >"$NETMON_LOG" 2>&1 &
NETMON_PID=$!

for _ in {1..10}; do
  [[ -f "$METRICS_FILE" ]] && break
  sleep 1
done

if [[ ! -f "$METRICS_FILE" ]]; then
  echo "[ERROR] Netmon non ha creato il file delle metriche." >&2
  cat "$NETMON_LOG" >&2 || true
  exit 1
fi

wait_for_present() {
  local regex="$1"
  for _ in {1..10}; do
    if grep -Eq "$regex" "$METRICS_FILE"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_absent() {
  local regex="$1"
  for _ in {1..10}; do
    if ! grep -Eq "$regex" "$METRICS_FILE"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

metric_value() {
  local name="$1"
  awk -v metric="$name" '$1 == metric {print $2; exit}' "$METRICS_FILE"
}

PORT="${UDP_TEST_PORT:-19999}"
REGEX="^netmon_service_up\\{[^}]*protocol=\"udp\"[^}]*port=\"$PORT\"[^}]*\\} 1$"

python3 - "$PORT" >/dev/null 2>&1 <<'PY' &
import socket
import sys
import time
port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
try:
    time.sleep(30)
finally:
    sock.close()
PY
SERVICE_PID=$!

if wait_for_present "$REGEX"; then
  echo "[PASS] Servizio UDP su 0.0.0.0:$PORT rilevato."
else
  echo "[FAIL] Servizio UDP su 0.0.0.0:$PORT non rilevato." >&2
  cat "$METRICS_FILE" >&2
  exit 1
fi
