#!/bin/bash
if [ "${ATTACK_AUTOSTART:-0}" != "1" ]; then
    echo "[attacker] Ready. Use docker exec dhcp_attacker dhcp_starvation_attack.py eth0 ..."
    exec sleep infinity
fi

# Optional demo mode: wait for the detector warmup, then launch one attack.
WARMUP=${ATTACK_DELAY:-40}
echo "[attacker] Waiting ${WARMUP}s for detector baseline..."
sleep "$WARMUP"
echo "[attacker] Starting DHCP starvation (200 requests, LA-bit on)..."
exec python3 -u /usr/local/bin/dhcp_starvation_attack.py eth0 --count 200 --la on
