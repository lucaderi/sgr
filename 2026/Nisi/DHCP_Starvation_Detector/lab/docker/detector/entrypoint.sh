#!/bin/bash
set -e
echo "[detector] Waiting for router SSH starting on 192.168.100.1:830..."
until nc -z 192.168.100.1 830 2>/dev/null; do sleep 1; done
echo "[detector] Router ready. Container idle; test suite starts detector instances."
exec sleep infinity
