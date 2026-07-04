#!/bin/bash
set -e

echo "[client] Ready. Use docker exec dhcp_client dhcpcd -4 -1 eth0 for DHCP tests."
exec sleep infinity
