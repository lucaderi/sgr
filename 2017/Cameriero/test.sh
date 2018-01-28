#!/bin/bash

set -e

IMAGE=tnwinc/snmp

# Ensure image is present
docker pull $IMAGE

# Starts 6 instances of snmpd
echo ""
echo "Starting SNMP instances..."
CIDS=()
CIDS+=("$(docker run --rm -d -e SNMPD_rocommunity=public $IMAGE)")
CIDS+=("$(docker run --rm -d -e SNMPD_rocommunity=public $IMAGE)")
CIDS+=("$(docker run --rm -d -e SNMPD_rocommunity=public $IMAGE)")
CIDS+=("$(docker run --rm -d -e SNMPD_rocommunity=public $IMAGE)")
CIDS+=("$(docker run --rm -d -e SNMPD_rocommunity=public $IMAGE)")
CIDS+=("$(docker run --rm -d -e SNMPD_rocommunity=public $IMAGE)")
echo "Done."

# Wait, just to be sure
sleep 3

# Start the scan on the /24 of the first container
SUBNET="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${CIDS[0]} | head -n 1)/24"
./out/snmpscan -d -p 10 $SUBNET

# Stop the containers
echo ""
echo "Stopping containers..."
for CID in "${CIDS[@]}"
do
	docker stop -t 1 $CID
done
echo "Done."