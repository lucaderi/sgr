#!/bin/bash
apt update && apt install -y \
  python3 python3-scapy libpcap0.8 \
  iproute2 procps sudo yersinia openssh-server
