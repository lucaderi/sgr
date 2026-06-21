#!/bin/bash

# Needed to install the client and test DHCP server and project functionality. 
apt update && apt install -y dhcpcd iproute2 procps mawk tar util-linux
