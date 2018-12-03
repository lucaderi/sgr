#!/bin/sh
if [[ ! $# == 1 ]]; then
echo "usage $0 and dir_name"
exit 1
fi
cd "$1"

cat tests/result/Modbus.pcap.out 
cd example/
./ndpiReader -i ../tests/pcap/Modbus.pcap  -v 1
