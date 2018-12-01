#!/bin/sh

cd nDPI-dev
cat tests/result/Modbus.pcap.out 
cd example/
./ndpiReader -i ../tests/pcap/Modbus.pcap  -v 1