#!/bin/sh

if [[ ! $# == 1 ]]; then
    echo "usage $0 and dir_name"
    exit 1
fi


    cp ndpi_protocol_ids.h "$1"/src/include
    cp ndpi_protocols.h "$1"/src/include
    cp ndpi_typedefs.h "$1"/src/include
    cp modbus.c "$1"/src/lib/protocols
    cp Modbus.pcap "$1"/tests/pcap
    cp ndpi_main.c "$1"/src/lib

