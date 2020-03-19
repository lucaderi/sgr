#!/usr/bin/env bash

walk() {
	GROUP=$1
	HOST=$2

	if [[ ! ( $1 && $2 ) ]]; then
		echo "usage: snmp-status <group> <hostname>"
		return 1
	fi

	IFS=$'\n'
	read -d '' -r -a KEYS <<< $(snmpwalk -v1 -OQ -c $GROUP $HOST lmTempSensorsDevice | head -5 | cut -d" " -f3,4)
	while read -r value; do
 		VALUES+=("$(( $value / 1000 )).0 C")
   	done <<< $(snmpwalk -v1 -OQ -c $GROUP $HOST lmTempSensorsValue | head -5 | cut -d" " -f3)

	
	KEYS+=("cpu usage")
	VALUES+=($((100 -  $(snmpget -v1 -OQ -c $GROUP $HOST UCD-SNMP-MIB::ssCpuIdle.0 | cut -d" " -f3) ))%)

	KEYS+=("free mem")
	VALUES+=("$(snmpget -v1 -OQ -c $GROUP $HOST UCD-SNMP-MIB::memAvailReal.0 | cut -d" " -f3) KB / $(snmpget -v1 -OQ -c $GROUP $HOST UCD-SNMP-MIB::memTotalReal.0 | cut -d" " -f3) KB")


	for i in $(seq 0 $(( ${#KEYS[@]} - 1)) ); do	
		echo ${KEYS[$i]}: ${VALUES[$i]}
	done
}

export -f walk
watch -e -n5 walk $1 $2
