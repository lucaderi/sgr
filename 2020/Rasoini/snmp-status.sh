#!/usr/bin/env bash

walk() {
	#Save cursor position
	tput sc

	GROUP=$1
	HOST=$2
	TIME=$3
	KEYS=()
	VALUES=()

	if [[ ! ( $1 && $2 && $3 ) ]]; then
		echo "usage: snmp-status <group> <hostname> <time>"
		return 1
	fi

	IFS=$'\n'
	
	#Check if the system has lm_sensors and if positive grab data
	if snmpget -v1 -c $GROUP $HOST lmTempSensorsIndex.1 &> /dev/null; then
		read -d '' -r -a KEYS <<< $(snmpwalk -v1 -OQv -c $GROUP $HOST lmTempSensorsDevice | head -5)
		while read -r value; do
 			VALUES+=("$(( $value / 1000 )).0 C")
   		done <<< $(snmpwalk -v1 -OQv -c $GROUP $HOST lmTempSensorsValue | head -5)
	fi
	
	KEYS+=("cpu usage")
	VALUES+=($((100 -  $(snmpget -v1 -OQv -c $GROUP $HOST UCD-SNMP-MIB::ssCpuIdle.0) ))%)

	KEYS+=("free mem")
	VALUES+=("$(snmpget -v1 -OQv -c $GROUP $HOST UCD-SNMP-MIB::memAvailReal.0) / $(snmpget -v1 -OQv -c $GROUP $HOST UCD-SNMP-MIB::memTotalReal.0)")

	#print data
	for i in $(seq 0 $(( ${#KEYS[@]} - 1)) ); do	
		echo ${KEYS[$i]}: ${VALUES[$i]}
	done
	
	#wait $TIME
	sleep $TIME
	
	#Clear screen and walk again
	tput rc
    tput ed
	walk $GROUP $HOST $TIME
}

walk $1 $2 $3
