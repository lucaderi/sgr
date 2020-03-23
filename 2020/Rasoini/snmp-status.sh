#!/usr/bin/env bash

walk() {
	#Save cursor position
	#tput sc

	GROUP=$1
	HOST=$2
	KEYS=()
	VALUES=()

	if [[ ! ( $1 && $2 ) ]]; then
		echo "usage: snmp-status.sh <community> <hostname>"
		return 1
	fi
	
	IFS=$'\n'

	#Check if the system has lm_sensors and if positive grab data

	INDEXES=($(snmpwalk -v1 -OQv -c $GROUP $HOST LM-SENSORS-MIB::lmTempSensorsIndex 2> /dev/null))
	if (( ${#INDEXES[@]} )); then
		for index in ${INDEXES[@]}; do
			#Sensor name
			KEYS+=($(snmpget -v1 -OQv -c $GROUP $HOST LM-SENSORS-MIB::lmTempSensorsDevice.$index))
			#Sensor value
			VALUES+=($(( $(snmpget -v1 -OQv -c $GROUP $HOST LM-SENSORS-MIB::lmTempSensorsValue.$index) / 1000))".00 C")
		done
	fi
	
	KEYS+=("cpu usage")
	VALUES+=($((100 -  $(snmpget -v1 -OQv -c $GROUP $HOST UCD-SNMP-MIB::ssCpuIdle.0) ))%)

	KEYS+=("free mem")
	VALUES+=("$(snmpget -v1 -OQv -c $GROUP $HOST UCD-SNMP-MIB::memAvailReal.0) / $(snmpget -v1 -OQv -c $GROUP $HOST UCD-SNMP-MIB::memTotalReal.0)")

	#print data
	for i in $(seq 0 $(( ${#KEYS[@]} - 1)) ); do	
		echo ${KEYS[$i]}: ${VALUES[$i]}
	done
}

walk $1 $2
