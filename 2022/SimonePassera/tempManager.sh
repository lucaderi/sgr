#!/bin/bash

FILE=/home/pi/temp/temp_db.rrd

if [ ! -f "$FILE" ]; then
	# Create db
	rrdtool create $FILE \
	--step 300 \
	DS:tmp:GAUGE:600:15:50 \
	RRA:AVERAGE:0.5:1:144 \
	RRA:AVERAGE:0.5:12:24 \
	RRA:AVERAGE:0.5:288:7
fi

COMMUNITY=public
HOSTNAME=localhost
TMP_FILE=/tmp/12_values
DES_PATH=double_exponential_smoothing.py

while true; do
	temp_value=$(snmpget -v1 -c $COMMUNITY $HOSTNAME nsExtendOutputFull.\"temp\" | cut -f 4 -d " ")
	#rrdtool update $FILE N:$temp_value

	#echo $temp_value

	rrdtool fetch temp_db.rrd AVERAGE -r 300 -s -1h | tail -n +3 | head -n 12 | cut -f 2 -d " " > $TMP_FILE

	input_values=""

	while read -r line; do		
		if [ $line != nan ]; then
			old_value=$(echo $line | cut -c -6 | bc -l)
			input_values+=$(echo " $old_value")
		fi
	done < $TMP_FILE

	# (lower_bound, prediction, upper_bound)
	output_values=( $(./$DES_PATH $input_values) )

	echo ${output_values[1]}
	
	sleep 300
done

#rrdtool graph temp_graph.png DEF:tmp=temp_db.rrd:tmp:AVERAGE LINE1:tmp#00ff00:Temperature --start -1h
