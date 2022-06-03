#!/bin/bash

FILE=/home/pi/temp/temp_db.rrd

if [ ! -f "$FILE" ]; then
	# Create db
	rrdtool create $FILE \
	--step 300 \
	DS:tmp:GAUGE:360:10:60 \
	DS:low:GAUGE:360:10:60 \
	DS:pre:GAUGE:360:10:60 \
	DS:upp:GAUGE:360:10:60 \
	RRA:AVERAGE:0.5:1:144 \
	RRA:AVERAGE:0.5:12:24 \
	RRA:AVERAGE:0.5:288:7
fi

COMMUNITY=public
HOSTNAME=localhost
TMP_FILE=/tmp/12_values
DES_PATH=double_exponential_smoothing.py


first=1
lower_bound=0
prediction=0
upper_bound=0

while true; do
	temp_value=$(snmpget -v1 -c $COMMUNITY $HOSTNAME nsExtendOutputFull.\"temp\" | cut -f 4 -d " ")

	rrdtool fetch temp_db.rrd AVERAGE -r 300 -s -2h | tail -n +3 | cut -f 2 -d " " > $TMP_FILE

	input_values=""

	while read -r line; do		
		if [ $line != nan ]; then
			old_value=$(echo $line | cut -c -6 | bc -l)
			input_values+=$(echo " $old_value")
		fi
	done < $TMP_FILE

	if [ $(echo $input_values | wc -w) -ge 12 ]; then
		# (lower_bound, prediction, upper_bound)
		output_values=( $(./$DES_PATH $input_values) )

		if [ $first -eq 1 ]; then
			first=0
			
			lower_bound=${output_values[0]}
			prediction=${output_values[1]}
			upper_bound=${output_values[2]}
			
			rrdupdate $FILE -t tmp N:$temp_value
		else
			rrdupdate $FILE -t tmp:low:pre:upp N:$temp_value:$lower_bound:$prediction:$upper_bound

			lower_bound=${output_values[0]}
			prediction=${output_values[1]}
			upper_bound=${output_values[2]}
		fi		
	else
		rrdupdate $FILE -t tmp N:$temp_value
	fi
	
	rrdtool graph /var/www/html/temp_graph.png \
	DEF:tmp=temp_db.rrd:tmp:AVERAGE \
	DEF:pre=temp_db.rrd:pre:AVERAGE \
	DEF:low=temp_db.rrd:low:AVERAGE \
	DEF:upp=temp_db.rrd:upp:AVERAGE \
	LINE1:tmp#1dd1a1:Temperature \
	LINE1:pre#54a0ff:Prediction \
	LINE1:upp#ee5253:Upper_bound \
	LINE1:low#576574:Lower_bound \
	-s -1h -e +5min > /dev/null
	
	sleep 300
done
