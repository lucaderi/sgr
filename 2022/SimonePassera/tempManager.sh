#!/bin/bash

# rrd
FILE=/home/pi/temp/temp_db.rrd
GRAPH_PATH=/var/www/html/
# snmp
COMMUNITY=public
HOSTNAME=localhost
# telegram
TOKEN=XXXXX
CHAT_ID=-1001733889922
MAX_LIMIT=30
# temporary file with last temperature values
TMP_FILE=/tmp/last_values
# path to code python
DES_PATH=double_exponential_smoothing.py

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

while true; do
	temp_value=$(snmpget -v1 -c $COMMUNITY $HOSTNAME nsExtendOutputFull.\"temp\" | cut -f 4 -d " ")

	rrdtool fetch $FILE AVERAGE -r 300 -s -2h | tail -n +3 | cut -f 2 -d " " > $TMP_FILE

	input_values=""

	while read -r line; do		
		if [ $line != nan ]; then
			old_value=$(echo $line | cut -c -6 | bc -l)
			input_values+=$(echo " $old_value")
		fi
	done < $TMP_FILE

	if [ $(echo $input_values | wc -w) -ge 2 ]; then
		# (lower_bound, prediction, upper_bound)
		output_values=( $(./$DES_PATH $input_values) )

		rrdupdate $FILE -t tmp:low:pre:upp N:$temp_value:${output_values[0]}:${output_values[1]}:${output_values[2]}

		if [ $(echo "$temp_value > ${output_values[2]}" | bc -l) -eq 1 ]; then
			curl -s -X POST https://api.telegram.org/bot$TOKEN/sendMessage -d chat_id=$CHAT_ID -d parse_mode=HTML -d text="<b>Alert</b> - Temperature: <b>$temp_value</b>°C %26gt; upper_bound = ${output_values[2]}°C" > /dev/null
		else
			if [ $(echo "$temp_value < ${output_values[0]}" | bc -l) -eq 1 ]; then
				curl -s -X POST https://api.telegram.org/bot$TOKEN/sendMessage -d chat_id=$CHAT_ID -d parse_mode=HTML -d text="<b>Alert</b> - Temperature: <b>$temp_value</b>°C %26lt; lower_bound = ${output_values[0]}°C" > /dev/null
			fi
		fi	
	else
		rrdupdate $FILE -t tmp N:$temp_value
	fi

	if [ $(echo "$temp_value > $MAX_LIMIT" | bc -l) -eq 1 ]; then
		curl -s -X POST https://api.telegram.org/bot$TOKEN/sendMessage -d chat_id=$CHAT_ID -d parse_mode=HTML -d text="<b>DANGER</b> : Temperature: <b>$temp_value</b>°C %26gt; LIMIT = <b>$MAX_LIMIT</b>°C" > /dev/null
	fi
	
	rrdtool graph $GRAPH_PATH/temp_graph_1h.png \
	DEF:tmp=temp_db.rrd:tmp:AVERAGE \
	DEF:pre=temp_db.rrd:pre:AVERAGE \
	DEF:low=temp_db.rrd:low:AVERAGE \
	DEF:upp=temp_db.rrd:upp:AVERAGE \
	LINE1:tmp#55e6c1:Temperature \
	LINE1:pre#54a0ff:Prediction \
	LINE1:upp#ee5253:Upper_bound \
	LINE1:low#576574:Lower_bound \
	HRULE:$MAX_LIMIT#a29bfe:Max_limit \
	-s -1h -e +5min --vertical-label "temperature (°C)" --title "1 hour" -w 500 -h 200 > /dev/null

	rrdtool graph $GRAPH_PATH/temp_graph_7d.png \
		DEF:tmp=temp_db.rrd:tmp:AVERAGE \
		DEF:pre=temp_db.rrd:pre:AVERAGE \
		DEF:low=temp_db.rrd:low:AVERAGE \
		DEF:upp=temp_db.rrd:upp:AVERAGE \
		LINE1:tmp#55e6c1:Temperature \
		LINE1:pre#54a0ff:Prediction \
		LINE1:upp#ee5253:Upper_bound \
		LINE1:low#576574:Lower_bound \
		HRULE:$MAX_LIMIT#a29bfe:Max_limit \
		-s -7d --vertical-label "temperature (°C)" --title "7 days" -w 500 -h 200 > /dev/null
	
	sleep 300
done
