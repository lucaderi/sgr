#!/bin/bash

# RRD
RRD_DB=/home/pi/temp/temp_db.rrd
GRAPH_PATH=/var/www/html/graphs/
# SNMP
COMMUNITY=public
HOSTNAME=localhost
# Telegram
TOKEN=XXXXX
CHAT_ID=-1001733889922
MAX_LIMIT=30
# Temporary file with last temperature values
TMP_FILE=/tmp/last_values
# Path to code python (Double exponential smoothing)
DES_PATH=double_exponential_smoothing.py

# Create rrd database if not exist
# Update db every 5 min, raw data for 12 hours, average of 1 hour for 1 day, average of 1 day for 7 days
if [ ! -f "$RRD_DB" ]; then
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
	# Get the current office temperature with SNMP GET request 
	temp_value=$(snmpget -v1 -c $COMMUNITY $HOSTNAME nsExtendOutputFull.\"temp\" | cut -f 4 -d " ")

	# Save the last two hours of points on a temporary file
	rrdtool fetch $RRD_DB AVERAGE -r 300 -s -2h | tail -n +3 | cut -f 2 -d " " > $TMP_FILE

	# Contains the list of temperatures used by the DES algorithm
	input_values=""

	while read -r line; do
		# Add only points with a significant value		
		if [ $line != nan ]; then
			old_value=$(echo $line | cut -c -6 | bc -l)
			input_values+=$(echo " $old_value")
		fi
	done < $TMP_FILE

	# Calculates the estimate of the next point only if there are at least two previous points
	if [ $(echo $input_values | wc -w) -ge 2 ]; then
		# The DES algorithm returns three values: (lower_bound, prediction, upper_bound)
		output_values=( $(./$DES_PATH $input_values) )

		# Insert the current temperature and the expected value (with upper and lower bound) for this point in the rrd database  
		rrdupdate $RRD_DB -t tmp:low:pre:upp N:$temp_value:${output_values[0]}:${output_values[1]}:${output_values[2]}

		# Send alert to channel Telegram if current temperature is over the limits
		if [ $(echo "$temp_value > ${output_values[2]}" | bc -l) -eq 1 ]; then
			curl -s -X POST https://api.telegram.org/bot$TOKEN/sendMessage -d chat_id=$CHAT_ID -d parse_mode=HTML -d text="<b>Alert</b> - Temperature: <b>$temp_value</b>°C %26gt; upper_bound = ${output_values[2]}°C" > /dev/null
		else
			if [ $(echo "$temp_value < ${output_values[0]}" | bc -l) -eq 1 ]; then
				curl -s -X POST https://api.telegram.org/bot$TOKEN/sendMessage -d chat_id=$CHAT_ID -d parse_mode=HTML -d text="<b>Alert</b> - Temperature: <b>$temp_value</b>°C %26lt; lower_bound = ${output_values[0]}°C" > /dev/null
			fi
		fi	
	else
		# Insert the current temperature in the rrd database
		rrdupdate $RRD_DB -t tmp N:$temp_value
	fi

	# Send a danger alert if the current temperature override the maximum limit
	if [ $(echo "$temp_value > $MAX_LIMIT" | bc -l) -eq 1 ]; then
		curl -s -X POST https://api.telegram.org/bot$TOKEN/sendMessage -d chat_id=$CHAT_ID -d parse_mode=HTML -d text="<b>DANGER</b> : Temperature: <b>$temp_value</b>°C %26gt; LIMIT = <b>$MAX_LIMIT</b>°C" > /dev/null
	fi

	# Creates the temperature graph for the last 60 minutes 
	rrdtool graph $GRAPH_PATH/temp_graph_1h.png \
	DEF:tmp=$RRD_DB:tmp:AVERAGE \
	DEF:pre=$RRD_DB:pre:AVERAGE \
	DEF:low=$RRD_DB:low:AVERAGE \
	DEF:upp=$RRD_DB:upp:AVERAGE \
	LINE1:tmp#55e6c1:Temperature \
	LINE1:pre#54a0ff:Prediction \
	LINE1:upp#ee5253:Upper_bound \
	LINE1:low#576574:Lower_bound \
	HRULE:$MAX_LIMIT#a29bfe:Max_limit \
	-s -1h -e +5min --vertical-label "temperature (°C)" --title "1 hour" -w 500 -h 200 > /dev/null

	# Creates the temperature graph for the last 7 days
	rrdtool graph $GRAPH_PATH/temp_graph_7d.png \
		DEF:tmp=$RRD_DB:tmp:AVERAGE \
		DEF:pre=$RRD_DB:pre:AVERAGE \
		DEF:low=$RRD_DB:low:AVERAGE \
		DEF:upp=$RRD_DB:upp:AVERAGE \
		LINE1:tmp#55e6c1:Temperature \
		LINE1:pre#54a0ff:Prediction \
		LINE1:upp#ee5253:Upper_bound \
		LINE1:low#576574:Lower_bound \
		HRULE:$MAX_LIMIT#a29bfe:Max_limit \
		-s -7d --vertical-label "temperature (°C)" --title "7 days" -w 500 -h 200 > /dev/null

	# Sleep for 5 min
	sleep 300
done
