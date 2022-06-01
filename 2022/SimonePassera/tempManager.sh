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

while true; do
	temp_value=$(snmpget -v1 -c $COMMUNITY $HOSTNAME nsExtendOutputFull.\"temp\" | cut -f 4 -d " ")
	rrdtool update $FILE N:$temp_value

	sleep 300
done

#rrdtool graph temp_graph.png DEF:tmp=temp_db.rrd:tmp:AVERAGE LINE1:tmp#00ff00:Temperature --start -1h
