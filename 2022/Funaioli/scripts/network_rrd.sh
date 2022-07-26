#! /bin/bash

ni=wlp2s0 
db=networkdata.rrd

if [ ! -f $db ]; then
	rrdtool create $db --step=1 --start=now-1800s\
		DS:in:COUNTER:1:0:U \
		RRA:AVERAGE:0.5:1:3600 \
		RRA:AVERAGE:0.5:60:120
fi

while true; do
	value=$(ifconfig $ni | grep 'RX packets' | cut -d "s" -f 3 | cut -d " " -f 2)
	rrdtool update $db N:$value
done
