#! /bin/bash

db=networkdata.rrd
img=networkdata.png

while true; do

	if [ -f $db ]; then
		rrdtool graph $img -s -2000s -t "Bytes received" -z \
			-h 200 -w 2000 -l 0 -a PNG \
			DEF:in=$db:in:AVERAGE \
			"LINE:in#b5bd68" > /dev/null
	fi

	sleep 5s
done
