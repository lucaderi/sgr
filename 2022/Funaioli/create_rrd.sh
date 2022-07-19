#! /bin/bash

db=skeweddata.rrd

# delete rrd if it already exists
rm -f $db

# create db: starts 30 min ago from now;
# new data point every 1 second, each one kept for 1 hour;
# consolidated data point made from 60 primary data points
# (1 minute) and kept for 2 hours
rrdtool create $db --step=1 --start=now-1800s\
	DS:in:COUNTER:1:0:U \
	RRA:AVERAGE:0.5:1:3600 \
	RRA:AVERAGE:0.5:60:120

high=1
value=0
now=$(expr $(date "+%s") - 1800)

if [[ $1 -eq 0 ]]; then

	for i in {0..1800}; do
		high=$((RANDOM % 2))
		if [ $i -ge 1500 ]; then
			increment=$((1 + RANDOM % 10 + 20))
		elif [ $i -ge 1200 ]; then
			if [ $high -eq 1 ]; then
				increment=$((1 + RANDOM % 5 + 40))
				#high=0
			else
				increment=$((1 + RANDOM % 5 + 5))
				#high=1
			fi
		elif [ $i -ge 900 ]; then
			increment=$((1 + RANDOM % 10 + 20))
		elif [ $i -ge 600 ]; then
			if [ $high -eq 1 ]; then
				increment=$((1 + RANDOM % 5 + 40))
				#high=0
			else
				increment=$((1 + RANDOM % 5 + 5))
				#high=1
			fi
		else increment=$((1 + RANDOM % 10 + 20))
		fi

		(( value+=increment ))

		rrdtool update $db ${now}:$value
		now=$(expr ${now} + 1)
	done

elif [[ $1 -eq 1 ]]; then

	for i in {0..1800}; do
		high=$((RANDOM % 2))
		if [ $i -ge 1500 ]; then
			increment=$((1 + RANDOM % 5 + 20))
		elif [ $i -ge 1320 ]; then
			if [ $high -eq 1 ]; then
				increment=$((1 + RANDOM % 3 + 30))
				#high=0
			else
				increment=$((1 + RANDOM % 3 + 12))
				#high=1
			fi
		elif [ $i -ge 1020 ]; then
			increment=$((1 + RANDOM % 5 + 20))
		elif [ $i -ge 840 ]; then
			if [ $high -eq 1 ]; then
				increment=$((1 + RANDOM % 3 + 40))
				#high=0
			else
				increment=$((1 + RANDOM % 3 + 25))
				#high=1
			fi
		elif [ $i -ge 540 ]; then
			increment=$((1 + RANDOM % 5 + 20))
		elif [ $i -ge 360 ]; then
			if [ $high -eq 1 ]; then
				increment=$((1 + RANDOM % 3 + 17))
				#high=0
			else
				increment=$((1 + RANDOM % 3 + 2))
				#high=1
			fi
		else increment=$((1 + RANDOM % 5 + 20))
		fi

		(( value+=increment ))

		rrdtool update $db ${now}:$value
		now=$(expr ${now} + 1)
	done
fi

graph=1
img=skeweddata.png

if [ $graph -eq 1 ]; then

	rrdtool graph $img -s -2000s \
	-t "Skewed data $1" -z \
	-c "BACK#FFFFFF" -c "SHADEA#FFFFFF" -c "SHADEB#FFFFFF" \
	-c "MGRID#AAAAAA" -c "GRID#CCCCCC" -c "ARROW#333333" \
	-c "FONT#333333" -c "AXIS#333333" -c "FRAME#333333" \
	-h 200 -w 2000 -l 0 -a PNG \
	DEF:in=$db:in:AVERAGE \
	"LINE1:in#49BEEF" > /dev/null

fi
