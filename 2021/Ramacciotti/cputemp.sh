#!/bin/bash
if [ "$1" = "-g" ]
then
	echo .1.3.6.1.2.1.25.1.0
	echo integer
    echo $(($(cat /sys/class/thermal/thermal_zone7/temp) / 1000))
fi
exit 0
