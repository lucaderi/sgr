##!/bin/bash

if [ -z "$1" ]
    then
        # default is "/var/lib/ntopng/0"
        path_of_rrds="/var/lib/ntopng/0"
    else
        path_of_rrds=$1
fi

sudo find $path_of_rrds -type file -name "*.rrd" -exec python3 ~/Desktop/sgr/2022/Matricardi/skewness.py -n 30 -w 20 -p --rrd {} \;