#!/bin/bash

RRD_FILES=$(ls *.rrd)
for X in $RRD_FILES;
do
X=${X%\.rrd};
echo "Generating "$X"_proto.png from "$X".rrd";
rrdtool graph $X\_proto.png --start -80h -E -t "Traffic (by protos)" --vertical-label Bps -w 800 -h 200 DEF:Tcp=$X.rrd:Tcp:AVERAGE DEF:Udp=$X.rrd:Udp:AVERAGE DEF:Oth=$X.rrd:Udp:AVERAGE AREA:Udp#0000ff:"Udp":STACK AREA:Oth#ff0000:"Other":STACK AREA:Tcp#00ff00:"Tcp":STACK

echo "Generating "$X".png from "$X".rrd";
	       rrdtool graph $X.png --start -80h -E -t "Traffic" --vertical-label bps -w 800 -h 200 DEF:Bytes=$X.rrd:Bytes:AVERAGE CDEF:Bits=Bytes,8,* DEF:BytesPeak=$X.rrd:Bytes:MAX CDEF:BitsPeak=BytesPeak,8,* LINE2:Bits#00ff00:"Traffic" LINE1:BitsPeak#00ff00:"Traffic Peak":dashes=2,2

done
