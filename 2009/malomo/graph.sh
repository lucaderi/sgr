#!/bin/bash

RRD_FILES=$(ls *.rrd)
for X in $RRD_FILES;
do
X=${X%\.rrd};
echo "Generating "$X"_proto.png from "$X".rrd";
    case $X in
            in_* ) INOUT_RRD=${X:3}\\n$INOUT_RRD;
	           rrdtool graph $X\_proto.png --start -80h -E -t "In Traffic (by protos)" --vertical-label Bps -w 800 -h 200 DEF:Tcp=$X.rrd:Tcp:AVERAGE DEF:Udp=$X.rrd:Udp:AVERAGE DEF:Oth=$X.rrd:Udp:AVERAGE AREA:Udp#0000ff:"Udp":STACK AREA:Oth#ff0000:"Other":STACK AREA:Tcp#00ff00:"Tcp":STACK;;
            out_* ) INOUT_RRD=${X:4}\\n$INOUT_RRD;
	            rrdtool graph $X\_proto.png --start -80h -E -t "Out Traffic (by protos)" --vertical-label Bps -w 800 -h 200 DEF:Tcp=$X.rrd:Tcp:AVERAGE DEF:Udp=$X.rrd:Udp:AVERAGE DEF:Oth=$X.rrd:Udp:AVERAGE AREA:Udp#0000ff:"Udp":STACK AREA:Oth#ff0000:"Other":STACK AREA:Tcp#00ff00:"Tcp":STACK;;
            *) rrdtool graph $X\_proto.png --start -80h -E -t "Traffic (by protos)" --vertical-label Bps -w 800 -h 200 DEF:Tcp=$X.rrd:Tcp:AVERAGE DEF:Udp=$X.rrd:Udp:AVERAGE DEF:Oth=$X.rrd:Udp:AVERAGE AREA:Udp#0000ff:"Udp":STACK AREA:Oth#ff0000:"Other":STACK AREA:Tcp#00ff00:"Tcp":STACK;
	       echo "Generating "$X".png from "$X".rrd";
	       rrdtool graph $X.png --start -80h -E -t "Traffic" --vertical-label bps -w 800 -h 200 DEF:Bytes=$X.rrd:Bytes:AVERAGE CDEF:Bits=Bytes,8,* DEF:BytesPeak=$X.rrd:Bytes:MAX CDEF:BitsPeak=BytesPeak,8,* LINE2:Bits#00ff00:"Traffic" LINE1:BitsPeak#00ff00:"Traffic Peak":dashes=2,2;;
    esac ;
done

INOUT_RRD=$(echo -e $INOUT_RRD | sort | uniq -c | grep " 2 "| cut -c 6-)

for X in $INOUT_RRD;
do
echo "Generating "$X".png from in_"$X".rrd and out_"$X".png";
rrdtool graph $X.png --start -80h -E -t "In/Out Traffic" --vertical-label bps -w 800 -h 200 DEF:inBytes=in_$X.rrd:Bytes:AVERAGE CDEF:inBits=inBytes,8,* DEF:outBytes=out_$X.rrd:Bytes:AVERAGE CDEF:outBits=outBytes,8,* DEF:inBytesPeak=in_$X.rrd:Bytes:MAX CDEF:inBitsPeak=inBytesPeak,8,* DEF:outBytesPeak=out_$X.rrd:Bytes:MAX CDEF:outBitsPeak=outBytesPeak,8,* LINE2:inBits#00ff00:"In" LINE1:inBitsPeak#00ff00:"In Peak":dashes=2,2 LINE2:outBits#ff0000:"Out" LINE1:outBitsPeak#ff0000:"Out Peak":dashes=2,2;
done
