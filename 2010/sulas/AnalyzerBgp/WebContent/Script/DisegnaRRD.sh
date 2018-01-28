#!/bin/bash

# crea vari grafici in base ai valori letti

dir=$1

rrdtool graphv ./webapps/AnalyzerBgp/Data/$dir/pac.png \
--end now --start end-14400 \
--title="Packets" \
--vertical-label="pac" \
--height 200 \
DEF:pacLine=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nPach:MAX \
DEF:pac5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nPach:MAX:start=N-600 \
DEF:pac4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nPach:MAX:start=N-14400 \
VDEF:pRicev=pac5min,MAXIMUM \
VDEF:pMedia=pac4ore,AVERAGE \
DEF:updLine=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nUpda:MAX \
DEF:upd5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nUpda:MAX:start=N-600 \
DEF:upd4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nUpda:MAX:start=N-14400 \
VDEF:uRicev=upd5min,MAXIMUM \
VDEF:uMedia=upd4ore,AVERAGE \
DEF:kAlLine=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nKeep:MAX \
DEF:kAl5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nKeep:MAX:start=N-600 \
DEF:kAl4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nKeep:MAX:start=N-14400 \
VDEF:kRicev=kAl5min,MAXIMUM \
VDEF:kMedia=kAl4ore,AVERAGE \
DEF:othLine=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:others:MAX \
DEF:oth5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:others:MAX:start=N-600 \
DEF:oth4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:others:MAX:start=N-14400 \
VDEF:oRicev=oth5min,MAXIMUM \
VDEF:oMedia=oth4ore,AVERAGE \
LINE1:pacLine#000000:"packets    " \
GPRINT:pRicev:"recived\: %3.0lf " \
GPRINT:pMedia:"average\: %3.0lf packets" \
COMMENT:"\l" \
LINE1:updLine#00cc66:"updates    " \
GPRINT:uRicev:"recived\: %3.0lf " \
GPRINT:uMedia:"average\: %3.0lf packets" \
COMMENT:"\l" \
LINE1:kAlLine#cc0000:"keep alive " \
GPRINT:kRicev:"recived\: %3.0lf " \
GPRINT:kMedia:"average\: %3.0lf packets" \
COMMENT:"\l" \
LINE1:othLine#9900cc:"others     " \
GPRINT:oRicev:"recived\: %3.0lf " \
GPRINT:oMedia:"average\: %3.0lf packets" \
COMMENT:"\l" \
COMMENT:"\l";


rrdtool graphv ./webapps/AnalyzerBgp/Data/$dir/req.png \
--end now --start end-14400 \
--title="Update requests" \
--vertical-label="req" \
--height 200 \
DEF:upd=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:updReq:MAX \
DEF:upd5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:updReq:MAX:start=N-600 \
DEF:upd4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:updReq:MAX:start=N-14400 \
DEF:wit=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:witReq:MAX \
DEF:wit5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:witReq:MAX:start=N-600 \
DEF:wit4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:witReq:MAX:start=N-14400 \
VDEF:uReciv=upd5min,MAXIMUM \
VDEF:wReciv=wit5min,MAXIMUM \
VDEF:uMedia=upd4ore,AVERAGE \
VDEF:wMedia=wit4ore,AVERAGE \
LINE1:upd#ff0000:"update Request" \
GPRINT:uReciv:"recived\: %3.0lf " \
GPRINT:uMedia:"average\: %3.0lf request" \
COMMENT:"\l" \
LINE1:wit#00ff00:"withdr Request" \
GPRINT:wReciv:"recived\: %3.0lf " \
GPRINT:wMedia:"average\: %3.0lf request" \
COMMENT:"\l" \
COMMENT:"\l";


rrdtool graphv ./webapps/AnalyzerBgp/Data/$dir/oth.png \
--end now --start end-14400 \
--title="Others (details)" \
--vertical-label="pac" \
--height 200 \
DEF:oth=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:others:MAX \
DEF:oth5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:others:MAX:start=N-600 \
DEF:oth4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:others:MAX:start=N-14400 \
DEF:ope=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nOpen:MAX \
DEF:ope5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nOpen:MAX:start=N-600 \
DEF:ope4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nOpen:MAX:start=N-14400 \
DEF:nno=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nNoty:MAX \
DEF:nno5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nNoty:MAX:start=N-600 \
DEF:nno4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nNoty:MAX:start=N-14400 \
DEF:nch=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nChan:MAX \
DEF:nch5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nChan:MAX:start=N-600 \
DEF:nch4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nChan:MAX:start=N-14400 \
DEF:ntd=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nTDum:MAX \
DEF:ntd5min=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nTDum:MAX:start=N-600 \
DEF:ntd4ore=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nTDum:MAX:start=N-14400 \
VDEF:otReciv=oth5min,MAXIMUM \
VDEF:opReciv=ope5min,MAXIMUM \
VDEF:noReciv=nno5min,MAXIMUM \
VDEF:csReciv=nch5min,MAXIMUM \
VDEF:tdReciv=ntd5min,MAXIMUM \
VDEF:otMedia=oth4ore,AVERAGE \
VDEF:opMedia=ope4ore,AVERAGE \
VDEF:noMedia=nno4ore,AVERAGE \
VDEF:csMedia=nch4ore,AVERAGE \
VDEF:tdMedia=ntd4ore,AVERAGE \
LINE1:oth#9900cc:"others       " \
GPRINT:otReciv:"recived\: %4.0lf " \
GPRINT:otMedia:"average\: %4.0lf packets" \
COMMENT:"\l" \
LINE1:ope#1100ff:"open         " \
GPRINT:opReciv:"recived\: %4.0lf " \
GPRINT:opMedia:"average\: %4.0lf packets" \
COMMENT:"\l" \
LINE1:nno#ff9966:"notify       " \
GPRINT:noReciv:"recived\: %4.0lf " \
GPRINT:noMedia:"average\: %4.0lf packets" \
COMMENT:"\l" \
LINE1:nch#00ff00:"change state " \
GPRINT:csReciv:"recived\: %4.0lf " \
GPRINT:csMedia:"average\: %4.0lf packets" \
COMMENT:"\l" \
LINE1:ntd#ff0000:"table dump   " \
GPRINT:tdReciv:"recived\: %4.0lf " \
GPRINT:tdMedia:"average\: %4.0lf packets" \
COMMENT:"\l" \
COMMENT:"\l";

rrdtool graphv ./webapps/AnalyzerBgp/Data/$dir/sto.png \
--end now --start end-604800 \
--title="History" \
--vertical-label="pac & req" \
--width 600 \
DEF:pacLine=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nPach:MAX:step=1200 \
DEF:othLine=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:others:MAX:step=1200 \
DEF:updLine=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nUpda:MAX:step=1200 \
DEF:kAlLine=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nKeep:MAX:step=1200 \
DEF:pac=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nPach:MAX \
DEF:oth=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:others:MAX \
DEF:upd=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nUpda:MAX \
DEF:kAl=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:nKeep:MAX \
DEF:wReq=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:witReq:MAX \
DEF:uReq=./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd:updReq:MAX \
VDEF:w=wReq,MAXIMUM \
VDEF:u=uReq,MAXIMUM \
VDEF:pMedia=pac,AVERAGE \
VDEF:oMedia=oth,AVERAGE \
VDEF:uMedia=upd,AVERAGE \
VDEF:kMedia=kAl,AVERAGE \
AREA:pacLine#000000:"packets    " \
GPRINT:pMedia:"average\: %3.0lf packets" \
AREA:updLine#00cc66:"updates    " \
GPRINT:uMedia:"average\: %3.0lf packets \c" \
COMMENT:"\l" \
AREA:kAlLine#cc0000:"keep alive " \
GPRINT:kMedia:"average\: %3.0lf packets" \
AREA:othLine#9900cc:"others     " \
GPRINT:oMedia:"average\: %3.0lf packets \c" \
COMMENT:"\l" \
COMMENT:"\l" \
COMMENT:"\l" \
GPRINT:w:"max witdraw request\: %5.0lf " \
GPRINT:u:"max update request\: %5.0lf\c" \
COMMENT:"\l";