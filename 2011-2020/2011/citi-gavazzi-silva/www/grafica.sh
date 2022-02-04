#/bin/bash

while true;do
rrdtool graph /var/www/graph/80-2h.png DEF:x=/var/www/80.rrd:octet:AVERAGE AREA:x#0000FF:x --start -2h
rrdtool graph /var/www/graph/22-2h.png DEF:x=/var/www/22.rrd:octet:AVERAGE AREA:x#0000FF:x --start -2h
rrdtool graph /var/www/graph/25-2h.png DEF:x=/var/www/25.rrd:octet:AVERAGE AREA:x#0000FF:x --start -2h
rrdtool graph /var/www/graph/14536-2h.png DEF:x=/var/www/14536.rrd:octet:AVERAGE AREA:x#0000FF:x --start -2h
rrdtool graph /var/www/graph/0-2h.png DEF:x=/var/www/0.rrd:octet:AVERAGE AREA:x#0000FF:x --start -2h
rrdtool graph /var/www/graph/4662-2h.png DEF:x=/var/www/4662.rrd:octet:AVERAGE AREA:x#0000FF:x --start -2h
rrdtool graph /var/www/graph/6667-2h.png DEF:x=/var/www/6667.rrd:octet:AVERAGE AREA:x#0000FF:x --start -2h



rrdtool graph /var/www/graph/80-1d.png DEF:x=/var/www/80.rrd:octet:AVERAGE AREA:x#0000FF:x --start -1d
rrdtool graph /var/www/graph/22-1d.png DEF:x=/var/www/22.rrd:octet:AVERAGE AREA:x#0000FF:x --start -1d
rrdtool graph /var/www/graph/25-1d.png DEF:x=/var/www/25.rrd:octet:AVERAGE AREA:x#0000FF:x --start -1d
rrdtool graph /var/www/graph/14536-1d.png DEF:x=/var/www/14536.rrd:octet:AVERAGE AREA:x#0000FF:x --start -1d
rrdtool graph /var/www/graph/0-1d.png DEF:x=/var/www/0.rrd:octet:AVERAGE AREA:x#0000FF:x --start -1d
rrdtool graph /var/www/graph/4662-1d.png DEF:x=/var/www/4662.rrd:octet:AVERAGE AREA:x#0000FF:x --start -1d
rrdtool graph /var/www/graph/6667-1d.png DEF:x=/var/www/6667.rrd:octet:AVERAGE AREA:x#0000FF:x --start -1d


rrdtool graph /var/www/graph/80-12h.png DEF:x=/var/www/80.rrd:octet:AVERAGE AREA:x#0000FF:x --start -12h
rrdtool graph /var/www/graph/22-12h.png DEF:x=/var/www/22.rrd:octet:AVERAGE AREA:x#0000FF:x --start -12h
rrdtool graph /var/www/graph/25-12h.png DEF:x=/var/www/25.rrd:octet:AVERAGE AREA:x#0000FF:x --start -12h
rrdtool graph /var/www/graph/14536-12h.png DEF:x=/var/www/14536.rrd:octet:AVERAGE AREA:x#0000FF:x --start -12h
rrdtool graph /var/www/graph/0-12h.png DEF:x=/var/www/0.rrd:octet:AVERAGE AREA:x#0000FF:x --start -12h
rrdtool graph /var/www/graph/4662-12h.png DEF:x=/var/www/4662.rrd:octet:AVERAGE AREA:x#0000FF:x --start -12h
rrdtool graph /var/www/graph/6667-12h.png DEF:x=/var/www/6667.rrd:octet:AVERAGE AREA:x#0000FF:x --start -12h


rrdtool graph /var/www/graph/80-7d.png DEF:x=/var/www/80.rrd:octet:AVERAGE AREA:x#0000FF:x --start -7d
rrdtool graph /var/www/graph/22-7d.png DEF:x=/var/www/22.rrd:octet:AVERAGE AREA:x#0000FF:x --start -7d
rrdtool graph /var/www/graph/25-7d.png DEF:x=/var/www/25.rrd:octet:AVERAGE AREA:x#0000FF:x --start -7d
rrdtool graph /var/www/graph/14536-7d.png DEF:x=/var/www/14536.rrd:octet:AVERAGE AREA:x#0000FF:x --start -7d
rrdtool graph /var/www/graph/0-7d.png DEF:x=/var/www/0.rrd:octet:AVERAGE AREA:x#0000FF:x --start -7d
rrdtool graph /var/www/graph/4662-7d.png DEF:x=/var/www/4662.rrd:octet:AVERAGE AREA:x#0000FF:x --start -7d
rrdtool graph /var/www/graph/6667-7d.png DEF:x=/var/www/6667.rrd:octet:AVERAGE AREA:x#0000FF:x --start -7d


sleep 3600

done

