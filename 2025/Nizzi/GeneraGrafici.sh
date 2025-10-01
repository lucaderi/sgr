#!/bin/bash

# Grafico ultima ora
rrdtool graph scan-1h.png --start end-3600 --end now \
  DEF:syn=scan.rrd:syn:MAX \
  LINE1:syn#00FF00:"SYN ultima ora"

# Grafico ultimo giorno
rrdtool graph scan-1g.png --start end-86400 --end now \
  DEF:syn=scan.rrd:syn:MAX \
  LINE1:syn#0000FF:"SYN ultimo giorno"
