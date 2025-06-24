#!/bin/bash

# Nome dei file RRD
RRD1="test/1.rrd"
RRD2="test/2.rrd"
RRD3="test/3.rrd"
RRD4="test/4.rrd"
RRD5="test/5.rrd"

# Intervallo di step in secondi (5 minuti)
STEP=5

# Crea i file RRD
rrdtool create "$RRD1" \
--start now --step $STEP \
DS:traffic_out:COUNTER:600:0:U \
RRA:AVERAGE:0.5:1:288

rrdtool create "$RRD2" \
--start now --step $STEP \
DS:traffic_out:COUNTER:600:0:U \
RRA:AVERAGE:0.5:1:288

rrdtool create "$RRD3" \
--start now --step $STEP \
DS:traffic_out:COUNTER:600:0:U \
RRA:AVERAGE:0.5:1:288

rrdtool create "$RRD4" \
--start now --step $STEP \
DS:traffic_out:COUNTER:600:0:U \
RRA:AVERAGE:0.5:1:288

rrdtool create "$RRD5" \
--start now --step $STEP \
DS:traffic_out:COUNTER:600:0:U \
RRA:AVERAGE:0.5:1:288

# Timestamp iniziale (adesso, arrotondato allo step più vicino)
START=$(date +%s)
START=$((START - (START % STEP)))

echo "Inserimento dati a partire da: $START"

# Inserisce 10 entry con valori simili
for i in {0..50}; do
  T=$(($START + $STEP * $i))

  # Valori iface1
  OUT1=$((2000000 + $i * 700))

  # iface2 con una piccola variazione casuale
  OUT2=$(($OUT1 + RANDOM % 70))

  #same per iface3 e 4

  OUT3=$((100000 + $i * 500))

  OUT4=$(($OUT3 + RANDOM % 100))

  #metto una if totalmente uguale

  OUT5=$OUT2

  echo "[$T] iface1: $OUT1 | iface2: $OUT2 | iface3: $OUT3 | iface4: $OUT4 | iface5: $OUT5"

  # Update dei file RRD
  rrdtool update "$RRD1" "$T:$OUT1"
  rrdtool update "$RRD2" "$T:$OUT2"
  rrdtool update "$RRD3" "$T:$OUT3"
  rrdtool update "$RRD4" "$T:$OUT4"
  rrdtool update "$RRD5" "$T:$OUT5"

done

echo "Creazione completata. File: $RRD1 e $RRD2 e $RRD3 e $RRD4 e $RRD5"

