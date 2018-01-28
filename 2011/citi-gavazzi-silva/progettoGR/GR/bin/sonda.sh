#!/bin/bash
#rrdtool create /var/www/80.rrd --start 1308143559 --step 60 DS:octet:GAUGE:70:U:U RRA:AVERAGE:0.5:1:1296000
#echo Archivio Giornaliero Creato port 80

#rrdtool create /var/www/22.rrd --start 1308143559 --step 60 DS:octet:GAUGE:70:U:U RRA:AVERAGE:0.5:1:1296000
#echo Archivio Giornaliero Creato port 22

#rrdtool create /var/www/25.rrd --start 1308143559 --step 60 DS:octet:GAUGE:70:U:U RRA:AVERAGE:0.5:1:1296000
#echo Archivio Giornaliero Creato port 25

#rrdtool create /var/www/14536.rrd --start 1308143559 --step 60 DS:octet:GAUGE:70:U:U RRA:AVERAGE:0.5:1:1296000
#echo Archivio Giornaliero Creato port 14536


#rrdtool create /var/www/0.rrd --start 1308143559 --step 60 DS:octet:GAUGE:70:U:U RRA:AVERAGE:0.5:1:1296000
#echo Archivio Giornaliero Creato Port TUTTE


sleep 3600

while true; do
java Parser 80
java Parser 22
java Parser 25
java Parser 14536
java Parser 0
java Parser 4662
java Parser 6667

echo Parser Lanciato in data: >> /var/www/logs/sonda.log
date >> /var/www/logs/sonda.log
sleep 3600
done

