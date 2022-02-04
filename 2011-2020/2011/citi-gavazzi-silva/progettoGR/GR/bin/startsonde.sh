#! /bin/bash
echo "Inizio Attivazione Processi:"
echo "Lancio di nprobe"
/root/nprobe_6.5.1_062711/.libs/lt-nprobe -b 2 -i none -3 2055 -n none -T "%L4_DST_PORT %IPV4_SRC_ADDR %IPV4_DST_ADDR %IN_PKTS %IN_BYTES %L4_SRC_PORT  %PROTOCOL %FIRST_SWITCHED %LAST_SWITCHED %HTTP_URL " -P /testnProbe/ >/dev/null & echo $! > /var/www/pids/nprobe.pid
sleep 10
echo "lanciato"
echo "Lancio la sonda RRD"
/progettoGR/GR/bin/sonda.sh > /dev/null & echo $! > /var/www/pids/sonda.pid
echo " Lancio processo Carico CPU"
/var/www/carico.sh  >/dev/null & echo $! > /var/www/pids/carico.pid
sleep 5
echo "Lancio Processo Disegno"
/var/www/grafica.sh > /dev/null & echo $! > /var/www/pids/grafica.pid



