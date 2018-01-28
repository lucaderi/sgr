while [ 1 ] ; do
	echo "updating load.."
	echo ""
	#estraiamo il carico dell'ultimo minuto
	CURLOAD=`cat /proc/loadavg | cut -f 1 -d \ `
	#memorizziamo il valore ottenuto
	rrdtool update /var/www/loadav.rrd N:$CURLOAD
	#diamo qualche informazione a video
	CURTIMEIS=`date`
	echo "updated at "$CURTIMEIS" with "$CURLOAD
	echo ""
	#attendiamo 10 secondi prima di ripetere il tutto
	sleep 10s
	rrdtool graph /var/www/graph/loadav.png DEF:load=/var/www/loadav.rrd:load:AVERAGE AREA:load#0000ff:Load --start -15m
done
