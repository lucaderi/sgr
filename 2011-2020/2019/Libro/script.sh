#!/bin/bash
# Help function
function help { 
	echo "---------------------------HELP---------------------------"
	echo "COMMAND   : $0 ip label"
	echo "ip        : indirizzo ip influx db"
	echo "label     : parola chiave o label del container"
	echo "----------------------------------------------------------"
	exit
}
# Check indirizzo ip
function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}
# Verifico presenza parametro IP INFLUX
if [ $# -lt 2 ]
then 
	echo "parametro ip_influx_db o label_pod mancante";
	help;
	exit;
fi;
if ! valid_ip $1; then echo "IP NON VALIDO";exit; fi;
# Imposto label container stats
pod_label=$2;
# Recupero informazioni pod in esecuzione
cmd=`microk8s.kubectl get pods --field-selector=status.phase=Running | grep "Running"`
lista=$cmd;
unixTimeStamp=$(date +%s);
# Se lista vuota esco
if [ ${#lista} == 0 ]
then
	echo "Nessun pod attivo, chiusura app";
	exit;
fi;
#stats_filename=$(echo 'stats/stat_'${unixTimeStamp}'.txt');
stats_filename='/dev/null';
# Recupero lista di interfacce veth nel sistema host
cmd=`ls /sys/class/net | grep "veth"`;
veth_list=$cmd;
# Creo vettore associativo per interfaccia e veth
declare -A index_to_virtual_iface;
# per ogni veth aggiungo la coppia al vettore associativo
for iface in $veth_list
do
	# Recupero indice dell'interfaccia e lo uso come chiave vett associativo
	index_to_virtual_iface[$(cat /sys/class/net/${iface}/ifindex)]=$iface;
done
# Stampo visualizzazione
echo "Container    Pod     Replica  Interfaccia";
#echo "{" >> $stats_filename;
contatore=1;
# Per ogni stringa nel risultato 
for nome in $lista
do
	# Recupero nome pod
	nome_pod=$(echo $nome | grep $pod_label);
	if [ ${#nome_pod} != 0 ]
	then
		# recupero indice del pod
		temp=$(microk8s.kubectl exec -it ${nome_pod} --namespace=default cat /sys/class/net/eth0/iflink);
		indice="$(echo -e "${temp}" | tr -d '[:space:]')"
		# recupero interfaccia da vett associativo
		interfaccia=${index_to_virtual_iface[$indice]};
		# stats rx
		rx=`ifconfig | awk '/'$interfaccia'/,/collisions/' | grep "RX" | grep ")"`
		# stats rx
		tx=`ifconfig | awk '/'$interfaccia'/,/collisions/' | grep "TX" | grep ")"`
		# separazione info rx e tx
		byte_rx=$(echo $rx | cut -d' ' -f 5);
		pkt_rx=$(echo $rx | cut -d' ' -f 3);
		byte_tx=$(echo $tx | cut -d' ' -f 5);
		pkt_tx=$(echo $tx | cut -d' ' -f 3);
		# separazione info container
		container=$(echo $nome_pod | cut -d'-' -f 1)
		pod=$(echo $nome_pod | cut -d'-' -f 2)
		replica=$(echo $nome_pod | cut -d'-' -f 3)
		echo $container $pod $replica $interfaccia $rx $tx;
		# Invio dati su influx
		ris=$(curl -s -i -XPOST 'http://'$1':8086/write?db=k8s' --data-binary 'traffic,container='$container',pod='$pod',replica='$replica',interface='$interfaccia' byte_tx='$byte_tx',packet_tx='$pkt_tx',byte_rx='$byte_rx',packet_rx='$pkt_rx > /dev/null);
		echo "";
		# STAMPA SU JSON DELLE STATISTICHE
		#if [ $contatore -gt 1 ]
		#	then 
		#		echo }, >> $stats_filename;
		#fi;
		#echo '"'$indice'" : {' >> $stats_filename;
		#echo '"container" : "'${container}'",' >> $stats_filename;
		#echo '"pod" : "'$pod'",'  >> $stats_filename;
		#echo '"replica" : "'$replica'",'  >> $stats_filename;
		#echo '"interfaccia" : "'$interfaccia'",' >> $stats_filename;
		#echo '"ricevuti" : {'  >> $stats_filename;
		#	echo '"pkt" : "'$pkt_rx'",' >> $stats_filename;
		#	echo '"bytes" : "'$byte_rx'"' >> $stats_filename;
		#echo }, >> $stats_filename;
		#echo '"trasmessi" : {'  >> $stats_filename;
		#	echo '"pkt" : "'$pkt_tx'",'>> $stats_filename;
		#	echo '"bytes" : "'$byte_tx'"'>> $stats_filename;
		#echo }, >> $stats_filename;
		#echo '"time" : "'$(date)'"' >> $stats_filename;
		#let "contatore+=1";
	fi;
done
#echo "}" >> $stats_filename;
#echo "}" >> $stats_filename;