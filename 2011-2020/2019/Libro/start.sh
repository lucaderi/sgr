# @file: start.sh
# @author: Pietro Libro 545559
# @email: libropiero@gmail.com
#!/bin/bash
# --- https://127.0.0.1:16443/api/v1/namespaces/kube-system/services/monitoring-grafana/proxy
# --- sudo nano /var/snap/microk8s/current/credentials/basic_auth.csv
# INIZIALIZZAZIONE MICROK8S 
sudo microk8s.start
microk8s.enable dns dashboard
echo "Attendo 35 secondi affinche influx e grafana siano partiti";
sleep 35;
# Recupero ip influx db
ricerca=`kubectl get services --all-namespaces | grep "influx"`;
doricerca=$ricerca;
if [ ${#doricerca} == 0 ]
then
	echo 'influx non presente';
	exit;
fi;
count=1;
ipinflux='0.0.0.0';
for elem in $doricerca
do
	if [ $count -eq 4 ] 
	then
		ipinflux=$elem;
	fi;
	let "count+=1";	
done;
echo "IP influx DB" $ipinflux;
# Apertura browser web consultazione grafana
xdg-open https://127.0.0.1:16443/api/v1/namespaces/kube-system/services/monitoring-grafana/proxy
# Attesa creazione DB in caso non esistente
sleep 5;
# Avvio container per generazione traffico
microk8s.kubectl create -f yaml/traffic1.yaml
microk8s.kubectl create -f yaml/traffic2.yaml
microk8s.kubectl create -f yaml/traffic3.yaml
# Attesa avvio pod
sleep 5;
# Avvio script
watch -n 1 ./script.sh ${ipinflux} traffic
# Cancellazione deploy
microk8s.kubectl delete deployment downloadtraffic1
microk8s.kubectl delete deployment downloadtraffic2
microk8s.kubectl delete deployment pingtraffic
# Terminazione
sudo microk8s.stop