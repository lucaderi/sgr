//Progetto RETI
Simple Network monitor

**PREMESSA**
Il software preleva le metriche di rete direttamente dai file di sistema /sys/class/net , quindi funzionerà solo nelle distro di linux che utilizzano tali file. (Software scritto e testato su ubuntu 17.04).


**REQUISITI**
1) Installazione di ingluxdb , con il quale il software comunica.
	(Per ubuntu)
	wget https://dl.influxdata.com/influxdb/releases/influxdb_1.3.1_amd64.deb
	sudo dpkg -i influxdb_1.3.1_amd64.deb

2) Preparazione file di configurazione per il monitor "Config.txt" , dove è possibile sceglere la frequenza,il numero di punti da prelevare e le interfacce da controllare(Di default 50 punti, uno ogni 5 secondi , tutte le interfacce)

**PER ESEGUIRE**
3)Eseguire l'influxdb in modalità superutente :
	sudo influxd
4)Eseguire il jar "Progetto.jar"
	java -jar Progetto.jar

Una volta in esecuzione verranno stampati i dati che vengono mandati al database, ed infine viene fatta una query al DB per vederne i risultati.


Inoltre opzionalmente è possibile installare anche chronograf per visualizzare grafici sui dati che arrivano al DB.
