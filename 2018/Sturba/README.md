# Simple Docker Monitor

***Simple Docker Monitor*** e' un sistema in grado di collezionare, processare ed aggregare una serie di metriche riguardanti i Docker container in esecuzione sulla macchina


## Prerequisiti
* **Java 1.8**
* **Docker**
* **Docker Remote Rest API**
* **Grafana**
* **Graphite**


## Esecuzione
1. **Assicurarsi di aver attivato la Docker Rest API ([vedi guida attivazione API](https://www.ivankrizsan.se/2016/05/18/enabling-docker-remote-api-on-ubuntu-16-04/))** 
2. **Nel file *collector.config*, sotto la voce *DOCKER_REMOTE_API_PORT* inserire la porta in cui e' attiva l'API**
3. **Eseguire lo script *init_all.sh***
4. **Accedere a Grafana(su porta 3000) per visualizzare i grafici**
