# Introduzione
Utilizzo di uno script in python per la raccolta dell'utilizzo di CPU e RAM tramite SNMP e la memorizzazione di questi tramite Prometheus per l'analisi la generazione di allarmi. È stato Single Exponential Smoothing come algoritmo di forecast. La gestione degli allarmi viene implementata tramite Alertmanger interfacciandosi con Prometheous, questi allarmi vengono notificati tramite un bot su telegram.  
## Guida per l'installazione 
### SNMP

Per installare SNMP:
```Ubuntu
sudo apt install snmpd
sudo apt install snmp snmp-mibs-downloader
```
Per verificare la corretta installazione:
```Ubuntu
service snmpd status
```
Modificare i files `snmp.conf` e `snmpd.conf` nella cartella `/etc/snmp/` in questo modo:

[snmp.conf](/SNMP/snmp.conf)   
[snmpd.conf](/SNMP/snmpd.conf)

Potrebbe essere necessario riavviare il servizio SNMP:
```Ubuntu
service snmpd restart
```
### Prometheus

Scaricare [Prometheus](https://prometheus.io/download/). Estrarre il file .tar.gz e copiare i file [prometheus.yml](/PROMETHEUS/prometheus.yml) [prometheus_rules.yml](/PROMETHEUS/prometheus_rules.yml) all'interno della cartella estratta.

Verificare la corretta configurazione delle rules con il comando:

```Ubuntu
./promtool check rules prometheus_rules.yml
```

Dovrebbe restituire qualcosa del genere:


```Ubuntu
Checking prometheus_rules.yml
  SUCCESS: 6 rules found
```

### Alertmanager

Scaricare [Alertmanager](https://prometheus.io/docs/alerting/latest/overview/). Estrarre il file .tar.gz e copiare il file [alertmanager.yml](/ALERTMANAGER/alertmanager.yml) all'interno della cartella estratta. All'interno di questo file bisogna aggiungere il token del bot telegram e il chat id. Esempio:

```yml
- name: nomereceiver
  telegram_configs:
  - bot_token: TOKENBOT
    api_url: https://api.telegram.org
    chat_id: IDCHAT
    message: " Il tuo messaggio "
```

### Python

Assicurarsi che python3 sia installato, scaricare le librerie necessarie con i seguenti comandi:

```Ubuntu
pip install easysnmp
pip install prometheus-client
```

Scaricare lo script:

[monitor.py](/PYTHON/monitor.py)

## Utilizzo

Andare nella cartella di Prometheous e avviarlo con il seguente comando:

```Ubuntu
./prometheus --config.file=prometheus.yml
```

Il database potrebbe non avviarsi se la porta `9090` dell'host locale è già in uso.

Andare nella cartella di Alertmanager e avviarlo con il seguente comando:

```Ubuntu
./alertmanager --config.file=alertmanager.yml
```

Alertmanager potrebbe non avviarsi se la porta `9093` dell'host locale è già in uso. È possibile cambiare la porta nel file di configurazione.

Avviare lo script python:

```Ubuntu
python3 monitor.py
```
Lo script python invierà i dati a Prometheus tramite la porta `8000` quindi assicurarsi che non sia in uso.

Per accedere a Prometheus bisogna avviare il proprio browser e connettersi all'indirizzo `http://localhost:9090`. Cliccare la sezione `Graph` e scrivere quale parametro si vuole visualizzare fra: Ram, RamLow, RamUp, Cpu, CpuUP e CpuLow. Esempio del grafico della cpu:

![a](https://i.imgur.com/GvylvgR.png)

Per vedere le alert andare nella sezione `Alerts` dove è possibile vedere in che stato sono. Possono essere Inactive, Pending o Firing. Quando sono firing vengono gestite da alertmanager che notificherà il gruppo telegram. 

![ZZ](https://i.imgur.com/a0iGb2E.png)

Nella sezione `Status` e nella sottosezione `Runtime and build informaton` è possibile trovare il link per vedere lo stato dell'alertmanager.

![b](https://i.imgur.com/XBRlaZV.png)

Nella sezione `Status` e nella sottosezione `Targets` è possibile vedere le porte utilizzate da Prometheus. Se si clicca sul link con la porta `8000` è possibile vedere i valori che lo script sta trasmettendo.

![c](https://i.imgur.com/PgzWLq2.png)

Esempio dello stato dell'alertmanager durante il firing di un alert:

![bho](https://i.imgur.com/FHk4VB1.png)

Esempio di notifica su telegram:

![d](https://i.imgur.com/Bi8VorV.png)

