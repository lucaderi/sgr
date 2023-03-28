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

## Scelte implementative 

È stato scelto di utilizzare SES per generare gli allarmi senza dipendere da una seasonality e basandoci solo sugli ultimi dati letti. Questo permette di avere un forecast più generico per una serie stazionaria come il monitoring di cpu usage di un utente durante un utilizzo normale del computer.

Utilizzare il SES ci limita a poter rilevare anomalie quali utilizzo improvviso della cpu/ram oppure semplicemente un utilizzo eccessivo di queste risorse. 
Il Progetto è stato testato durante un utilizzo normale del pc e poi durante una fase di stress. Durante l’utilizzo normale i valori monitorati rientravano nei bound generati grazie all’utilizzo di SES e quindi non sono stati generati allarmi. Durante la fase di stress invece, all’inizio di questa, dato l’improvviso aumento dei valori monitorati questi hanno superato i bound stimati e sono stati generati gli apposite allarmi. Gli allarmi vengono generati correttamente anche dopo aver superato il threshold di utilizzo indicato nei files di configurazione.

Per quanto riguarda i valori scelti per l’utilizzo del SES (alpha e ro) è stato scelto un valore di smoothing alpha di 0.5 perché testando il codice con valori più piccoli il fitting dei dati era meno preciso. Per Ro, valore necessario per il calcolo della confidence, è stato scelto un valore di 2.5 per non rendere il rilevamento di anomalie troppo sensibile.

## Esempio di esecuzione

![d1](https://i.imgur.com/VzKgX4V.png)

Dalla console è possibile vedere la percentuale dell'uso della cpu e i valori del grafico di Prometheus corrispondo ai valori letti.

![d2](https://i.imgur.com/0gKy2kZ.png)

La percentuale della cpu Usage è maggiore del 70% come è possibile vedere dalla console e l'alert corrispondente è in stato di Firing.

![d3](https://i.imgur.com/hh9NkgF.png)
![d4](https://i.imgur.com/Q8zP2xn.png)

Grazie all'espressione cpu < cpuLow (espressione di Prometheus per visualizzare solo I momenti in cui il valore della cpu era inferiore al valore calcolato con SES del lower bound) è possibile visualizzare quando si è verificata l'anomalia, dall'immagine è possibile vedere che la notifica su telegram arriva correttamente e al momento giusto.

![d5](https://i.imgur.com/tp5mCMu.png)

Dal terminale è possibile vedere che l'utilizzo della cpu era molto maggiore di quello previsto (27% cpu usage e 23.2 % quello predicted). 


### Utilizzo effettivo per 7 ore.

Cpu usage:

![d6](https://i.imgur.com/MNNOgjF.png)

Cpu sopra upperbound (solo in 3 momenti):

![d7](https://i.imgur.com/1OtLR2G.png)

Cpu sotto il lowerbound:

![d8](https://i.imgur.com/4GVoMiE.png)
![d9](https://i.imgur.com/wr7QUWX.png)

Ram:

![d9](https://i.imgur.com/GIgxXTH.png)
