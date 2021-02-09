# Intro

Questo semplice script realizzato in Python è stato creato per monitorare il numero di processi caricati e attivi, la Ram occupata e la Ram libera di un sistema operativo Windows su cui è stata abilitata la funzionalità snmp.

# Attivare Agent SNMP su Windows 10
Per prima cosa è necessario abilitare la funzionalità SNMP sul pc che si vuole monitorare, per farlo bisogna seguire i seguenti passi:
- 1 Fare click su "Start"
- 2 Cliccare su "Impostazioni"
- 3 Clicare su "App"
- 4 Selezionare sulla destra "App e Funzionalità"
- 5 Cliccare su "Funzionalità facoltative"
- 6 Cercare nell'elenco Simple Network Management Protocol e attendere l'installazione

Una volta che il servizio sarà abilitato bisognerà configurarlo:

- 1 Fare click su "Start"
- 2 Digitare "Servizi" e cliccarci
- 3 Cercare "Servizio SNMP" nell'elenco
- 4 Fare click destro col mouse
- 5 Selezionare "proprietà"
- 6 Nella sezione "Sicurezza" disattivare la spunta "Invia Trap di autenticazione"
- 6-1 Sempre nella sezione "Sicurezza" cliccare sul tasto "aggiungi" sotto "Community" 
- 6-2 Nella finestra che si aprirà selezionare i diritti di "Lettura/scrittura"
- 6-3 Digitare il nome della community che si vuole attribuire (da usare poi come input al parametro communuty dello script)
- 6-4 Cliccare su "aggiungi"
- 7 Cliccare su "applica"
- 8 Chiudere le proprietà e cliccare nuovamente col tasto destro del mouse su "Servizio SNMP"
- 9 Cliccare su "Riavvia"

A questo punto il sistema che si vuole monitorare sarà configurato per ricevere le richieste da parte di un altro sistema su cui sarà in esecuzione lo script snmp_monitorRamProcesses.py

# Installazione su Ubuntu
Per poter utilizzare il software è necessario installare i seguenti pacchetti su Ubuntu:
- Python 3.9
- easysnmp
- rrdtool

con i seguenti comandi sulla shell:

```bash
sudo apt-get install python3 python3-pip
sudo apt-get install libsnmp-dev snmp-mibs-downloader gcc python-dev
pip3 install easysnmp
sudo apt-get install python3-rrdtool
```
Lo script utilizza i Mib HOST-RESOURCES-MIB (.1.3.6.1.2.1.25) e SNMPv2-MIB::sysDescr(.1.3.6.1.2.1.1.1)

# Utilizzo

Prima di eseguire lo script digitare il comando sulla shell:
```bash
export MIBS=ALL
```
Dopo basterà digitare:
```bash
python3 snmp_monitor_RamProcesses.py [hostname] [community]
```
Dove hostname è l'host target del monitoraggio e community è la community SNMP scelta nella configurazione dell'Agent su Windows 10, per eseguirlo è necessario inserire entrambi i parametri

Per terminare l'esecuzione dello script basterà digitare Ctrl+C (SIGINT) sulla shell in cui è in esecuzione

# Esempio di utilizzo
```bash
export MIBS=All
python3 snmp_monitor_RamProcesses.py 192.168.1.17 home
Start COLLECTING DATA at 192.168.1.17 Hardware: Intel64 Familiy 6 model......
--> System users number: 2
--> System date: 2021-02-04 15:33:12.124568
--> Total system Ram: 3.907  Gb
--> Total system storage drive: 112.645 Gb
--> Occupyed system storage: 79.733  Gb
--> For checking processes, busy Ram and free Ram in real time open the .png files whit associated names in reports/
+++++++++++++++++++++ To stop collecting press Ctrl+C ++++++++++++++
```
I grafici per Ram occupata, Ram libera e processi attivi sono nella cartella reports(generata automaticamente dallo script nella diractory in cui si trova)
Grafico per la Ram utilizzata:

![alt text](https://github.com/irfanto05/Fantozzi/blob/main/ram_graph.png)

Grafico per i Processi caricati e in esecuzione:

![alt text](https://github.com/irfanto05/Fantozzi/blob/main/process_graph.png)

Grafico per la Ram libera:

![alt text](https://github.com/irfanto05/Fantozzi/blob/main/freeRam_graph.png)


# Sviluppo e testing
Lo script è stato realizzato con Gedit 3.38.0 su sistema operativo Ubuntu 20.10, eseguito su macchina virtuale Oracle Virtualbox 6.1;  ed è stato testato monitorando un agent su cui è installato Windows 10 Pro e attivato il servizio snmp seguendo le istruzioni dell'introduzione.
