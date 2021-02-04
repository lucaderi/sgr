# Intro

Questo semplice script realizzato in Python è stato creato per monitorare il numero di processi caricati e attivi, la Ram occupata e la Ram libera di un sistema operativo Windows su cui è stata abilitata la funzionalità snmp (non attiva di defalut su Windows 10 Pro)

# Installazione
Per poter utilizzare il software è necessario installare i seguenti pacchetti:
- Python 3.9
- easysnmp
- rrdtool
con i seguenti comandi bash:

```bash
sudo apt-get install libsnmp-dev snmp-mibs-downloader gcc python-dev
pip3 install easysnmp
pip3 install rrdtool
```
Lo script utilizza il Mib HOST-RESOURCES-MIB (.1.3.6.1.2.1.25)
Inoltre per evitare errori come:
```bash
easysnmp.exceptions.EASYSNMPUnknownObjectIDError: unknown object id (hrStorageSize)
```
Bisognerà andare a modificare il file in "/etc/snmp/snmp.conf" aprendolo con un editor di testo e modificare la riga "mibs: "e commentandola
da:
```bash
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
mibs : 
```
a:
```bash
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
#mibs : 
```
Il mib in questione offre una serie di OID che permenttono il monitoraggio delle risorse hardware di un agent; tra i tanti ci sono quelli che  permettono di monitorare lo spazio di archiviazione, spazio occupato in memoria, ram totale e numero di processi "Caricati e attivi".

# Utilizzo
Per avviarlo basta digitare il comando:
```bash
python3 snmp_monitor_RamProcesses.py [hostname] [community]
```
Dove hostname è l'host target del monitoraggio e community è la community SNMP, a quel punto compariranno alcune statistiche sul terminale quali:
```bash
--> Informazioni sistema operativo: Stringa
--> Numero di utenti presenti sul sistema operativo: integer
--> Data del sistema: AAAA-MM-GG HH:MM:SS.mmmmmm
--> Ram totale del sistema: in Gb
--> Spazio totale su disco: in Gb
--> Spazio occupato su disco: in Gb
```
Per monitorare il numero dei processi attivi basterà andare nella cartella reports,generata dal programma nella stessa directory in cui si trova lo script, e aprire i files .png corrispondenti alle metriche:

Grafico per la Ram utilizzata:

![alt text](https://github.com/irfanto05/Fantozzi/blob/main/ram_graph.png)

Grafico per i Processi caricati e in esecuzione:

![alt text](https://github.com/irfanto05/Fantozzi/blob/main/process_graph.png)

Grafico per la Ram libera:

![alt text](https://github.com/irfanto05/Fantozzi/blob/main/freeRam_graph.png)

# Sviluppo e testing
Lo script è stato realizzato con Gedit 3.38.0 su sistema operativo Ubuntu 20.10, eseguito su macchina virtuale Oracle Virtualbox 6.1;  ed è stato testato monitorando un agent su cui è installato Windows 10 Pro.
Per abilitare il servizio snmp su Windows 10 seguire i seguenti steps:
- Fare click su "Start"
- Cliccare su "Impostazioni""
- Clicare su "App"
- Selezionare sulla destra "App e Funzionalità"
- Sulla sinistra di "App e Funzionalità" cliccare su "Funzionalità facoltative"
- Cercare nell'elenco Simple Network Management Protocol e attendere l'installazione

Una volta che il servizio sarà abilitato bisognerà configurarlo:

- Fare click su "Start"
- Digitare "Servizi" e cliccarci
- Cercare "Servizio SNMP" nell'elenco
- Fare click destro col mouse
- Selezionare "proprietà"
- Nella sezione "Sicurezza" disattivare la spunta "Invia Trap di autenticazione"
- Sempre nella sezione "Sicurezza" cliccare sul tasto "aggiungi" sotto "Community" 
- Nella finestra selezionare i diritti (minimo solo lettura)
- Digitare il nome della community che si vuole attribuire (da usare poi come input al parametro communuty dello script)
- Cliccare su "aggiungi"
- Cliccare su "applica"
- Chiudere le proprietà e cliccare nuovamente col tasto destro del mouse su "Servizio SNMP"
- Cliccare su "Riavvia"

Fatta tutta la condivisione sarà possibile eseguire lo script e monitorare i dati
