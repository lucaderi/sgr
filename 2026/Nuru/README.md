# Bandwidth Monitor per-host con RRDtool

**Nome e Cognome:**  Sourov Nuru 
**Email:**  s.nuru@studenti.unipi.it

----------

# 1. Descrizione del progetto

Il progetto consiste nella realizzazione di un sistema di monitoraggio del traffico di rete in tempo reale, sviluppato in Python, in grado di analizzare il traffico generato dalla macchina locale verso host esterni.

L'obiettivo principale è raccogliere statistiche sul traffico di rete aggregandole per indirizzo IP remoto, invece che per singolo flusso di rete. Per ogni host monitorato vengono raccolte informazioni relative al numero di byte trasferiti, al numero di pacchetti, alla direzione del traffico (upload/download) e alla distribuzione del traffico per protocollo.

Il sistema utilizza:

-   **Scapy**  per la cattura dei pacchetti di rete;
    
-   **psutil**  per il rilevamento delle interfacce e degli indirizzi IP locali;
    
-   **RRDtool**  per la memorizzazione delle serie temporali e la generazione dei grafici.
    

Il monitor è organizzato in due componenti principali:

1.  Un thread di acquisizione che cattura i pacchetti tramite Scapy.
    
2.  Un thread periodico che calcola la banda corrente per ogni host e aggiorna i database RRD.
    

Il traffico analizzato riguarda esclusivamente le comunicazioni:

-   macchina locale → host esterno (upload);
    
-   host esterno → macchina locale (download).
    

I pacchetti tra due host esterni o tra due host locali vengono ignorati per ridurre il numero di elementi monitorati.

----------

# 2. Architettura del sistema

Il funzionamento generale del programma è il seguente:

```
Pacchetti di rete
        |
        v
 Scapy sniff()
        |
        v
 Processamento pacchetto
        |
        v
 Aggregazione statistiche per IP
        |
        v
 Calcolo banda
        |
        v
 Aggiornamento database RRD
        |
        v
 Generazione grafici PNG

```

Le statistiche vengono mantenute tramite una struttura dati associata a ogni host remoto.

Per ogni host vengono memorizzati:

-   indirizzo IP;
    
-   byte totali trasferiti;
    
-   pacchetti totali;
    
-   byte ricevuti;
    
-   byte inviati;
    
-   byte suddivisi per protocollo;
    
-   tempo del primo e ultimo pacchetto osservato;
    
-   banda corrente.
    

----------

# 3. Cattura e analisi dei pacchetti

La cattura dei pacchetti viene effettuata tramite Scapy.

Ogni pacchetto catturato viene analizzato attraverso una callback che:

1.  verifica la presenza dell'header IP;
    
2.  identifica indirizzo IP sorgente e destinazione;
    
3.  determina se gli indirizzi appartengono alla macchina locale;
    
4.  classifica il traffico come upload o download;
    
5.  aggiorna le statistiche dell'host corrispondente.
    

Esempio:

Se viene catturato un pacchetto:

```
192.168.1.50  --->  8.8.8.8

```

dove  `192.168.1.50`  è l'indirizzo locale:

-   l'host monitorato sarà  `8.8.8.8`;
    
-   il traffico verrà classificato come upload;
    
-   verranno incrementati i contatori  `bytes_out`.
    

Nel caso opposto:

```
8.8.8.8  ---> 192.168.1.50

```

il traffico verrà classificato come download.

----------

# 4. Aggregazione per host

A differenza di un monitor basato sui flussi a 5-tupla, il progetto aggrega i dati per indirizzo IP.

La chiave utilizzata è:

```
IP remoto

```

Questo permette di rispondere a domande come:

-   Quale host genera più traffico?
    
-   Quanto traffico sto ricevendo da un determinato server?
    
-   Quali protocolli utilizza maggiormente un host?
    

Per ogni host viene mantenuta una struttura  `HostStats`  contenente tutti i contatori necessari.

La struttura utilizza  `__slots__`  per ridurre il consumo di memoria evitando la creazione automatica del dizionario degli attributi (`__dict__`) per ogni istanza.

----------

# 5. Classificazione dei protocolli

Ogni pacchetto viene classificato in base al protocollo di trasporto:

-   TCP;
    
-   UDP;
    
-   ICMP;
    
-   altri protocolli.
    

I byte trasferiti vengono memorizzati in un array:

```
proto_bytes = [
    TCP,
    UDP,
    ICMP,
    OTHER
]

```

Questo permette di ottenere statistiche sul tipo di traffico generato da ciascun host.

----------

# 6. Memorizzazione tramite RRDtool

Per ogni host viene creato un database RRD dedicato.

Esempio:

```
host_8_8_8_8.rrd

```

Ogni database contiene due Data Source:

-   `bytes_in`: banda ricevuta dall'host;
    
-   `bytes_out`: banda inviata verso l'host.
    

I valori salvati rappresentano direttamente una velocità in byte/sec, quindi viene utilizzato il tipo:

```
GAUGE

```

La frequenza di aggiornamento è definita tramite  `STATS_INTERVAL`.

----------

# 7. Archivi RRD

RRDtool utilizza diversi archivi per mantenere dati con differenti risoluzioni temporali.

Sono stati configurati quattro archivi:

## Ultima ora

Risoluzione:

```
5 secondi

```

per mantenere informazioni dettagliate sul traffico recente.

## Ultime 24 ore

Risoluzione:

```
1 minuto

```

ottenuta aggregando 12 campioni da 5 secondi.

## Ultimo anno

Risoluzione:

```
1 ora

```

ottenuta aggregando 720 campioni.

## Picchi di traffico

Un archivio aggiuntivo salva il valore massimo raggiunto per individuare eventuali picchi.

Questa tecnica permette di mantenere dimensioni del database costanti evitando una crescita illimitata dei dati.

----------

# 8. Generazione dei grafici

Il programma permette di generare grafici PNG tramite RRDtool.

Per ogni host viene creato un grafico contenente:

-   traffico in ingresso;
    
-   traffico in uscita;
    
-   valore medio;
    
-   valore massimo.
    

Esempio:

```
host_8_8_8_8_1h.png

```

rappresenta il traffico dell'host  `8.8.8.8`  nell'ultima ora.

----------

# 9. Modalità di utilizzo

## Visualizzazione delle interfacce disponibili

Comando:

```bash
python3 bandwidth_monitor.py --list-interfaces

```

Mostra le interfacce di rete disponibili.

----------

## Avvio del monitoraggio

Esempio:

```bash
sudo python3 bandwidth_monitor.py -i en0

```

Avvia la cattura sulla interfaccia  `en0`.

----------

## Utilizzo di un filtro BPF

Esempio:

```bash
sudo python3 bandwidth_monitor.py -i en0 -f "tcp port 443"

```

Analizza solamente traffico HTTPS.

----------

## Generazione grafici

Esempio:

```bash
python3 bandwidth_monitor.py --graph

```

Genera grafici dai database RRD già presenti.

Per un periodo specifico:

```bash
python3 bandwidth_monitor.py --graph --period 6h

```

----------

# 10. Prerequisiti

Per eseguire il progetto sono necessari:

-   Python 3;
    
-   Scapy;
    
-   psutil;
    
-   RRDtool.
    

Installazione delle dipendenze Python:

```bash
pip install scapy psutil

```

Installazione RRDtool:

macOS:

```bash
brew install rrdtool

```

Linux:

```bash
sudo apt install rrdtool

```

------
# 11. Test effettuati e file di esempio

Per verificare il corretto funzionamento del progetto sono stati eseguiti i seguenti test:

-   cattura del traffico di rete durante la navigazione web;
-   verifica dell'aggregazione delle statistiche per host remoto;
-   verifica della distinzione tra traffico in upload e download;
-   verifica della classificazione dei protocolli (TCP, UDP, ICMP e altri);
-   verifica della creazione automatica dei database RRD;
-   verifica dell'aggiornamento periodico dei valori memorizzati nei database;
-   verifica della generazione dei grafici PNG tramite RRDtool.

## Cartella `rrd_data`

Nel repository è presente la cartella `rrd_data`, che contiene due database RRD di esempio e i rispettivi grafici PNG generati dal programma.

Questi file hanno lo scopo di mostrare il formato dei dati prodotti dal monitor e permettono di verificare il corretto funzionamento della fase di generazione dei grafici senza dover necessariamente eseguire una nuova cattura del traffico.

I file possono essere utilizzati, ad esempio, eseguendo il comando:

```
python3 bandwidth_monitor.py --graph
```

oppure

```
python3 bandwidth_monitor.py --graph --period 30m
```

che rigenera i grafici utilizzando i database RRD presenti nella cartella.
