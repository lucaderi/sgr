# Bandwidth Monitor per-host con RRDtool

**Nome e Cognome:**  Sourov Nuru 
**Email:**  s.nuru@studenti.unipi.it

----------

# 1. Descrizione del progetto

Il progetto consiste nella realizzazione di un sistema di monitoraggio del traffico IPv4 e IPv6 in tempo reale, sviluppato in Python, in grado di analizzare il traffico scambiato dalla macchina locale con host esterni.

L'obiettivo principale è raccogliere statistiche sul traffico di rete aggregandole per indirizzo IP remoto, invece che per singolo flusso di rete. Per ogni host monitorato vengono raccolte informazioni relative al numero di byte trasferiti, al numero di pacchetti, alla direzione del traffico (upload/download) e alla distribuzione del traffico per protocollo.

Il sistema utilizza:

-   **Scapy**  per la cattura dei pacchetti di rete;
    
-   **psutil**  per il rilevamento delle interfacce e degli indirizzi IP locali;
    
-   **RRDtool**  per la memorizzazione delle serie temporali e la generazione dei grafici.
    

Il monitor è organizzato in tre componenti principali:

1.  Un thread di acquisizione che cattura i pacchetti tramite Scapy.
    
2.  Un thread periodico che invia a RRDtool i contatori cumulativi per ogni host e per la macchina locale. RRDtool calcola nativamente il throughput.

3.  Una dashboard web locale opzionale che genera e mostra i grafici aggiornati.
    

Il traffico analizzato riguarda esclusivamente le comunicazioni:

-   macchina locale → host esterno (upload);
    
-   host esterno → macchina locale (download).
    

I pacchetti tra due host esterni o tra due host locali vengono ignorati per ridurre il numero di elementi monitorati.

## Caso d'uso pratico

Lo strumento e' pensato per l'analisi locale di un piccolo server.
Aiuta a capire con quali host remoti comunica la macchina, quali host
consumano piu' traffico, quanto viene caricato o scaricato e quali protocolli
sono utilizzati nel tempo.

Un caso concreto e' la diagnosi di una macchina che utilizza banda in modo
inaspettato: attraverso le statistiche raccolte e la dashboard, l'amministratore
puo' osservare quali host remoti generano piu' traffico e analizzarne direzione,
volume e protocollo prevalente. Lo storico RRD consente di osservare anche
eventi gia' terminati e picchi di traffico verificatisi quando il sistema non
era controllato direttamente.

Per esempio, un picco anomalo di upload durante la notte verso un singolo
indirizzo IP remoto potrebbe indicare un backup programmato, un servizio
configurato in modo errato oppure un'attivita' che richiede ulteriori verifiche.
Il monitor non determina automaticamente la causa o la pericolosita' del
trasferimento, ma fornisce indirizzo remoto, volume, direzione, protocollo e
andamento temporale utili all'analisi.

Il monitor e' quindi utile per:

- individuare servizi o comunicazioni che generano traffico inatteso;
- confrontare upload e download della macchina locale;
- identificare gli host remoti con maggiore volume di traffico;
- osservare picchi di banda e stabilire quando si sono verificati;
- rilevare trasferimenti in upload avvenuti durante periodi insoliti, come le
  ore notturne;
- fornire informazioni iniziali per approfondire possibili anomalie di rete.

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
 Invio contatori cumulativi
        |
        v
 Aggiornamento database RRD
        |
        v
 Generazione grafici PNG
        |
        v
 Dashboard web locale

```

Le statistiche vengono mantenute tramite una struttura dati associata a ogni host remoto.

Il codice e' separato in due moduli:

- `bandwidth_monitor.py` contiene cattura, aggregazione, database RRD, grafici e CLI;
- `web_dashboard.py` contiene esclusivamente server HTTP, pagina HTML e stile della dashboard.

Per ogni host remoto e, separatamente, per la macchina locale vengono memorizzati:

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

Questo permette di ottenere statistiche correnti e serie storiche sul tipo di traffico generato da ciascun host. ICMP comprende sia ICMP per IPv4 sia ICMPv6.

----------

# 6. Memorizzazione tramite RRDtool

Per ogni host remoto viene creato un database RRD dedicato. Il file `local_host.rrd` contiene invece le statistiche complessive della macchina sulla quale gira il monitor.

Esempio:

```
host_8_8_8_8.rrd

```

Ogni database contiene sei Data Source:

-   `bytes_in`: byte cumulativi ricevuti dall'host;
    
-   `bytes_out`: byte cumulativi inviati verso l'host;

-   `proto_tcp`: byte TCP cumulativi;

-   `proto_udp`: byte UDP cumulativi;

-   `proto_icmp`: byte ICMP e ICMPv6 cumulativi;

-   `proto_other`: byte degli altri protocolli cumulativi.
    

I valori inviati sono contatori cumulativi di byte. Viene utilizzato il tipo:

```
DERIVE

```

RRDtool calcola nativamente la variazione del contatore nel tempo, producendo il throughput in byte/sec. Il limite minimo pari a zero evita valori negativi quando il programma viene riavviato. La frequenza di aggiornamento è definita tramite `STATS_INTERVAL`.

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

Per ogni host remoto e per l'host locale vengono creati due grafici. Il grafico del traffico contiene:

-   traffico in ingresso;
    
-   traffico in uscita;
    
-   valore medio;
    
-   valore massimo.

Il download è rappresentato sotto l'asse Y in blu, mentre l'upload è rappresentato sopra l'asse Y in arancione. Il secondo grafico mostra le serie storiche TCP, UDP, ICMP/ICMPv6 e altri protocolli con colori distinti.
    

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
python3 bandwidth_monitor.py -i en0

```

Avvia la cattura sulla interfaccia  `en0`.

----------

## Utilizzo di un filtro BPF

Esempio:

```bash
python3 bandwidth_monitor.py -i en0 -f "tcp port 443"

```

Analizza solamente traffico HTTPS.

Se il sistema non concede all'utente l'accesso alla cattura dei pacchetti, il
comando puo' essere eseguito con `sudo`. In questo caso il programma assegna i
file prodotti all'utente che ha invocato `sudo`, evitando database di proprieta'
di `root`.

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

## Dashboard web

Per consultare tramite browser i database e i grafici gia' presenti:

```bash
python3 bandwidth_monitor.py --web --period 5min
```

La pagina e' disponibile all'indirizzo:

```text
http://localhost:8080
```

Per avviare contemporaneamente cattura e dashboard:

```bash
python3 bandwidth_monitor.py -i en0 --web --period 5min
```

La dashboard si aggiorna automaticamente ogni 15 secondi e permette di scegliere
fra 5 minuti, 30 minuti, 1 ora, 6 ore e 24 ore. Mostra prima il riepilogo della
macchina locale e poi, per ciascun host remoto IPv4 o IPv6, il grafico di
upload/download e quello dei protocolli.

Per impostazione predefinita il server ascolta soltanto su `127.0.0.1` ed e'
quindi accessibile esclusivamente dalla macchina locale. Le opzioni `--web-host`
e `--web-port` permettono di modificare indirizzo e porta quando necessario.

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
-   verifica della dashboard web e della corretta pubblicazione dei grafici;
-   verifica della selezione del periodo e dell'aggiornamento automatico.

## Cartella `rrd_data`

La cartella `rrd_data` viene popolata durante la cattura con i database RRD e i grafici PNG generati dal programma.


I file possono essere utilizzati, ad esempio, eseguendo il comando:

```
python3 bandwidth_monitor.py --graph
```

oppure

```
python3 bandwidth_monitor.py --graph --period 30min
```

che rigenera i grafici utilizzando i database RRD presenti nella cartella.

Le unita' accettate per `--period` sono:

- `s` per secondi (es. `30s`);
- `min` per minuti (es. `5min` o `30min`);
- `h` per ore (es. `6h`);
- `d` per giorni (es. `7d`);
- `w` per settimane (es. `2w`).

L'abbreviazione `m` non viene accettata perche' RRDtool la interpreta in modo
ambiguo; per indicare i minuti bisogna usare esplicitamente `min`.
