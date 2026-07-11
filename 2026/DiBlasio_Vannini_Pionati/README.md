# SNMP Network Monitor con Trap-Directed Polling

## Relazione Tecnica del Progetto

**Studenti:** Marco Vannini, Marco Di Blasio, Riccardo Pionati

**Email:** [m.vannini14@studenti.unipi.it](mailto:m.vannini14@studenti.unipi.it), [m.diblasio@studenti.unipi.it](mailto:m.diblasio@studenti.unipi.it), [r.pionati@studenti.unipi.it](mailto:r.pionati@studenti.unipi.it)

---

## 1. Descrizione del Progetto

Il progetto consiste nella realizzazione di un sistema di monitoraggio di rete basato sul protocollo **SNMP (Simple Network Management Protocol)**, sviluppato in Python. L'obiettivo principale dell'applicazione è l'ottimizzazione delle risorse computazionali e di banda attraverso il meccanismo di **Trap-Directed Polling**.

### Architettura del Software

Il sistema è architettato in tre macro-moduli funzionali operanti in sinergia:

- **Trap Receiver:** Un demone asincrono costantemente in ascolto sulla porta UDP. Il suo compito è intercettare le notifiche asincrone (*Trap*) inviate dagli agenti a fronte di anomalie o variazioni di stato (es. un'interfaccia che va in *down*).
- **Poller Core:** Un motore di interrogazione ciclica che effettua operazioni di SNMP Walk per raccogliere le metriche prestazionali dettagliate dei dispositivi (descrittori, stato operativo, ottetti in ingresso/uscita ed errori sulle interfacce).
- **RRD Manager & Data Processor:** Un modulo che si occupa della persistenza dei dati. Memorizza le metriche all'interno di un file strutturato `metrics.csv` e, alla chiusura del programma, sfrutta la libreria **RRDtool** per elaborare i dati storici e generare grafici temporali in formato `.png`.

### Il Meccanismo del Trap-Directed Polling

L'applicazione adotta un approccio di monitoraggio strutturato su due livelli logici:

- **Polling Ordinario:** Il sistema esegue un'interrogazione ciclica programmata verso tutti i dispositivi indicati nel file di configurazione, raccogliendo i dati prestazionali a intervalli di tempo regolari.
- **Reazione Event-Driven:** Parallelamente al ciclo ordinario, il *Trap Receiver* rimane in ascolto di messaggi asincroni provenienti dalla rete. Non appena viene intercettata una notifica di anomalia (*Trap*), il thread principale interrompe l'attesa del timer e **forza un ciclo di polling straordinario immediato** verso l'agente che ha generato la segnalazione, registrando all'istante lo stato esatto dei contatori.

---

## 2. Prerequisiti di Sistema e Installazione dei Tool

Il progetto è sviluppato per essere eseguito direttamente all'interno del terminale integrato di **Visual Studio Code**, sfruttando un ambiente virtuale Python per isolare le dipendenze. A seconda del sistema operativo ospitante, installare i seguenti componenti tramite la CLI di VS Code.

> ⚠️ **Nota importante sulla versione di Python:** si raccomanda l'utilizzo di **Python 3.14**. Le versioni più recenti rimuovono funzioni interne C deprecate che impediscono la corretta compilazione della libreria `rrdtool`, causando il fallimento di `pip install`.

### 2.1 Per utenti macOS (Terminale VS Code: zsh o bash)

I computer Apple Silicon (M1/M2/M3) e le versioni recenti di macOS nascondono i file di sviluppo di Homebrew in percorsi non standard che il compilatore di `pip` non riesce a vedere autonomamente.

Assicurarsi che nel sistema sia installato il gestore di pacchetti **Homebrew**, quindi lanciare nel terminale di VS Code:

```bash
brew install python git rrdtool
brew install net-snmp
```

**Risoluzione problemi su macOS** (`rrd.h not found` o `library 'rrd' not found`):

Se durante l'esecuzione di `pip install -r requirements.txt` l'installazione di `rrdtool` dovesse fallire, è necessario indicare esplicitamente al compilatore dove si trovano le librerie di Homebrew. Eseguire questi comandi nel terminale prima di lanciare l'installazione dei requisiti:

```bash
export CFLAGS="-I$(brew --prefix rrdtool)/include"
export LDFLAGS="-L$(brew --prefix rrdtool)/lib"
pip install -r requirements.txt
```

### 2.2 Per utenti Linux / Ubuntu (Terminale VS Code: bash)

Aprire il terminale di VS Code ed eseguire l'installazione delle dipendenze e dei compilatori di sistema:

```bash
sudo apt install -y python3 python3-pip python3-venv git gcc librrd-dev rrdtool
sudo apt install -y snmp snmpd
```

### 2.3 Per utenti Windows (Terminale VS Code: PowerShell)

Aprire il terminale integrato di VS Code (assicurandosi che sia impostato su **PowerShell**) ed eseguire:

```powershell
# Installazione rapida di Python e Git tramite il gestore nativo Windows
winget install Python.Python.3.11
winget install Git.Git
```

> **Nota per l'ambiente Windows:** per evitare complessità legate alla compilazione dei binding C della libreria `rrdtool` nativa su Windows, si consiglia di utilizzare il terminale di VS Code connesso a una distribuzione Linux tramite l'estensione **WSL (Windows Subsystem for Linux)**, oppure procedere al deployment tramite Docker.

### 2.4 Configurazione dell'Ambiente Virtuale in VS Code (comune a tutti i S.O.)

Una volta installati i tool di sistema, aprire la cartella del progetto in VS Code. Aprire il terminale integrato e digitare i comandi per creare e attivare l'ambiente virtuale locale prima di installare i pacchetti Python:

```bash
# Creazione dell'ambiente virtuale nella cartella del progetto
python3 -m venv .venv

# Attivazione dell'ambiente (VS Code mostrerà il prefisso '(.venv)' nel terminale)
# Su macOS / Linux:
source .venv/bin/activate
# Su Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Installazione dei pacchetti Python necessari all'applicazione
pip install --upgrade pip
pip install -r requirements.txt
```

### 2.5 Containerizzazione degli Agenti (Docker)

In parallelo a VS Code, è fondamentale che sia attivo **Docker** sul computer per far girare i simulatori di rete.

- Su **Windows** e **macOS**, accertarsi che l'applicazione **Docker Desktop** sia aperta e in esecuzione in background prima di lanciare i comandi di test dal terminale dell'editor.

---

## 3. Istruzioni per l'Esecuzione

L'esecuzione del sistema richiede l'utilizzo di due sessioni di terminale distinte: una per la gestione del monitor centrale e una per la simulazione della rete e degli eventi.

### Passo 1: Avvio degli Agenti SNMP Simulati (Terminale 2)

Per testare il programma senza disporre di apparati hardware fisici, si avviano due container Docker basati su Ubuntu che simulano due agenti SNMP attivi internamente sulla porta standard 161, ma esposti verso l'host sulle porte 1161 e 1163:

```bash
docker run -d --name snmp-agent-1 -p 1161:161/udp ubuntu:24.04 sh -c "apt-get update && apt-get install -y snmpd && echo 'agentAddress udp:161' > /etc/snmp/snmpd.conf && echo 'rocommunity public default' >> /etc/snmp/snmpd.conf && snmpd -f -Lo"

docker run -d --name docker-agent -p 1163:161/udp ubuntu:24.04 sh -c "apt-get update && apt-get install -y snmpd && echo 'agentAddress udp:161' > /etc/snmp/snmpd.conf && echo 'rocommunity public default' >> /etc/snmp/snmpd.conf && snmpd -f -Lo"
```

> *Nota: assicurarsi che il file `config/agents.yml` sia configurato per puntare a `127.0.0.1` sulle rispettive porte 1161 e 1163.*

### Passo 2: Avvio dello SNMP Manager (Terminale 1)

Posizionarsi nella **cartella radice** del progetto (quella che contiene al suo interno le directory `src` e `config`). L'applicazione viene avviata esplicitando la variabile d'ambiente `PYTHONPATH` per consentire la corretta risoluzione dei moduli interni e delle importazioni:

**Modalità Standard (intervallo di default):**

```bash
PYTHONPATH=src python3 -m snmp_monitor.main --config config/agents.yml
```

**Modalità Personalizzata (con specifica del tempo di polling):**

Se si desidera personalizzare la frequenza di campionamento ordinaria (es. impostando il ciclo di polling a ogni **10 secondi**), è sufficiente aggiungere l'argomento `--interval`:

```bash
PYTHONPATH=src python3 -m snmp_monitor.main --config config/agents.yml --interval 10
```

---

## 4. Test Svolti e Risultati Funzionali

### Test 1: Polling Standard Pianificato (Verifica del Timer)

**Procedura:** avviare il manager impostando l'intervallo a 10 secondi. Lasciare il programma in esecuzione per raccogliere i dati in modalità ordinaria.

**Risultato nei Log (Terminale 1):** il sistema interroga ciclicamente i nodi configurati rispettando la cadenza temporale impostata e popolando progressivamente le metriche:

```
2026-07-06 18:32:46,014 INFO __main__: Trap receiver avviato su udp://127.0.0.1:9162
[TRAP] Receiver avviato su udp://127.0.0.1:9162 community=public
[TRAP] In attesa di trap SNMP...
2026-07-06 18:32:46,130 INFO __main__: Polling completato: 22 metriche raccolte da 2 agenti
2026-07-06 18:32:56,065 INFO __main__: Polling completato: 22 metriche raccolte da 2 agenti
2026-07-06 18:33:06,063 INFO __main__: Polling completato: 22 metriche raccolte da 2 agenti
```

### Test 2: Verifica del Trap-Directed Polling (Reattività ad Anomalia)

**Procedura:** con lo SNMP Manager in esecuzione (`PYTHONPATH=src python3 -m snmp_monitor.main --config config/agents.yml`), da un secondo terminale è stata inviata una trap SNMPv2c di tipo **linkDown**:

```bash
snmptrap -v2c -c public localhost:9162 "" 1.3.6.1.6.3.1.1.5.3
```

**Risultato — evidenza su `metrics.csv`:** l'analisi del file mostra due polling distanziati di circa 30 secondi, seguiti da un terzo polling a circa 1 secondo dal precedente, eseguito immediatamente dopo l'invio della trap:

```csv
timestamp,agent,if_index,if_name,if_status,in_octets,out_octets,in_errors,out_errors,in_mbps,out_mbps
2026-07-08T16:30:19.402369,docker-agent,11,eth0,up,44661120,367410,0,0,0.0002,0.0007
2026-07-08T16:30:48.713685,docker-agent,11,eth0,up,44661636,369974,0,0,0.0001,0.0007
2026-07-08T16:30:49.369110,docker-agent,11,eth0,up,44662152,372538,0,0,0.0063,0.0313
```

I primi due campionamenti rispettano l'intervallo configurato (~30 s), mentre il terzo, avvenuto circa un secondo dopo, dimostra il corretto funzionamento del meccanismo di Trap-Directed Polling. L'aggiornamento dei contatori e del throughput conferma che il polling straordinario ha acquisito lo stato aggiornato dell'interfaccia.

**Risultato — evidenza nei log (Terminale 1):** il Trap Receiver intercetta immediatamente il pacchetto UDP sulla porta 9162. Il flusso principale interrompe l'attesa del timer standard e avvia un'operazione di polling immediata per registrare istantaneamente lo stato del dispositivo:

```
[TRAP] Ricevuta trap da unknown
[TRAP] Tipo trap: linkDown
[TRAP]   1.3.6.1.2.1.1.3.0 = 0
[TRAP]   1.3.6.1.6.3.1.1.4.1.0 = 1.3.6.1.6.3.1.1.5.3
2026-07-08 16:30:48,691 INFO __main__: Trap ricevuta dal main: tipo=linkDown sorgente=unknown
2026-07-08 16:30:48,691 INFO __main__: Trap linkDown rilevante: avvio polling immediato
2026-07-08 16:30:48,713 INFO __main__: Polling immediato da trap linkDown completato: 22 metriche raccolte
```

Le due evidenze, lette insieme, mostrano l'intera catena causa-effetto: ricezione della trap → decisione di forzare il polling → aggiornamento dei contatori nel CSV nel giro di circa un secondo.

### Test 3: Generazione dei Grafici RRDtool e Terminazione

**Procedura:** inviare un segnale di interruzione nel Terminale 1 premendo la combinazione di tasti **Ctrl + C**.

**Risultato nei Log:** il programma intercetta il segnale, chiude in sicurezza i socket di ascolto e invoca il modulo RRDtool per elaborare lo storico dei dati estratti:

```
^C2026-07-06 18:33:20,105 INFO __main__: Segnale di stop ricevuto, chiusura in corso...
2026-07-06 18:33:20,112 INFO __main__: Loop di polling terminato
```

---

## 5. File di Test e Validazione dei Risultati

La corretta esecuzione del software e la validazione dei risultati funzionali possono essere verificate mediante l'analisi dei file generati sulla macchina host al termine dei test:

- **`config/agents.yml`** (Configurazione di Input): permette di definire i nodi target. Iniettando parametri errati (es. IP inesistenti), è possibile testare la robustezza del codice verificando la corretta gestione dei timeout a terminale (`SNMP error: No SNMP response received before timeout`).
- **`metrics.csv`** (Risultati Grezzi): questo file viene generato e popolato dinamicamente dal nucleo del poller. Ogni riga rappresenta un record temporale strutturato contenente le metriche relative a: Timestamp, Agent_Name, Interface_Index, ifDescr, ifOperStatus, ifInOctets, ifOutOctets, ifInErrors, ifOutErrors. La presenza di record con timestamp non allineati all'intervallo standard (es. i 10 secondi del test) valida la corretta esecuzione dei cicli straordinari avviati dalle trap.
- **`rrd_graphs/`** (Output Grafico): al momento dello spegnimento dell'applicazione, il modulo di elaborazione dati converte i contatori cumulativi del CSV in delta di traffico (throughput calcolato in byte al secondo). La comparsa all'interno di questa cartella dei file grafici `.png` relativi alle singole interfacce monitorate (es. `docker_agents.png`) certifica il successo e il corretto funzionamento dell'intera pipeline del software.
