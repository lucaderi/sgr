# Relazione di Progetto: Analisi Comportamentale dei Flussi di Rete con Catene di Markov

**Corso di Gestione di Rete**  
**Università degli Studi di Pisa**

---

## Informazioni Autore

- **Nome e Cognome:** Fabio Fasiello  
- **Email:** f.fasiello@studenti.unipi.it
- **Repository / Progetto:** Analisi markoviana dei pacchetti (Analisi comportamentale dei flussi di rete cifrati)

---



## Caso d'uso che questo progetto risolve
Il caso d'uso di questo progetto è fornire una prima euristica nel monitoraggio del traffico. Un'eventuale versione migliorata (magari live, con dei modelli probabilistici più avanzati) potrebbe essere integrata in una dashboard di monitoring, per vedere quanti flussi di rete presentano dei pacchetti anomali e la loro evoluzione 

L'intero progetto si basa sull'assunzione che ogni flusso di rete cifrato abbia un bias di determinate dimensioni e direzioni abbastanza stabile, rilevabile nel training.

Eg: Il download di un file avrà dimensioni di inbound considerevoli e outbound esigue, quindi un’inversione anomala del traffico di rete con grandi volumi di outbound potrebbe segnalare un'esfiltrazione.

### Possibili limiti
- Alta possibilità di falsi positivi: essendo l'attuale rilevazione un semplice threshold, é possibile che pacchetti legittimi siano flaggati come anomali. Si potrebbe mitigare implementando Holt-Winters o modelli probabilistici piú avanzati
- Poca granularitá nella regolazione dei parametri di threshold: l'incremento della threshold, implicitamente, aumenta i falsi negativi e viceversa, il suo decremento, può risultare in falsi positivi


## Definizione di Anomalia
Definisco come anomalia un pacchetto di rete (inbound o outbound), che dopo la fase di training, appartiene a un bin "non attivato" in training. 

Eg:
Dopo il training arriva un pacchetto appartente a S, con stato precedente L. Sia P(L->S) il corrispondente elemento nella matrice di Markov creata nel training.
Se P(L->S) <= soglia di `-t` allora il pacchetto è anomalo.

### Stati della matrice

Compresi tra 0-11:
- 0-5: Il pacchetto è inbound, ovvero proviene dalla rete locale (definito dal argomento `-l`)
- 6-11: Il pacchetto è outbound, ovvero proviene dall'esterno 

Considerando Inbound e Outbound come modulo 6 ricavo i bin delle dimensioni rispettivamente:
 - 0: `0-64`,
 - 1: `65–128`,
 - 2: `129–256`,
 - 3: `257-512`,
 - 4: `513–1024`,
 - 5: `1025+`


---

## 1. Descrizione di Cosa è Stato Fatto

Questo progetto realizza un sistema per il rilevamento di anomalie comportamentali (come *beaconing* o esfiltrazione di dati) all'interno di flussi di rete cifrati (**HTTPS, QUIC, TLS**). L'obiettivo principale è identificare deviazioni anomale analizzando esclusivamente la sequenza temporale di **dimensione** e **direzione** dei pacchetti, senza necessità di decifrare il payload.

La pipeline di analisi implementata comprende:
1. **Ingestione e Classificazione (nDPI + libpcap + uthash):** Lettura dei pacchetti da file `.pcap` tramite `libpcap` e classificazione dei protocolli tramite la libreria **nDPI** per isolare i flussi target (TLS/QUIC). Per la gestione efficiente in-memory delle tabelle dei flussi identificati e sconosciuti viene utilizzata la libreria open-source **uthash**. I flussi sconosciuti vengono tracciati temporaneamente e promossi se identificati come traffico target entro una soglia di pacchetti (*give-up threshold*).
2. **Discretizzazione dei Pacchetti:** Mappatura di ciascun pacchetto in uno stato discreto ($12$ stati totali) combinando:
   - **Direzione:** `Inbound` / `Outbound`
   - **Dimensione payload (6 bin):** `0-64`, `65–128`, `129–256`, `257-512`, `513–1024`, `1025+` byte.
3. **Training e Convergenza della Matrice di Markov:**: Per ogni flusso viene mantenuta una matrice di transizione $12 \times 12$. Inoltre per ogni flusso in fase di training:
	- Popolo la matrice di frequenza (ogni pacchetto di rete considerato come +1)
	- A intervalli di `norm_interval_check` normalizzo la matrice attuale e controllo se la **norma infinito della differenza tra la matrice di Markov precedente e attuale <= `convergence_delta`** (`convergence_delta` settabile da argomento)
	- Se la condizione precedente e verificata "congelo" la matrice normalizzata e passo alla fase successiva altrimenti itero.
4. **Rilevamento delle Anomalie:** Nelle fasi successive, ogni transizione tra stati viene confrontata con la matrice di transizione congelata. Se la probabilità calcolata è inferiore alla soglia configurata (`-t`), l'evento viene classificato come anomalia.
5. **Reportistica e Monitoraggio (RRDtool):** Raccolta periodica delle metriche (transizioni anomale cumulative, probabilità media dei flussi attivi, numero di flussi attivi e rapporto dei pacchetti monitorati) in un database RRD con generazione automatica di grafici PNG al termine dell'elaborazione.

---

## 2. Prerequisiti ed Istruzioni per Eseguire il Progetto

### Prerequisiti di Sistema (Linux / Ubuntu / Debian)
Assicurarsi di avere installati i seguenti pacchetti di sviluppo e librerie:
- `gcc`
- `make`
- `libpcap-dev`
- `libndpi-dev`
- `librrd-dev` 
- `libglib2.0-dev`
- `pkg-config`
- `uthash` (Libreria open-source header-only per tabelle hash in-memory in C, inclusa in `include/uthash.h`)
- `python3` (con libreria `scapy` per la generazione dei file di test)

Installazione rapida su Ubuntu/Debian:
```bash
sudo apt update
sudo apt install build-essential libpcap-dev libndpi-dev librrd-dev libglib2.0-dev pkg-config python3-scapy
```

### Compilazione
Per compilare il progetto, posizionarsi nella cartella principale ed eseguire:
```bash
make
```
Questo per generare l'eseguibile binario in `bin/netflow_analyzer`.

### Esecuzione
Il progetto richiede un file di cattura `.pcap` e l'indirizzo IP locale (inbound) associato:
```bash
./bin/netflow_analyzer -r test/capture.pcap -l 192.168.1.100
```

Per creare i `.pcap` di test viene fornito un piccolo script Python aggiuntivo (Richiede `scapy` come dipendenza)
Per eseguirlo:
```bash
python3 generate_pcaps.py
```

**Opzioni disponibili (`-h` per l'aiuto):**
- `-r FILE`: File di input `.pcap` da analizzare (obbligatorio)
- `-l IP`: Indirizzo IP locale/inbound di riferimento (obbligatorio)
- `-o PATH`: Percorso del database RRD di output (default: `test/out/netflow_metrics.rrd`)
- `-t VAL`: Soglia di probabilità per il rilevamento anomalie (default: `0.01`)
- `-c VAL`: Soglia di convergenza per il congelamento della matrice (default: `0.001`)
- `-n NUM`: Intervallo in pacchetti per il controllo di convergenza (default: `1000`)
- `-m NUM`: Numero massimo di flussi concorrenti (default: `100000`)

---

## 3. Test Svolti per la Verifica

Per validare il corretto funzionamento del sistema e la conformità agli obiettivi, sono stati eseguiti i seguenti test:

1. **Test di Ingestione e Riconoscimento nDPI:**
   - Esecuzione sui file di cattura di test, generati con python, per verificare il corretto parsing dei pacchetti Ethernet/IP/TCP/UDP, la normalizzazione topologica dei flussi e l'identificazione dei protocolli TLS e QUIC tramite nDPI.
2. **Test di Convergenza Markoviana:**
   - Verifica che le matrici di transizione vengano popolate correttamente e che il criterio di arresto (norma infinito $\le$ soglia di convergenza) congeli con successo il modello di baseline per ciascun flusso.
3. **Test di Rilevamento Anomalie e Persistenza RRD:**
   - Validazione del calcolo delle probabilità di transizione post-training, conteggio delle anomalie sotto soglia e scrittura corretta sul database RRD, con conseguente generazione dei grafici PNG riepilogativi (`monitored_traffic.png`, `active_flows.png`, `average_probability.png`, `anomalies.png`).
4. **Test di Gestione della Memoria (Valgrind):**
   - Verifica tramite deallocazione ricorsiva delle tabelle hash (`cleanup_flows()`) e rilascio delle risorse nDPI/pcap per assicurare l'assenza di memory leak critici (`definitely lost: 0 bytes`).

---

## 4. File di Test e Generazione tramite `generate_pcaps.py`

I file `.pcap` di test utilizzati per validare il comportamento del sistema vengono generati tramite lo script Python **`generate_pcaps.py`** (basato sulla libreria **Scapy**). Questo permette di simulare flussi di rete TLS/QUIC con sequenze controllate di pacchetti (in termini di direzione e dimensioni del payload) sia per la fase di training che per l'introduzione di anomalie comportamentali mirate.

- **`test/out/`**: Directory di output in cui vengono salvati automaticamente il database RRD (`netflow_metrics.rrd`) e i grafici PNG generati al termine dell'esecuzione:
  - `monitored_traffic.png`
  - `active_flows.png`
  - `average_probability.png`
  - `anomalies.png`

**Comando di riproduzione dei test:**
```bash
python3 generate_pcaps.py
./bin/netflow_analyzer -r normal_flow.pcap -l 192.168.1.100 -t 0.01 -c 0.001 -o test/out/normal/netflow_metrics.rrd
./bin/netflow_analyzer -r anomalous_flow.pcap -l 192.168.1.100 -t 0.01 -c 0.001 -o test/out/anomalous/netflow_metrics.rrd
```
Al termine dell'esecuzione, verranno stampate a schermo le matrici di probabilità di transizione Markoviane per ciascun flusso identificato e verranno generati i grafici in `test/out/`.
