# Progetto Gestione di Reti

Studente: **Matteo Luzzetti**

Corso: **Gestione di Reti**

Anno Accademico: **2025/2026**

Titolo del progetto:

**Network Traffic Anomaly Detection mediante analisi di flow IPv4 e metriche statistiche**

## Descrizione

Il progetto realizza una pipeline completa per l'analisi di traffico di rete a partire da una cattura PCAP.

L'applicazione ricostruisce i flow di rete, li aggrega in finestre temporali e calcola diverse metriche statistiche. Successivamente applica un algoritmo di **Anomaly Detection** basato sullo **Z-score** per individuare finestre temporali caratterizzate da comportamenti anomali rispetto al traffico normale.

L'obiettivo del progetto **non è identificare automaticamente un attacco**, ma evidenziare eventi statisticamente anomali che possano rappresentare un campanello d'allarme da approfondire mediante analisi successive.

---

# Pipeline

L'applicazione è composta da cinque fasi principali.

```
PCAP
   │
   ▼
1. Lettura dei pacchetti
   │
   ▼
2. Ricostruzione dei Flow
   │
   ▼
3. Aggregazione in finestre temporali
   │
   ▼
4. Anomaly Detection
   │
   ▼
5. Visualizzazione dei risultati
```

---

# Moduli

## pcap_parser.py

Legge il file PCAP utilizzando Scapy e restituisce la lista dei pacchetti che verrà elaborata nei moduli successivi.

---

## flow_builder.py

Ricostruisce i flow IPv4 unidirezionali utilizzando la classica **5-tupla**:

- IP sorgente
- IP destinazione
- Porta sorgente
- Porta destinazione
- Protocollo

La gestione dei flow segue le convenzioni utilizzate da NetFlow/IPFIX:

- **Inactive Timeout:** 15 secondi
- **Active Timeout:** 30 minuti

Ogni flow memorizza:

- timestamp iniziale
- timestamp finale
- numero di pacchetti
- byte trasferiti
- motivo della terminazione

---

## metrics.py

I flow vengono aggregati in finestre temporali di durata configurabile (default: 5 secondi).

Per ogni finestra vengono calcolate le seguenti metriche:

- Numero di nuovi flow
- Numero di porte di destinazione distinte
- Numero di host di destinazione distinti
- Entropia delle porte di destinazione
- Numero medio di pacchetti per flow
- Byte medi per flow
- Durata media dei flow

---

## anomaly.py

L'individuazione delle anomalie viene effettuata utilizzando lo **Z-score**.

Per ogni metrica vengono calcolati:

- media della baseline
- deviazione standard
- z-score

Una metrica viene considerata anomala quando:

```
z-score > threshold
```

Nel test effettuato è stata utilizzata una soglia:

```
threshold = 3.0
```

Una finestra temporale viene classificata come anomala solamente quando **almeno due metriche** risultano contemporaneamente anomale.

Questa scelta ha lo scopo di ridurre il numero di segnalazioni dovute alla variazione di una singola metrica. Le metriche utilizzate rimangono tuttavia semplici indicatori statistici e la presenza di più anomalie contemporanee non implica necessariamente la presenza di un attacco.

---

## plotting.py

Genera automaticamente un grafico per le metriche selezionate.

Le finestre nelle quali una determinata metrica supera la soglia dello Z-score vengono evidenziate mediante una **X**.

---

# Metriche utilizzate

| Metrica | Obiettivo |
|----------|-----------|
| New Flow Count | Individuazione di improvvisi aumenti di nuove connessioni |
| Distinct Destination Ports | Individuazione di attività di port scanning |
| Distinct Destination Hosts | Individuazione di scansioni verso host differenti |
| Port Entropy | Misura della dispersione della distribuzione delle porte di destinazione |
| Average Packets per Flow | Individuazione di trasferimenti anomali |
| Average Bytes per Flow | Individuazione di elevati volumi di traffico |
| Average Flow Duration | Individuazione di comunicazioni particolarmente lunghe |

---

# Esecuzione

Installare le dipendenze:

```bash
pip install -r requirements.txt
```

Il programma può essere eseguito specificando il file PCAP da analizzare:

```bash
python3 main.py <file.pcapng>
```

Ad esempio:

```bash
python3 main.py cattura_progetto.pcapng
```

Al termine dell'esecuzione vengono prodotti i file CSV e i grafici nella directory `output/`.

---

# Risultati

L'applicazione produce automaticamente:

```
output/
│
├── csv/
│   ├── flows.csv
│   ├── window_metrics.csv
│   └── anomalies.csv
│
└── plots/
    ├── new_flow_count.png
    ├── distinct_destination_ports.png
    ├── port_entropy.png
    ├── average_packets_per_flow.png
    ├── average_bytes_per_flow.png
    └── average_flow_duration.png
```

`flows.csv` contiene i flow ricostruiti a partire dalla cattura.

`window_metrics.csv` contiene le metriche aggregate per ogni finestra temporale.

`anomalies.csv` contiene, oltre alle metriche, gli Z-score calcolati e le relative segnalazioni di anomalia.

I grafici presenti in `output/plots/` sono stati generati utilizzando il test descritto nella sezione seguente.

---

# Test e riproduzione dell'esperimento

## Ambiente di test

Il test è stato effettuato utilizzando due host collegati alla stessa rete locale:

- **MacBook Pro:** generazione del traffico di test e cattura dei pacchetti tramite Wireshark;
- **Raspberry Pi:** host di destinazione del traffico generato.

La cattura è stata effettuata sul MacBook tramite **Wireshark**, sull'interfaccia di rete utilizzata per la comunicazione con il Raspberry Pi.

Durante la cattura era presente anche il normale traffico di background generato dalla rete e dal sistema.

---

## PCAP utilizzato

Per il test è stata generata una singola cattura denominata:

```text
cattura_progetto.pcapng
```

La cattura ha una dimensione di circa **300 MB**.

A causa delle dimensioni, il file PCAP non viene incluso direttamente nel repository. Per rendere comunque riproducibile il test, di seguito vengono riportati l'ambiente, i comandi e la sequenza utilizzati per generare una cattura equivalente.

Gli output presenti nella directory `output/` sono stati ottenuti analizzando questa cattura.

---

## Generazione del traffico

L'esperimento è stato realizzato alternando traffico ordinario e due differenti tipologie di traffico di test: un port scan tramite **Nmap** e un trasferimento ad alto volume tramite **iperf3**.

La sequenza utilizzata è stata:

1. circa 35 secondi di traffico ICMP tramite `ping`;
2. port scan del Raspberry Pi tramite Nmap;
3. circa 30 secondi di traffico ICMP tramite `ping`;
4. 30 secondi di traffico generato tramite iperf3;
5. circa 30 secondi finali di traffico ICMP tramite `ping`.

### Traffico ICMP

Dal MacBook è stato eseguito:

```bash
ping <IP_RASPBERRY>
```

### Port scanning

Il port scan è stato effettuato dal MacBook verso il Raspberry Pi sulle porte da 1 a 500:

```bash
nmap -Pn -p 1-500 <IP_RASPBERRY>
```

L'opzione `-Pn` evita la fase di host discovery e considera direttamente l'host di destinazione attivo.

### Traffico iperf3

Sul Raspberry Pi è stato avviato iperf3 in modalità server:

```bash
iperf3 -s
```

Sul MacBook è stato successivamente avviato il client per 30 secondi:

```bash
iperf3 -c <IP_RASPBERRY> -t 30
```

---

## Costruzione della baseline

Le metriche vengono calcolate su finestre temporali di **5 secondi**.

Per il test sono state utilizzate come baseline le prime:

```text
6 finestre temporali
```

corrispondenti ai primi **30 secondi della cattura**.

Questa parte della cattura precede l'esecuzione del port scan ed è stata utilizzata per stimare, per ciascuna metrica:

- media;
- deviazione standard.

Gli Z-score delle finestre successive vengono quindi calcolati rispetto a questi valori.

La baseline utilizzata in questo esperimento rappresenta una semplificazione dovuta alla disponibilità di una singola cattura controllata. In un sistema reale sarebbe preferibile costruire la baseline utilizzando un periodo storico di traffico normale sufficientemente rappresentativo della rete monitorata.

---

## Riproduzione del test

Per riprodurre l'esperimento:

1. collegare due host alla stessa rete;
2. avviare `iperf3 -s` sull'host utilizzato come destinazione;
3. avviare Wireshark sull'host utilizzato per generare il traffico;
4. iniziare la cattura sull'interfaccia di rete corretta;
5. generare circa 35 secondi di traffico tramite `ping`;
6. interrompere il ping ed eseguire:

```bash
nmap -Pn -p 1-500 <IP_DESTINAZIONE>
```

7. al termine dello scan, generare nuovamente circa 30 secondi di traffico tramite `ping`;
8. eseguire per 30 secondi:

```bash
iperf3 -c <IP_DESTINAZIONE> -t 30
```

9. generare circa 30 secondi finali di traffico tramite `ping`;
10. interrompere la cattura e salvarla in formato PCAP/PCAPNG;
11. analizzare il file ottenuto tramite:

```bash
python3 main.py <file.pcapng>
```

Gli output verranno generati automaticamente nella directory `output/`.

---

# Analisi dei risultati del test

Il test permette di osservare due differenti comportamenti anomali.

## Port scanning tramite Nmap

Durante il port scan si osserva un forte aumento di:

- **New Flow Count**
- **Distinct Destination Ports**
- **Port Entropy**

Nella cattura utilizzata, il fenomeno è particolarmente evidente approssimativamente tra **50 e 75 secondi** dall'inizio.

Questo comportamento è coerente con lo scan effettuato: vengono generati numerosi flow verso un elevato numero di porte di destinazione.

La metrica `Distinct Destination Hosts` non presenta invece un incremento significativo, poiché il test viene effettuato verso un singolo host.

## Traffico iperf3

Durante il test iperf3 si osserva invece un forte incremento di:

- **Average Packets per Flow**
- **Average Bytes per Flow**

Nella cattura utilizzata il picco principale viene associato alla finestra che inizia approssimativamente a **110 secondi**.

Questo comportamento è differente dal port scanning: iperf3 utilizza un numero limitato di flow, ma trasferisce attraverso questi una quantità molto elevata di pacchetti e byte.

Poiché almeno due metriche superano contemporaneamente la soglia dello Z-score, la relativa finestra viene classificata come anomala.

È importante osservare che i flow vengono associati alle finestre temporali sulla base del loro **timestamp di inizio**. Di conseguenza, un flow iniziato in una determinata finestra può continuare a trasportare traffico anche nelle finestre temporali successive.

---

# Tecnologie utilizzate

- Python 3
- Scapy
- Pandas
- NumPy
- Matplotlib
- Wireshark
- Nmap
- iperf3

---

# Considerazioni finali

Il progetto implementa un semplice sistema di **Network Traffic Anomaly Detection**.

Le anomalie individuate rappresentano esclusivamente indicatori statistici di comportamenti non ordinari e **non costituiscono una prova certa della presenza di un attacco**.

L'utilizzo congiunto di più metriche permette di osservare differenti caratteristiche del traffico. Nel test effettuato, ad esempio, il port scanning determina principalmente un aumento del numero di nuovi flow, delle porte di destinazione e della relativa entropia, mentre il traffico generato da iperf3 determina principalmente un aumento del numero medio di pacchetti e byte per flow.

L'interpretazione finale degli eventi rimane demandata all'analista di rete, che può approfondire le finestre segnalate esaminando i flow corrispondenti.

In un'applicazione reale sarebbe inoltre necessario costruire la baseline a partire da un periodo storico di traffico normale sufficientemente rappresentativo, anziché utilizzare solamente le prime finestre di una singola cattura controllata.

---