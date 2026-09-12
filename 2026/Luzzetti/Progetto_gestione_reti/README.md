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

Una finestra temporale viene classificata come anomala solamente quando **almeno due metriche** risultano contemporaneamente anomale.

Questa scelta riduce il numero di falsi positivi dovuti a singole variazioni statistiche.

---

## plotting.py

Genera automaticamente un grafico per ogni metrica.

Le finestre identificate come anomale vengono evidenziate mediante una **X**.

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

---

# Tecnologie utilizzate

- Python 3
- Scapy
- Pandas
- NumPy
- Matplotlib

---

# Caso di studio

Per la validazione del progetto è stata realizzata una cattura PCAP comprendente differenti tipologie di traffico:

- traffico ICMP normale
- attività di Port Scanning tramite Nmap
- trasferimento dati mediante iperf3

L'algoritmo è stato in grado di individuare automaticamente le principali variazioni statistiche introdotte durante l'esperimento.

---

# Considerazioni finali

Il progetto implementa un semplice sistema di **Network Traffic Anomaly Detection**.

Le anomalie individuate rappresentano esclusivamente indicatori statistici di comportamenti non ordinari e **non costituiscono una prova certa della presenza di un attacco**.

L'interpretazione finale degli eventi rimane demandata all'analista di rete, che può approfondire le finestre segnalate esaminando i flow corrispondenti.

Questo approccio è coerente con la filosofia dei moderni sistemi di monitoraggio di rete e con quanto discusso durante il corso.

---