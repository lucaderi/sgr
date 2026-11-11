# Analisi Comportamentale dei Flussi di Rete con Catene di Markov

Progetto di **Gestione di Rete** – Fasiello Fabio

## Sommario

Questo progetto realizza un sistema di rilevamento anomalie per flussi di rete cifrati (HTTPS, QUIC, TLS). L'approccio si basa sull'identificazione dei flussi tramite **nDPI**, sulla discretizzazione dei pacchetti in stati simbolici, e sulla modellazione del comportamento di ciascun flusso attraverso una **catena di Markov**. In questo modo è possibile individuare deviazioni comportamentali — come *beaconing* o *esfiltrazione di dati* — analizzando esclusivamente la sequenza temporale di **dimensione** e **direzione** dei pacchetti, senza bisogno di ispezionare il contenuto cifrato.

---

## Pipeline di Analisi

### 1. Ingestione e Identificazione dei Flussi (nDPI)

- Cattura dei pacchetti da file `.pcap` tramite **libpcap**
- Classificazione dei protocolli tramite **nDPI** per isolare i flussi target: **HTTPS**, **QUIC**, **TLS**

### 2. Discretizzazione dei Pacchetti

Ogni pacchetto viene mappato in uno **stato discreto** combinando:

| Componente  | Valori possibili                                  |
|-------------|---------------------------------------------------|
| Direzione   | `Inbound` / `Outbound`                            |
| Dimensione  | 6 bin: `0-64`, `65–128`, `129–256`, `257-512`, `513–1024`, `1025+` (byte) |

Questo produce un insieme finito di stati simbolici che descrivono il flusso in modo indipendente dal contenuto del payload.

### 3. Analisi con la Matrice di Transizione di Markov

Per ogni flusso viene mantenuta una **matrice di transizione** che descrive le probabilità di passaggio tra gli stati discretizzati.

Per ciascun pacchetto in arrivo:
- Si calcola la probabilità di transizione dallo stato corrente allo stato osservato
- Se la probabilità è **inferiore a una soglia configurabile**, la transizione viene classificata come **anomalia**

### 4. Output e Monitoraggio (RRD)

Le metriche vengono raccolte e graficate tramite **RRDtool**:

| Metrica                                      | Descrizione                                          |
|----------------------------------------------|------------------------------------------------------|
| Transizioni anomale (totale)                 | Conteggio cumulativo di transizioni sotto soglia      |
| Probabilità media dei flussi attivi           | Media della probabilità di transizione sui flussi in corso |
| Media dei flussi monitorati                  | Numero medio di flussi attivi nel tempo               |
| Pacchetti monitorati / pacchetti totali       | Copertura dell'analisi rispetto al traffico catturato |

---

## Costruzione e Training della Matrice di Transizione

La matrice di transizione di ciascun flusso viene costruita attraverso la **Fase di Training**:

- La matrice viene popolata osservando i pacchetti iniziali del flusso.
- A intervalli regolari (configurabili tramite `-n`), si calcola la **norma infinito della differenza** tra la matrice di probabilità corrente e quella precedente (`delta_prob_norm`).
- Quando il delta scende al di sotto della **soglia di convergenza** (`-c`), la matrice viene considerata **"congelata"** (training completato), ed entra nella fase operativa di rilevamento anomalie.

---

## Architettura

```
┌──────────────┐     ┌───────────────┐     ┌───────────────────┐
│  cattura     │────>│  identificaz. │────>│  discretizzazione │
│  (libpcap)   │     │  (nDPI)       │     │  (stati Markov)   │
└──────────────┘     └───────────────┘     └────────┬──────────┘
                                                    │
                                                    ▼
                                          ┌───────────────────┐
                                          │  matrice di       │
                                          │  transizione      │
                                          │  (training +      │
                                          │   convergenza)    │
                                          └────────┬──────────┘
                                                   │
                                    ┌──────────────┼──────────────┐
                                    ▼              ▼              ▼
                               ┌────────┐    ┌──────────┐   ┌─────────┐
                               │ normale│    │ anomalia │   │  RRD    │
                               │ flusso │    │ rilevata │   │ output  │
                               └────────┘    └──────────┘   └─────────┘
```

---

## Tecnologie

| Strumento   | Ruolo                                          |
|-------------|------------------------------------------------|
| **nDPI**    | Classificazione dei protocolli di rete         |
| **libpcap** | Cattura e lettura dei pacchetti `.pcap`         |
| **RRDtool** | Raccolta e visualizzazione delle metriche      |
| **uthash**  | Libreria open-source C per tabelle hash in-memory|

---

## Configurazione

I parametri principali del sistema (configurabili da CLI):

| Parametro                  | Opzione CLI | Descrizione                                             | Valore di default |
|----------------------------|-------------|---------------------------------------------------------|-------------------|
| `threshold_probability`    | `-t`        | Soglia di probabilità per il rilevamento anomalie       | `0.01`            |
| `convergence_delta`        | `-c`        | Soglia di convergenza per il congelamento della matrice | `0.001`           |
| `norm_interval_check`      | `-n`        | Intervallo in pacchetti per il controllo di convergenza | `1000`            |
| `max_flows`                | `-m`        | Numero massimo di flussi concorrenti                    | `100000`          |
| `size_bins`                | —           | Bin di discretizzazione della dimensione payload        | Vedi sezione 2    |

---

## Stato del Progetto

> ✅ Progetto completo e funzionante (Training, Convergenza, Anomaly Detection e Reportistica RRD).

---

## Autori

- **Fabio** — Corso di Gestione di Rete, Università degli Studi di Pisa
