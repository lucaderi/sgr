# Firewall Userspace con NFQUEUE

## Introduzione

Il progetto consiste nello sviluppo di un firewall userspace in linguaggio C per sistemi Linux, basato sul sottosistema NFQUEUE di Netfilter.
L’obiettivo è intercettare pacchetti IP selezionati dal kernel, analizzarli in spazio utente e applicare politiche di filtraggio personalizzate.

Oltre al filtraggio tradizionale, il firewall integra due meccanismi di analisi del traffico:

* un sistema di rate limiting basato su algoritmo Leaky Bucket;
* una stima del numero di IP sorgenti distinti tramite HyperLogLog.

---

# Architettura del Sistema

Il firewall è suddiviso nei seguenti moduli principali:

| Modulo         | Funzione                                         |
| -------------- | ------------------------------------------------ |
| `nfqueue_core` | Gestione della comunicazione con NFQUEUE         |
| `parser`       | Estrazione delle informazioni dai pacchetti IPv4 |
| `rules`        | Caricamento e verifica delle regole firewall     |
| `decision`     | Decision engine del firewall                     |
| `rate_limit`   | Controllo del traffico tramite Leaky Bucket      |
| `hyperloglog`  | Stima degli IP sorgenti distinti                 |
| `logging`      | Registrazione di eventi e decisioni              |

Flusso di elaborazione:

1. Il kernel inoltra i pacchetti selezionati a una coda NFQUEUE.
2. Il firewall riceve il pacchetto in userspace.
3. Il parser estrae le informazioni rilevanti:

   * IP sorgente e destinazione;
   * protocollo;
   * porte TCP/UDP.
   
4. Il decision engine:

   * aggiorna le statistiche HyperLogLog;
   * verifica eventuali limiti di traffico;
   * applica le regole firewall;
   * produce il verdetto finale.
   
5. Il risultato viene restituito al kernel.

Questa struttura rende il progetto più semplice da estendere e facilita la separazione delle responsabilità tra i moduli.

---

# Utilizzo di NFQUEUE

NFQUEUE è un componente di Netfilter che consente di trasferire pacchetti dal kernel allo spazio utente.
In questo progetto viene utilizzato per delegare al firewall userspace la decisione finale sui pacchetti intercettati.

Le regole `iptables` indirizzano verso la queue `0` solo il traffico di interesse.

Esempio:

```bash
iptables -t mangle -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
```

In questo modo soltanto il traffico TCP destinato alla porta 80 viene analizzato dal firewall.

---

# Parsing dei Pacchetti

Il modulo `parser` analizza pacchetti IPv4 e supporta i protocolli:

* TCP
* UDP
* ICMP

Le informazioni estratte vengono salvate nella struttura condivisa:

```
struct packet_info {
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    int protocol;
};
```

Durante il parsing vengono effettuati controlli di validità sugli header IPv4 e TCP/UDP.
I pacchetti malformati vengono scartati prima di raggiungere il decision engine.

---

# Gestione delle Regole

Le regole firewall sono definite nel file `firewall.conf` con il formato:

```text
ACTION SRC_IP DST_IP SRC_PORT DST_PORT PROTOCOL
```

Esempio:

```text
DROP ANY ANY ANY 23 TCP
ALLOW ANY ANY ANY 80 TCP
```

Le regole vengono valutate in ordine sequenziale.
La prima regola che produce match determina la decisione finale.

Sono supportati:

* indirizzi IPv4 specifici;
* wildcard `ANY`;
* protocolli TCP, UDP e ICMP.

---

# Rate Limiting con Leaky Bucket

Per limitare possibili attacchi flood, il progetto implementa un sistema di rate limiting basato su algoritmo Leaky Bucket.

Per ogni IP sorgente vengono mantenuti:

* numero di richieste accumulate;
* timestamp dell’ultimo aggiornamento.

Quando il traffico supera la soglia configurata, il pacchetto può essere classificato come sospetto e gestito dal decision engine.

Questo approccio consente di limitare traffico anomalo senza bloccare immediatamente connessioni legittime.

---

# Stima degli IP con HyperLogLog

Il modulo `hyperloglog` viene utilizzato per stimare il numero di indirizzi IP sorgenti distinti osservati dal firewall.

HyperLogLog è una struttura probabilistica che permette di ottenere una stima della cardinalità utilizzando poca memoria.

Nel progetto:

* ogni IP sorgente viene convertito in un hash;
* l’hash aggiorna uno specifico registro della struttura;
* la cardinalità stimata viene calcolata periodicamente dal decision engine.

Questo approccio consente di monitorare il traffico in modo efficiente anche con un numero elevato di host.

---

# Packet Mark e CONNMARK

Il firewall utilizza i packet mark di Netfilter per associare una decisione ai flussi già analizzati.

Sono definiti due mark principali:

```text
FW_MARK_PASS = 0x1
FW_MARK_DROP = 0x2
```

Il funzionamento è il seguente:

1. un pacchetto privo di mark entra in NFQUEUE;
2. il firewall decide se consentire o bloccare il traffico;
3. il mark viene salvato nel conntrack tramite `CONNMARK`;
4. i pacchetti successivi dello stesso flusso vengono gestiti direttamente dal kernel.

Questo meccanismo riduce il numero di pacchetti inviati in userspace e diminuisce l’overhead complessivo del firewall.

---
## Requisiti

Su Ubuntu/WSL:

```bash
sudo apt update
sudo apt install build-essential libnetfilter-queue-dev iptables netcat-openbsd python3
```

---

# Compilazione ed Esecuzione

Per compilare il progetto:

```bash
make firewall
```

Il programma deve essere eseguito con privilegi root:

```bash
sudo ./firewall
```

Per intercettare il traffico è necessario installare le regole `iptables` fornite dagli script del progetto.

Esempio:

```bash
sudo ./scripts/fw_mark_setup.sh 80 23
```

Lo script configura:

* regole NFQUEUE;
* packet mark e CONNMARK;
* catene `mangle` necessarie al test.

Per visualizzare regole e contatori:

```bash
sudo ./scripts/fw_mark_status.sh
```

Per rimuovere tutte le regole create:

```bash
sudo ./scripts/fw_mark_cleanup.sh
```

---

# Testing

Il progetto include uno smoke test automatico:

```bash
make firewall
sudo ./scripts/fw_mark_smoke_test.sh
```

Lo script:

1. avvia il firewall;
2. configura automaticamente le regole `iptables`;
3. crea un server HTTP locale sulla porta 80;
4. genera traffico reale verso le porte 80 e 23;
5. verifica il corretto comportamento del firewall.

In particolare:

* il traffico HTTP verso porta 80 deve essere accettato;
* il traffico Telnet verso porta 23 deve essere bloccato.

Al termine vengono mostrati:

* log del firewall;
* contatori delle regole;
* stato dei mark Netfilter.

---

# Debug

Per visualizzare le regole `mangle`:

```bash
sudo iptables -t mangle -S
```

Per visualizzare i contatori delle chain:

```bash
sudo iptables -t mangle -L FW_OUTPUT -v -n --line-numbers
sudo iptables -t mangle -L FW_POSTROUTING -v -n --line-numbers
```
---

# Autori

* Federico Guastella
* Marco Tavani
* Elio Torraj

