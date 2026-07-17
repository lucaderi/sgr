# Firewall Userspace con NFQUEUE

## Introduzione

Il progetto consiste in un firewall userspace che integra sia il filtraggio classico tramite NFQUEUE sia alcune strutture dati viste durante il corso, in particolare Leaky Bucket e HyperLogLog.

L’obiettivo del Leaky Bucket è introdurre una forma semplice di rate limiting per limitare host che generano un numero elevato di connessioni in un breve intervallo temporale. Per ogni IP sorgente si mantiene infatti un bucket associato, che cresce all’arrivo dei pacchetti e si svuota progressivamente nel tempo. Quando il numero di token supera una soglia prefissata, il traffico viene considerato eccessivo e classificato come DROP dal decision engine.
HyperLogLog viene invece utilizzato come struttura statistica per stimare il numero di IP sorgenti distinti osservati dal firewall. L’idea è avere un indicatore leggero di possibili fenomeni anomali distribuiti (ad esempio flood provenienti da molti host differenti) senza mantenere in memoria l’elenco completo degli IP osservati. L' HLL non influisce direttamente sulla decisione ACCEPT/DROP: essendo una struttura probabilistica, fornisce una stima della cardinalità ma non permette di identificare direttamente gli host coinvolti. Per questo motivo viene utilizzato a fini di monitoring e logging.

Mentre le tecnologie di packet mark e CONNMARK, hanno il seguente comportamento: il firewall userspace non applica direttamente NF_DROP; la callback NFQUEUE restituisce sempre NF_ACCEPT; il firewall assegna però un mark differente ai pacchetti classificati ACCEPT o DROP; successivamente le regole iptables/mangle utilizzano tali mark per decidere se accettare o scartare il traffico. Questa scelta è stata fatta per evitare reiniezioni ripetute dello stesso traffico nella NFQUEUE e ridurre il numero di pacchetti riesaminati dal firewall userspace.
Nel caso dei flussi ACCEPT: il pacchetto prosegue normalmente nello stack di rete; conntrack conferma la connessione; il CONNMARK viene salvato correttamente; i pacchetti successivi dello stesso flusso possono quindi bypassare NFQUEUE; dove con il termine flusso si indica una quintupla <IpSorgente, IpDestinazione, PortaSorgente, PortaDestinazione, Protocollo>. 
Nel caso dei flussi classificati DROP: il pacchetto riceve il mark corrispondente; il DROP effettivo viene eseguito successivamente da iptables; tuttavia il comportamento dipende dal lifecycle della conntrack entry. In particolare, se il primo pacchetto del flusso viene scartato prima che la connessione venga completamente confermata dal kernel, il relativo stato conntrack potrebbe non essere persistente. In questo caso il mark non viene necessariamente riutilizzato dai pacchetti successivi dello stesso flusso.

Di conseguenza, la nostra implementazione garantisce in modo affidabile il caching dei flussi ACCEPT tramite CONNMARK, mentre per i flussi DROP il comportamento è più limitato e dipende dalla conferma della connessione nello stack Netfilter/conntrack.
La meccanica relativa ai DROP potrebbe essere ulteriormente migliorata in una futura evoluzione del progetto, ad esempio introducendo blacklist temporanee lato userspace oppure una diversa gestione del verdict NFQUEUE. La soluzione adottata è volutamente più semplice e facilmente analizzabile, coerente con gli obiettivi del progetto. 

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

Le regole `iptables` indirizzano verso la queue `0` solo il traffico di interesse. Nel progetto non conviene aggiungerle a mano: lo script `fw_mark_setup.sh` installa anche le chain necessarie per packet mark e `CONNMARK`.

Esempio per intercettare traffico TCP locale verso porta 80:

```bash
sudo ./scripts/fw_mark_setup.sh -p tcp -d 127.0.0.1 80
```

In questo modo soltanto il traffico selezionato viene analizzato dal firewall, mentre il resto continua a seguire il normale percorso del kernel.

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

I valori di configurazione di questo meccanismo sono le costanti RATE_LIMIT_MAX_TOKENS e RATE_LIMIT_LEAK_RATE definite in include/rate_limit.h. 

---

# Stima degli IP con HyperLogLog

Il modulo `hyperloglog` viene utilizzato per stimare il numero di indirizzi IP sorgenti distinti osservati dal firewall.

HyperLogLog è una struttura probabilistica che permette di ottenere una stima della cardinalità utilizzando poca memoria.

Nel progetto:

* ogni IP sorgente viene convertito in un hash;
* l’hash aggiorna uno specifico registro della struttura;
* la cardinalità stimata viene calcolata periodicamente dal decision engine.

Questo approccio consente di monitorare il traffico in modo efficiente anche con un numero elevato di host.

I valori di configurazione di questo meccanismo sono le costanti HLL_P e HLL_M, rispettivamente il numero di bit dedicati ai registri e il numero di registri, presenti nel file hyperloglog.h  

---

# Packet Mark e CONNMARK

Il firewall utilizza i packet mark di Netfilter per associare una decisione ai pacchetti analizzati e, quando possibile, ai flussi già visti.

Sono definiti due mark principali:

```text
FW_MARK_PASS = 0x1
FW_MARK_DROP = 0x2
```

Il funzionamento è il seguente:

1. `FW_OUTPUT` prova a recuperare dal conntrack una decisione già salvata con `CONNMARK --restore-mark`;
2. se il mark è `0x1`, il pacchetto viene accettato direttamente dal kernel;
3. se il mark è `0x2`, il pacchetto viene scartato direttamente dal kernel;
4. se non esiste ancora una decisione, il pacchetto entra in NFQUEUE;
5. il firewall userspace decide `ALLOW` o `DROP` e restituisce il pacchetto al kernel con mark `0x1` o `0x2`;
6. `FW_POSTROUTING` salva il mark con `CONNMARK --save-mark` e applica il verdetto finale.

Questo meccanismo riduce il numero di pacchetti inviati in userspace sui flussi che il conntrack riesce a riassociare, diminuendo l’overhead complessivo del firewall.

Nel caso di traffico UDP bloccato(DROP), è normale vedere più righe di log anche se i pacchetti vengono respinti. Il client può generare ritrasmissioni o nuove query con porte sorgenti diverse; inoltre UDP non ha una connessione persistente come TCP. Per verificare il blocco bisogna quindi guardare sia l’esito del client, ad esempio timeout o assenza di risposta, sia i contatori `FW_POSTROUTING` sulla regola `mark 0x2 DROP`.

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

Dopo la compilazione servono due componenti: il processo userspace e le regole `iptables` che scelgono quali pacchetti inviare a NFQUEUE. Si consiglia di usare due terminali:

Terminale 1, firewall userspace:

```bash
sudo ./firewall firewall.conf
```

Terminale 2, regole Netfilter per scegliere cosa mandare a NFQUEUE:

```bash
sudo ./scripts/fw_mark_cleanup.sh
sudo ./scripts/fw_mark_setup.sh -p <protocol> -d <dst_ip> [ports...]
```

Lo script richiede esplicitamente almeno una porta da intercettare; non installa porte di default. Protocollo e destinazione possono essere scelti in base al test:

Esempio:
```bash
sudo ./scripts/fw_mark_setup.sh -p tcp -d 127.0.0.1 80 23 443
```

Prima di cambiare protocollo, destinazione o insieme di porte, eseguire `fw_mark_cleanup.sh` per rimuovere eventuali jump precedenti.


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

Lo smoke test può richiedere qualche secondo in più perché il controllo sulla porta 23 genera un tentativo TCP che viene droppato. In questo caso il kernel può ritrasmettere alcuni SYN prima di chiudere il tentativo; è normale vedere più righe `DROP` con la stessa porta sorgente nel log.

## Test consigliati

### Test TCP ACCEPT con riuso del mark

Questo test verifica che il traffico TCP permesso venga analizzato in userspace solo all'inizio della connessione e che i pacchetti successivi vengano gestiti dal kernel tramite `CONNMARK`.

Terminale 1:

```bash
make firewall
sudo ./firewall firewall.conf
```

Terminale 2:

```bash
sudo ./scripts/fw_mark_cleanup.sh
sudo ./scripts/fw_mark_setup.sh -p tcp -d 127.0.0.1 80
sudo python3 -m http.server 80 --bind 127.0.0.1
```

Terminale 3:

```bash
curl http://127.0.0.1/
curl http://127.0.0.1/
curl http://127.0.0.1/
sudo ./scripts/fw_mark_status.sh
```

Risultato atteso:

* i tre `curl` devono ricevere una risposta HTTP;
* nel log del firewall devono comparire decisioni `ACCEPT` per traffico TCP verso porta 80;
* nei contatori, `FW_OUTPUT / NFQUEUE` deve aumentare per i primi pacchetti analizzati;
* `FW_OUTPUT / mark 0x1 ACCEPT` deve aumentare, indicando che pacchetti successivi sono stati accettati direttamente dal kernel;
* `FW_POSTROUTING / mark 0x1 ACCEPT` deve aumentare, indicando che il mark `PASS` e' stato applicato e salvato.

### Test UDP DROP

Questo test verifica che traffico UDP bloccato dalle regole venga marcato con `FW_MARK_DROP` e scartato in `FW_POSTROUTING`.

Terminale 1:

```bash
make firewall
sudo ./firewall firewall.conf
```

Terminale 2:

```bash
sudo ./scripts/fw_mark_cleanup.sh
sudo ./scripts/fw_mark_setup.sh -p udp -d <dns_server_ip> 53
host <domain> <dns_server_ip>
sudo ./scripts/fw_mark_status.sh
```

Risultato atteso:

* il comando `host` deve andare in timeout o non ricevere risposta;
* nel log del firewall devono comparire decisioni `DROP` per pacchetti UDP verso porta 53;
* `FW_POSTROUTING / mark 0x2 DROP` deve aumentare, indicando che il pacchetto marcato come DROP e' stato scartato dal kernel.

Nel caso UDP e' normale vedere piu' righe nel log: il client puo' generare ritrasmissioni o nuove query con porte sorgenti diverse. Questo non indica che i pacchetti siano stati accettati; il controllo importante e' il timeout lato client insieme ai contatori `mark 0x2 DROP`.

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
