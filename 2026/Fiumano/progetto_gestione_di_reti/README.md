# Relazione: monitoraggio di metriche di rete e di sistema con Prometheus


## Informazioni di contatto

**Studente:** Alessandro Fiumanò  
**Matricola:** 674559  
**E-mail:** a.fiumano1@studenti.unipi.it

## Struttura del progetto
Il progetto è strutturato nel seguente modo:
- **`README`**: questo documento, contiene la relazione del progetto che consiste in guida all'installazione e documentazione del lavoro svolto.
- **`start.py`**: script principale in Python che automatizza l'avvio dei demoni (Prometheus, Node exporter, Alertmanager), gestisce la configurazione della dashboard su Grafana e istanzia il server web locale (usando Flask) per stampare su terminale gli alert in tempo reale.
- **`prometheus.yml`**: file di configurazione base di Prometheus, contenente le istruzioni per lo scraping delle metriche dai vari target e i riferimenti ad Alertmanager.
- **`alerts.yml`**: file contenente le regole di alerting scritte in PromQL, definite dinamicamente tramite il calcolo delle medie mobili.
- **`alertmanager.yml`**: file di configurazione di Alertmanager, che si occupa di ricevere gli allarmi da Prometheus e instradarli verso il webhook esposto da `start.py`.
- **`dashboard.json`**: template preconfigurato della dashboard per visualizzare le timeseries e le metriche di riferimento interattivamente su Grafana. 
- **`experiments/`**: cartella contenente i log e le osservazioni effettuate nella fase di sperimentazione della dashboard.
- **`experiments/project_execution.txt`**: file di testo contenente l'output stampato su terminale da `start.py` durante la fase di sperimentazione.
- **`experiments/preview`**: png contenente una visualizzazione della dashboard al termine dell'esperimento, su cui verte la discussione dei risultati ottenuti.
- **`logs/`**: cartella generata automaticamente a runtime da `start.py` per raccogliere l'output di log dei demoni avviati in background. I log di Prometheus, Node Exporter e Alertmanager relativi alla fase di sperimentazione sono memorizzati in `experiments`.

## Installazione
In accordo con le specifiche di consegna, il progetto non contiene gli eseguibili necessari alla riproduzione dell'esperimento, ovvero Prometheus, Node Exporter e Alertmanager. Tali software possono essere scaricati dal sito ufficiale di Prometheus, al seguente link: https://prometheus.io/download/, selezionando il pacchetto adatto al proprio sistema operativo e alla propria architettura:

- Prometheus, versione 3.11.3 usata nel progetto;
- Node Exporter, versione 1.11.1 usata nel progetto;
- Alertmanager, versione 0.32.1 usata nel progetto.

Come software di supporto per la visualizzazione della dashboard è stato impiegato Grafana, nella versione Enterprise 13.0.2, scaricabile dal seguente link: https://grafana.com/grafana/download.

L'esecuzione dell'esperimento non richiede configurazioni particolarmente complesse; per questo motivo dovrebbero essere supportate anche release recenti diverse da quelle appena indicate. Dopo aver scaricato ed estratto gli archivi, i file `prometheus.yml` e `alerts.yml` devono essere collocati nella directory di Prometheus, mentre il file `alertmanager.yml` deve essere collocato nella directory di Alertmanager. Se nelle directory sono già presenti file omonimi, questi devono essere sovrascritti. I file di configurazione forniti sono comuni a Linux e macOS: la differenza principale riguarda il nome dell'interfaccia di rete monitorata, ad esempio `wlp1s0f0` su Linux o `en0` su macOS, che può essere sostituito automaticamente tramite `start.py`. Windows non è supportato, se usato potrebbero verificarsi incongruenze.

## Configurazione automatizzata
È possibile automatizzare l'avvio dell'ambiente usando il comando `start.py` allegato al progetto. Lo script può essere usato in due modalità:

1. **Solo avvio dei servizi**: avvia Prometheus, Node Exporter, Alertmanager e il server Flask per la ricezione degli alert;
2. **Configurazione e avvio**: oltre ad avviare i servizi, configura la dashboard Grafana e le regole di alerting sostituendo automaticamente l'interfaccia di rete da monitorare nei file comuni a Linux e macOS.

Nel primo caso è sufficiente fornire i percorsi delle directory dei tre software di monitoraggio:

```bash
python3 start.py \
  --prometheus-dir /path/to/prometheus \
  --node-exporter-dir /path/to/node_exporter \
  --alertmanager-dir /path/to/alertmanager
```

Nel secondo caso devono essere forniti anche `--dashboard` e `--device`:

```bash
python3 start.py \
  --prometheus-dir /path/to/prometheus \
  --node-exporter-dir /path/to/node_exporter \
  --alertmanager-dir /path/to/alertmanager \
  --dashboard dashboard.json \
  --device en0
```

I parametri `--dashboard` e `--device` devono essere usati insieme: se viene specificato solo uno dei due, lo script termina segnalando l'errore. Quando si usa la modalità di configurazione e avvio, Grafana deve essere già in esecuzione prima di invocare `start.py`, poiché lo script utilizza le API HTTP di Grafana su `http://localhost:3000` per configurare il datasource Prometheus e caricare la dashboard.

### Parametri di `start.py`
- `--prometheus-dir` *(obbligatorio)* — percorso della directory di Prometheus;
- `--node-exporter-dir` *(obbligatorio)* — percorso della directory di Node Exporter;
- `--alertmanager-dir` *(obbligatorio)* — percorso della directory di Alertmanager;
- `--dashboard` *(opzionale)* — percorso del file JSON della dashboard Grafana allegata al progetto, comune a Linux e macOS;
- `--device` *(opzionale)* — interfaccia di rete da monitorare, ad esempio `wlp1s0` su Linux o `en0` su macOS;
- `--grafana-user` *(default: `admin`)* — username di Grafana;
- `--grafana-password` *(default: `admin`)* — password di Grafana.

## Configurazione manuale
In alternativa alla configurazione automatica, è possibile configurare manualmente Grafana tramite interfaccia web. Anche in questo caso è necessario avviare prima i servizi di monitoraggio con `start.py`, fornendo almeno i percorsi di Prometheus, Node Exporter e Alertmanager:

```bash
python3 start.py \
  --prometheus-dir /path/to/prometheus \
  --node-exporter-dir /path/to/node_exporter \
  --alertmanager-dir /path/to/alertmanager
```

Su Ubuntu, se Grafana è installato come servizio di sistema, può essere avviato con:

```bash
sudo systemctl start grafana-server
```

Una volta avviato Grafana, collegarsi all'indirizzo `http://localhost:3000`. Al primo accesso le credenziali predefinite sono `admin` come username e `admin` come password; Grafana può richiedere di impostare una nuova password, ma per un ambiente di test locale è possibile saltare il passaggio.

Dalla GUI di Grafana, aprire la sezione **Connections/Data sources**, selezionare **Add data source** e scegliere **Prometheus**. Nella pagina di configurazione impostare il campo relativo all'URL del server Prometheus con `http://localhost:9090`, quindi salvare usando **Save & test**. Successivamente, dalla sezione **Dashboards**, importare una nuova dashboard caricando il file JSON allegato al progetto, comune a Linux e macOS. A questo punto la configurazione del tool di visualizzazione è completata ed è possibile osservare le metriche raccolte durante l'esecuzione dell'esperimento.


## Introduzione allo strumento e obiettivi
L'obiettivo del progetto è monitorare metriche di rete e di sistema di un host al variare del traffico; si procede quindi a descrivere l'esperimento e l'ambiente di esecuzione utilizzato. L'ambiente di esecuzione monta macOS 26.5.1, con 16 GB di RAM a disposizione e l'interfaccia di rete monitorata assume la denominazione di sistema `en0`. Il lavoro prevede l'utilizzo di Prometheus come database temporale, affiancato a Grafana per la visualizzazione della dashboard rappresentativa dell'esperimento. L'architettura consiste nell'interazione di Prometheus con Node Exporter, sorgente di scrape delle metriche via HTTP per la raccolta dati. È presente infine un'ultima componente, Alertmanager, adibita alla gestione degli alert generati in caso di anomalie. Gli alert vengono inoltre visualizzati in tempo reale su terminale tramite lo script Python `start.py`, responsabile anche dell'avvio delle componenti considerate.

Prometheus è un sistema di monitoraggio basato su time series, progettato per la raccolta sequenziale di campioni nel tempo. La piattaforma utilizza un linguaggio proprietario, PromQL, per la formulazione delle query, tipicamente formattate nel seguente modo:

```promql
nome_metrica{label="valore"}[range]
```

Il nome della metrica identifica la grandezza osservata, le label permettono di filtrare specifiche serie temporali, mentre `range` qualifica un intervallo temporale da cui estrarre i campioni disponibili. Quest'ultimo parametro non è sempre presente: tipicamente viene usato in combinazione con valori di tipo counter, al fine di misurare dati omogenei nell'intervallo temporale specificato.

Come già accennato, Prometheus interroga periodicamente Node Exporter tramite richieste HTTP per la raccolta dei dati, che vengono visualizzati interattivamente su Grafana in accordo a query appositamente definite. A tal proposito, Prometheus è stato configurato con `scrape_interval=5s` e `evaluation_interval=5s`, intervalli di tempo ragionevoli rispettivamente per lo scrape verso Node Exporter e per la valutazione delle alert rules. Una volta avviato `start.py`, è possibile visualizzare la dashboard interattiva su Grafana all'indirizzo `localhost:3000`, previa esecuzione sull'host bersaglio. Le regole di alert sono definite in `alerts.yml`, mentre la configurazione di Prometheus è definita in `prometheus.yml`.

## Query impiegate
Molti dati saranno raccolti grazie all'impiego della funzione `rate`, che in PromQL calcola, sull'ultimo intervallo temporale di riferimento, la variazione media del counter per unità di tempo:

```text
(valore_finale - valore_iniziale) / durata_intervallo
```
Questo procedimento è necessario per andare a modellare le time series che si originano da counters: tale funzione permette di trasformare queste series da non stazionarie a stazionarie, permettendone una visualizzazione più chiara nel tempo. Si descrivono in seguito le queries impiegate.

1. Pacchetti ricevuti/s, media 1 min

```promql
rate(node_network_receive_packets_total{job="node", device="wlp1s0f0"}[1m])
```

Misura il numero medio di pacchetti ricevuti al secondo sull’interfaccia wlp1s0f0. Reagisce quando aumenta o diminuisce il numero di pacchetti in ingresso.

2. Byte ricevuti/s, media 1 min

```promql
rate(node_network_receive_bytes_total{job="node", device="wlp1s0f0"}[1m])
```

Misura il volume medio di byte ricevuti al secondo. Serve per distinguere un traffico fatto da tanti pacchetti piccoli da un traffico con grande quantità di dati. Reagisce quando cresce il volume di traffico in ingresso.

3. Pacchetti trasmessi/s, media 1 min

```promql
rate(node_network_transmit_packets_total{job="node", device="wlp1s0f0"}[1m])
```

Misura i pacchetti inviati al secondo sull'interfaccia wlp1s0f0. Reagisce se l’host comincia a trasmettere più pacchetti, per esempio risposte di rete o traffico generato localmente.

4. Byte trasmessi/s, media 1 min

```promql
rate(node_network_transmit_bytes_total{job="node", device="wlp1s0f0"}[1m])
```

Misura il volume di byte trasmessi al secondo. Reagisce quando aumenta il traffico in uscita in termini di byte.

5. Utilizzo CPU (%), media 1 min

```promql
100 * (1- avg by (instance) (rate(node_cpu_seconds_total{job="node", mode="idle"}[1m])))
```

Calcola la percentuale di CPU usata partendo dal tempo idle. Se la CPU è idle all’80%, allora è usata al 20%. Serve per vedere se il traffico anomalo impatta anche il carico del sistema. Reagisce quando l’host lavora di più: processi, rete, kernel, Prometheus/node_exporter, ecc.

6. Memoria usata (%)

```promql
100 * (1 - node_memory_MemAvailable_bytes{job="node"} / node_memory_MemTotal_bytes{job="node"})
or
100 * (1 - (node_memory_free_bytes{job="node"} + node_memory_inactive_bytes{job="node"}) / node_memory_total_bytes{job="node"})
```

Calcola la percentuale di memoria usata. L'operatore `or` permette di supportare sia Linux sia macOS nello stesso pannello: su Linux Node Exporter espone tipicamente metriche come `node_memory_MemAvailable_bytes` e `node_memory_MemTotal_bytes`, mentre su macOS possono essere disponibili metriche con nomi diversi, come `node_memory_free_bytes`, `node_memory_inactive_bytes` e `node_memory_total_bytes`. Essendo una gauge, la memoria rappresenta lo stato corrente del sistema e reagisce quando cambia la quantità di memoria disponibile.

7.  Stato node_exporter

```promql
up{job="node"}
```

Vale 1 se Prometheus riesce a contattare node_exporter, 0 se non riesce. Serve come metrica di disponibilità del target to scrape. 

Infine, sono state aggiunte altre due query per il monitoraggio degli alerts attivi e della loro cronologia, in supporto alle notifiche attive su terminale gestite da Alertmanager.

## Configurazione: gestione dell'alerting 
Si descrivono in seguito gli alert che sono stati adoperati per intercettare anomalie, intese come improvvisi aumenti di traffico. È stato scelto di non configurare delle soglie statiche basate su valori ricavati empiricamente dal comportamento al caso medio della LAN, bensì di fornire condizoni di guardia sensibili alle variazioni dei trend. Pur essendo dinamici, gli alert sono stati calibrati per rilevare variazioni improvvise durante una finestra di monitoraggio di circa 5 minuti; in un sistema operativo continuativamente, invece, sarebbe opportuno costruire la baseline su intervalli più lunghi, ad esempio giornalieri, così da ottenere segnalazioni più affidabili.

1. NodeExporterDown
```promql
up{job="node"} == 0
```
Scatta quando Prometheus non riesce a raccogliere metriche da node_exporter. È fondamentale perché, se node_exporter non è raggiungibile, tutte le metriche dell'host monitorato smettono di essere aggiornate.

2. CounterPacchettiReteMancante
```promql
absent_over_time(node_network_receive_packets_total{job="node", device="wlp1s0f0"}[30s])
```
Scatta se la serie dei pacchetti ricevuti non produce campioni per 30 secondi. In caso di assenza di dati non viene inventato alcun valore, per esempio, tramite interpolazione.

3. PacchettiIngressoElevati
```promql
rate(node_network_receive_packets_total{job="node", device="wlp1s0f0"}[30s]) 
          > 
(avg_over_time(rate(node_network_receive_packets_total{job="node", device="wlp1s0f0"}[30s])[5m:15s]) * 3 + 100)
```
Scatta quando il numero medio di pacchetti ricevuti al secondo negli ultimi 30 secondi supera tre volte la media calcolata sugli ultimi 5 minuti, con un margine aggiuntivo di 100 pacchetti al secondo. In questo contesto, [5m:15s] indica che, per costruire la media di riferimento, Prometheus valuta rate(...[30s]) ogni 15 secondi lungo gli ultimi 5 minuti. È uno degli alert principali per rilevare improvvisi aumenti di traffico in ingresso sull'interfaccia monitorata.

4. PacchettiUscitaElevati
```promql
rate(node_network_transmit_packets_total{job="node", device="wlp1s0f0"}[30s]) 
          > 
(avg_over_time(rate(node_network_transmit_packets_total{job="node", device="wlp1s0f0"}[30s])[5m:15s]) * 3 + 50)
```
Scatta quando il numero medio di pacchetti trasmessi al secondo negli ultimi 30 secondi supera tre volte la media calcolata sugli ultimi 5 minuti, con un margine aggiuntivo di 50 pacchetti al secondo. Serve a rilevare improvvisi aumenti del traffico in uscita dall'interfaccia monitorata.

5. ByteIngressoElevati
```promql
rate(node_network_receive_bytes_total{job="node", device="wlp1s0f0"}[30s]) 
          > 
(avg_over_time(rate(node_network_receive_bytes_total{job="node", device="wlp1s0f0"}[30s])[5m:15s]) * 3 + 20000)
```
Scatta quando il volume medio di byte ricevuti al secondo negli ultimi 30 secondi supera tre volte la media calcolata sugli ultimi 5 minuti, con un margine aggiuntivo di 20.000 byte al secondo. Questo alert permette di rilevare improvvisi aumenti del volume di traffico in ingresso, non sempre infatti corrispondono a un incremento altrettanto marcato del numero di pacchetti.

6. ByteUscitaElevati
```promql
rate(node_network_transmit_bytes_total{job="node", device="wlp1s0f0"}[30s]) 
          > 
(avg_over_time(rate(node_network_transmit_bytes_total{job="node", device="wlp1s0f0"}[30s])[5m:15s]) * 3 + 20000)
```
Scatta quando il volume medio di byte trasmessi al secondo negli ultimi 30 secondi supera tre volte la media calcolata sugli ultimi 5 minuti, con un margine aggiuntivo di 20.000 byte al secondo. Completa il monitoraggio del traffico in uscita, affiancando al controllo sul numero di pacchetti quello relativo alla quantità complessiva di dati trasmessi.

La configurazione di Alertmanager raggruppa gli alert per `alertname`, attende 10 secondi prima del primo invio, usa un intervallo di raggruppamento di 1 minuto e ripete gli alert non risolti ogni 4 ore. Gli alert sono inoltrati al webhook Flask locale esposto da `start.py` su `http://127.0.0.1:5001/`, che li stampa in tempo reale sul terminale.

In caso di assenza di dati, Grafana mostra un valore nullo/interrotto quando Prometheus non restituisce alcun valore per quella serie nel timestamp visualizzato. Per le query `rate(...[1m])` ciò accade se nella finestra di 1 minuto non ci sono almeno due campioni del counter; per le metriche istantanee/gauge, invece, accade quando non esiste un campione recente entro il lookback di Prometheus o la serie è assente.

## Esecuzione dell'esperimento
Oltre al monitoraggio passivo delle metriche citate, l'esperimento prevede la simulazione di un disservizio della rete, generato tramite un traffico arp anomalo provocato da un secondo host nella LAN, sfruttando un'apposita modifca al programma psend affrontato durante il corso. L'intera simulazione ha una durata di 15 minuti ed è divisa in varie fasi:
- Avvio + fase stabile (circa 5 minuti): avvio di `start.py` osservazione passiva della dashboard senza interazione di alcun tipo.
- Fase di stress (circa 5 minuti): generazione di traffico ARP anomalo da un secondo host nella LAN, formato da ARP request con MAC sorgente variabile. Il sender chiede in continuazione il target IP appartenente all'host bersaglio, costringendolo a rispondere.
- Fase di recupero (circa 7 minuti): interruzione della generazione di traffico ARP e verifica della successiva stabilizzazione.
La durata di ciascuna fase è stata impostata anche in base ad alcuni parametri di configurazione: scrape/evaluation ogni 5 secondi permettono la raccolta di un numero rilevante di campioni, mentre il ritardo iniziale di 10 secondi configurato in Alertmanager non intacca il rilevamento delle anomalie considerate.


## Osservazioni e conclusioni
Dopo la conclusione della fase stabile, l'esecuzione dell'esperimento ha mostrato un sensibile aumento del traffico di byte e pacchetti sia in uscita che in entrata, correttamente intercettato dagli alert. Le quattro time series relative a tx pkts/s, rx pkts/s, tx Bps e rx Bps mostrano il medesimo andamento, in quanto l'host destinatario risponde alle arp request con il proprio MAC. Successivamente all'aumento improvviso di traffico, le metriche appena citate si sono stabilizzate intorno a nuovi valori, per poi crollare ripidamente al termine della fase di stress. 