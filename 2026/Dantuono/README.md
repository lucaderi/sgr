# Netmon — Monitor dei servizi TCP/UDP esposti su Linux

Progetto finale per il corso di **Gestione di Rete**.

**Studente:** _[Francesco D'Antuono]_
**Email:** _[f.dantuono1@studenti.unipi.it]_

## Descrizione

**Netmon** è un monitor scritto in C per sistemi Linux che osserva nel tempo i servizi TCP e UDP esposti dall'host.

Il programma interroga direttamente il kernel tramite **Netlink (`NETLINK_SOCK_DIAG`)**, associa i socket ai processi tramite `/proc`, confronta snapshot successivi e rileva l'apertura e la chiusura dei servizi. Le informazioni raccolte vengono esportate nel formato testuale di Prometheus e visualizzate tramite **Grafana**.

L'obiettivo è rispondere in modo semplice alla domanda:

> Quale processo sta esponendo quale porta TCP o UDP su questo host Linux?

## Architettura

Il flusso dei dati è il seguente:

```text
Linux kernel sockets
        |
        | NETLINK_SOCK_DIAG
        v
     Netmon
        |
        | associazione inode -> processo tramite /proc
        v
   netmon.prom
        |
        | textfile collector
        v
 node_exporter
        |
        | HTTP scrape
        v
   Prometheus
        |
        v
     Grafana
```

**Netmon** e **node_exporter** vengono eseguiti direttamente sull'host Linux, mentre **Prometheus** e **Grafana** vengono avviati tramite Docker Compose.

## Individuazione dei servizi

Netmon supporta esclusivamente **IPv4**.

Per TCP vengono considerati soltanto i socket nello stato `LISTEN`; connessioni attive come `ESTABLISHED`, `TIME_WAIT` o `SYN_SENT` non vengono quindi interpretate come servizi esposti.

Per UDP, non esistendo uno stato equivalente a `LISTEN`, vengono considerati i socket IPv4 con porta locale diversa da zero. Questo significa che, allo stato attuale, possono comparire anche socket UDP connessi usati da applicazioni client.

Tutti i binding appartenenti alla rete di loopback `127.0.0.0/8` vengono esclusi. Sono invece considerati i binding wildcard (`0.0.0.0`) e quelli su indirizzi IPv4 non-loopback.

L'indirizzo locale viene utilizzato soltanto per il filtraggio: un servizio viene identificato logicamente dalla tripla:

```text
(processo, protocollo, porta)
```

Ad esempio:

```text
nginx, tcp, 80
nginx, tcp, 443
sshd , tcp, 22
```

Binding dello stesso processo, protocollo e porta su indirizzi locali differenti vengono aggregati in un unico servizio.

## Associazione socket-processo

Netlink restituisce, tra le altre informazioni, l'inode del socket. Netmon utilizza questo valore per cercare il relativo file descriptor in:

```text
/proc/<pid>/fd/*
```

Un collegamento simbolico del tipo:

```text
socket:[123456]
```

permette di associare l'inode a un PID. Il nome del processo viene poi letto da:

```text
/proc/<pid>/comm
```

Se l'associazione non è possibile, il servizio non viene scartato ma viene esportato con:

```text
process="unknown"
```

## Rilevamento delle variazioni

Il monitor esegue una scansione periodica e confronta lo snapshot corrente con quello precedente.

Sono rilevati due eventi:

- **OPEN**: compare una nuova combinazione `processo + protocollo + porta`;
- **CLOSE**: una combinazione precedentemente presente scompare.

Con l'opzione `--verbose`, gli eventi sono mostrati anche sul terminale, ad esempio:

```text
[open] process=python3 protocol=tcp port=8080
[close] process=python3 protocol=tcp port=8080
```

I servizi presenti al momento dell'avvio costituiscono lo snapshot iniziale e non incrementano il contatore degli eventi `OPEN`.

## Metriche Prometheus

Netmon pubblica le metriche in un file `.prom` letto dal **textfile collector** di node_exporter.

| Metrica | Descrizione |
| --- | --- |
| `netmon_services{protocol="tcp \| udp"}` | Numero corrente di servizi per protocollo |
| `netmon_service_up{process,protocol,port}` | Servizi attualmente presenti |
| `netmon_process_services{process,protocol}` | Numero di porte usate da ciascun processo |
| `netmon_open_events_total` | Numero cumulativo di eventi OPEN |
| `netmon_close_events_total` | Numero cumulativo di eventi CLOSE |
| `netmon_last_success_timestamp_seconds` | Timestamp dell'ultima raccolta Netlink completata con successo |
| `netmon_collection_errors_total` | Numero di errori di raccolta Netlink |

La pubblicazione del file è atomica: Netmon scrive prima un file temporaneo, esegue `flush` e `fsync` e infine usa `rename()` per sostituire il file precedente. In questo modo node_exporter non legge mai un file parzialmente scritto.

In caso di errore durante una raccolta Netlink, l'ultimo snapshot valido viene mantenuto e non vengono generati falsi eventi `CLOSE`.

## Prerequisiti

Il progetto richiede un sistema **Linux** con:

- compilatore C con supporto C11;
- `make`;
- `libcap` e relativi header di sviluppo;
- Docker Engine;
- Docker Compose;
- `node_exporter` con supporto al textfile collector.

### Installazione e avvio di node_exporter

Installare `node_exporter` tramite `apt`:

```bash
sudo apt update
sudo apt install prometheus-node-exporter

```

## Compilazione

Dalla directory del progetto:

```bash
make
```

Il comando genera l'eseguibile:

```text
./netmon
```

Per rimuovere i file prodotti dalla compilazione:

```bash
make clean
```

## Configurazione iniziale

Creare le directory utilizzate dai componenti del progetto:

```bash
mkdir -p monitoring/node_exporter
mkdir -p monitoring/prometheus
mkdir -p monitoring/grafana
```

Prometheus e Grafana vengono eseguiti con l'UID/GID configurato all'inizio di `compose.yaml`:

```yaml
x-container-user: &container-user "1000:1000"
```

Verificare i valori del proprio utente con:

```bash
id -u
id -g
```

Se sono diversi da `1000:1000`, aggiornare il valore in `compose.yaml` prima dell'avvio.

## Struttura del programma C

L'implementazione è contenuta principalmente in `netmon.c`.

### Raccolta dei socket tramite Netlink

Le funzioni `request_sockets()`, `receive_sockets()` e `collect_services()` comunicano con il kernel attraverso `NETLINK_SOCK_DIAG`.

Per ogni ciclo vengono richiesti:

- socket TCP IPv4 in stato `LISTEN`;
- socket UDP IPv4 con porta locale diversa da zero.

I risultati ricevuti dal kernel vengono filtrati e inseriti nello snapshot corrente.

### Snapshot dei servizi

Ogni servizio è rappresentato da una struttura `service_t` contenente principalmente:

```text
protocollo
porta
inode del socket
nome del processo
```

I servizi raccolti vengono mantenuti in una struttura `snapshot_t`. Lo snapshot rappresenta quindi lo stato dei servizi esposti in un preciso momento.

Prima del confronto i servizi vengono ordinati per:

```text
processo + protocollo + porta
```

in modo da poter aggregare eventuali socket equivalenti.

### Associazione socket-processo

La funzione `resolve_processes()` usa l'inode ottenuto da Netlink per cercare il processo proprietario attraverso `/proc/<pid>/fd`.

Una volta trovata la corrispondenza, il nome del processo viene letto da `/proc/<pid>/comm` e associato al servizio.

Netlink rimane quindi la sorgente utilizzata per scoprire i socket, mentre `/proc` viene usato esclusivamente per completare l'informazione con il processo proprietario.

### Confronto tra snapshot

La funzione `compare_snapshots()` confronta lo snapshot precedente con quello appena raccolto.

Da questo confronto vengono individuati:

- `OPEN`, quando compare un nuovo servizio;
- `CLOSE`, quando un servizio precedentemente presente scompare.

I relativi contatori vengono aggiornati e, se è attiva l'opzione `--verbose`, l'evento viene stampato sul terminale.

### Esportazione delle metriche

Le funzioni `render_metrics()` e `publish_metrics()` trasformano lo stato corrente e i contatori in metriche compatibili con Prometheus.

Il file `.prom` viene scritto prima in un file temporaneo e poi sostituito tramite `rename()`, evitando che node_exporter possa leggere dati incompleti durante l'aggiornamento.

### Gestione dei privilegi

La funzione `restrict_privileges()` gestisce l'avvio tramite `sudo`.

Dopo la fase iniziale Netmon torna all'utente che lo ha avviato e conserva soltanto le capability necessarie per leggere le informazioni sui processi di altri utenti. Il ciclo di monitoraggio non viene quindi eseguito con privilegi completi di root.

### Ciclo principale

La funzione `main()` coordina tutte le componenti:

```text
raccolta Netlink
      |
      v
associazione con /proc
      |
      v
ordinamento dello snapshot
      |
      v
confronto con lo snapshot precedente
      |
      v
aggiornamento delle metriche
      |
      v
attesa fino alla scansione successiva
```

Il ciclo continua fino alla ricezione di `SIGINT` o `SIGTERM`, ad esempio quando il programma viene terminato con `Ctrl+C`.

## Avvio rapido

Dopo aver completato la configurazione iniziale, l'intero progetto può essere avviato con:

```bash
export GRAFANA_ADMIN_PASSWORD='password'
./start.sh
```

Lo script:

1. compila Netmon;
2. avvia node_exporter sull'host con il textfile collector;
3. avvia Prometheus e Grafana tramite Docker Compose;
4. esegue Netmon in foreground con intervallo di 5 secondi.

Premendo `Ctrl+C` vengono arrestati Netmon e il node_exporter avviato dallo script e viene eseguito `docker compose down`.

Le interfacce web sono disponibili su:

```text
Prometheus: http://localhost:9090
Grafana:    http://localhost:3000
```

L'utente amministratore predefinito di Grafana è `admin`; la password è quella impostata nella variabile `GRAFANA_ADMIN_PASSWORD`.

## Avvio manuale

Per osservare separatamente i vari componenti è possibile avviarli in terminali differenti.

### 1. node_exporter

```bash
node_exporter \
  --web.listen-address=0.0.0.0:9100 \
  --collector.textfile.directory="$PWD/monitoring/node_exporter"
```

### 2. Netmon

```bash
make

sudo ./netmon \
  --interval 1 \
  --output "$PWD/monitoring/node_exporter/netmon.prom" \
  --verbose
```

L'intervallo di un secondo è utile per una dimostrazione. Il valore predefinito è 5 secondi.

### 3. Prometheus e Grafana

```bash
export GRAFANA_ADMIN_PASSWORD='password'
docker compose up -d
```

## Opzioni di Netmon

```text
Usage: netmon --output PATH [options]

-i, --interval SECONDS
    Intervallo di polling compreso tra 1 e 86400 secondi. (24 ore)
    Default: 5 secondi.

-o, --output PATH
    File Prometheus di output. Il percorso deve terminare in .prom.

-v, --verbose
    Mostra i servizi iniziali e gli eventi OPEN/CLOSE.

-h, --help
    Mostra l'help.
```

## Gestione dei privilegi

Per poter associare anche i socket appartenenti a processi di altri utenti, Netmon può essere avviato con `sudo`.

Il monitor **non rimane in esecuzione come root**. Durante l'avvio:

1. recupera UID e GID dell'utente che ha invocato `sudo`;
2. elimina i gruppi supplementari;
3. passa all'utente chiamante;
4. conserva soltanto `CAP_SYS_PTRACE` e `CAP_DAC_READ_SEARCH`;
5. elimina le altre capability dal bounding set;
6. abilita `no_new_privs`;
7. verifica che il file delle metriche sia scrivibile;
8. inizia il ciclo di monitoraggio.

L'avvio senza `sudo` è possibile, ma alcuni processi appartenenti ad altri utenti potrebbero essere riportati come `unknown`.

## Grafana

Il file `grafana/netmon-dashboard.json` contiene una dashboard già predisposta per visualizzare le principali metriche del progetto.

Per importarla:

1. aprire `http://localhost:3000`;
2. accedere a Grafana;
3. aprire **Dashboards → New → Import**;
4. caricare `netmon-dashboard.json`;
5. selezionare il datasource Prometheus se richiesto;
6. confermare l'importazione.

La dashboard include, tra gli altri, pannelli per:

- stato del target Netmon;
- errori di raccolta;
- numero di servizi TCP e UDP;
- elenco dei servizi TCP;
- elenco dei servizi UDP;
- numero di eventi OPEN e CLOSE negli ultimi 5 minuti;
- servizi raggruppati per processo;
- tempo trascorso dall'ultima scansione completata.

Immagine esempio della dashboard:
![description](./img/netmon-dashboard-img)

## Verifica del funzionamento

Con lo stack in esecuzione:

### Verifica del target Prometheus

Aprire `http://localhost:9090` ed eseguire:

```promql
up{job="netmon"}
```

Il risultato atteso è:

```text
1
```

Per vedere i servizi correnti:

```promql
netmon_service_up
```

## Test funzionale OPEN/CLOSE

Con Netmon in esecuzione in modalità `--verbose`, aprire un altro terminale e avviare un semplice server HTTP:

```bash
python3 -m http.server 8080 --bind 0.0.0.0
```

Dopo la scansione successiva Netmon dovrebbe rilevare un nuovo servizio TCP sulla porta 8080 e generare un evento `OPEN`.

Arrestare il server con `Ctrl+C`. Alla scansione successiva Netmon dovrebbe generare un evento `CLOSE`.

È possibile verificare anche il filtro del loopback con:

```bash
python3 -m http.server 8081 --bind 127.0.0.1
```

Questo listener non deve comparire nelle metriche dei servizi di Netmon.

## Test valgrind

Test eseguito con:

```bash
sudo valgrind \
  --leak-check=full \
  --show-leak-kinds=all \
  --track-origins=yes \
  --errors-for-leak-kinds=all \
  --error-exitcode=1 \
  ./netmon \
  --interval 5 \
  --output "$PWD/monitoring/node_exporter/netmon.prom" \
  --verbose
```

Produce in output da valgrind:

```text
==119605== HEAP SUMMARY:
==119605==     in use at exit: 0 bytes in 0 blocks
==119605==   total heap usage: 86 allocs, 86 frees, 2,510,304 bytes allocated
==119605==
==119605== All heap blocks were freed -- no leaks are possible
==119605==
==119605== For lists of detected and suppressed errors, rerun with: -s
==119605== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

# Test funzionali Netmon

Questi script verificano i comportamenti principali di Netmon direttamente sul file Prometheus generato dal programma.

Prima di eseguirli, compilare il progetto dalla directory principale:

```bash
make
```

Poi eseguire l'intera suite:

```bash
./tests/run_all.sh
```

I test coprono:

| Test | Verifica |
| --- | --- |
| `test_tcp.sh` | un listener TCP su `0.0.0.0` viene rilevato |
| `test_loopback.sh` | un listener TCP su `127.0.0.1` viene ignorato |
| `test_udp.sh` | un socket UDP associato a `0.0.0.0` viene rilevato |
| `test_open_close.sh` | apertura e chiusura di un servizio incrementano i relativi contatori |

Gli script avviano una propria istanza di Netmon con intervallo di raccolta di 1 secondo e utilizzano una directory temporanea per il file `.prom`. Non richiedono Prometheus, Grafana o node_exporter.

Per evitare conflitti con servizi già presenti vengono usate, di default, le porte TCP `18080`, `18081`, `18082` e UDP `19999`. È possibile cambiarle tramite le variabili `TCP_TEST_PORT`, `LOOPBACK_TEST_PORT`, `EVENT_TEST_PORT` e `UDP_TEST_PORT`.

## Limiti attuali

- supporto esclusivamente IPv4;
- i socket UDP con porta locale diversa da zero possono includere anche client UDP connessi, ad esempio traffico QUIC;
- il progetto osserva l'esposizione a livello di socket e non verifica firewall, NAT, `iptables` o `nftables`;
- l'identità del servizio è `processo + protocollo + porta`: la ricreazione dello stesso socket tra due snapshot non viene interpretata come restart;
- eventi molto brevi che si aprono e si chiudono interamente tra due intervalli di polling possono non essere osservati;
- se `/proc` non consente di risolvere il processo proprietario, il servizio viene mantenuto come `unknown`;
- i contatori OPEN/CLOSE sono cumulativi soltanto per la durata del processo Netmon e ripartono da zero dopo un riavvio.

## Screenshot

**Terminale Netmon in modalità verbose** durante il test della porta 8080 con python:
![description](./img/test_funzionalita_python_img)

## Utilità pratica del progetto

Netmon non si limita a mostrare quali servizi TCP/UDP sono esposti in un determinato momento, ma rende disponibili a Prometheus informazioni che possono essere utilizzate da Grafana anche per creare **alert automatici** e individuare variazioni anomale nel tempo.

Un primo caso d'uso è il controllo della disponibilità di un servizio considerato essenziale. Ad esempio, se un server web deve mantenere attiva la porta TCP 443, è possibile creare in Grafana una regola di alert basata sulla seguente query PromQL:

```promql
absent(netmon_service_up{process="nginx",protocol="tcp",port="443"})
```

Se la metrica scompare, significa che Netmon non rileva più quel servizio tra quelli attualmente esposti. Grafana può quindi generare una notifica, permettendo di accorgersi rapidamente dell'arresto del processo, della chiusura della porta o di una modifica inattesa alla configurazione del servizio.

Un secondo utilizzo riguarda il numero di aperture e chiusure rilevate nel tempo. Netmon esporta i contatori cumulativi:

```text
netmon_open_events_total
netmon_close_events_total
```

Prometheus può calcolare quanti eventi si sono verificati in una determinata finestra temporale. Ad esempio:

```promql
increase(netmon_open_events_total[5m])
```

oppure:

```promql
increase(netmon_close_events_total[5m])
```

Su queste query è possibile impostare una soglia in Grafana. Un numero insolitamente elevato di eventi `OPEN` o `CLOSE` in pochi minuti può evidenziare, ad esempio, un servizio che viene continuamente avviato e arrestato, una configurazione instabile oppure processi che iniziano a esporre nuove porte con una frequenza non prevista.

È importante osservare che questi contatori riguardano **l'apertura e la chiusura dei servizi monitorati**, non il numero di connessioni TCP ricevute dal sistema. Un valore elevato di `netmon_open_events_total` indica quindi molte variazioni nell'insieme dei servizi esposti, non un elevato numero di client che si collegano a una porta.

Un ulteriore controllo può essere effettuato sul numero di porte esposte da ciascun processo tramite:

```promql
netmon_process_services
```

Ad esempio, una regola come:

```promql
netmon_process_services{process="nginx",protocol="tcp"} > 5
```

può essere usata quando si conosce il comportamento atteso di un processo e si vuole essere avvisati se questo inizia a utilizzare un numero di porte superiore alla norma. Analogamente, `netmon_services` permette di controllare il numero complessivo di servizi TCP e UDP presenti sul sistema.

Netmon esporta inoltre:

```text
netmon_last_success_timestamp_seconds
netmon_collection_errors_total
```

che permettono di controllare lo stato del monitor stesso. Una possibile regola per rilevare un monitor che non aggiorna più correttamente i dati è:

```promql
time() - netmon_last_success_timestamp_seconds > 30
```

oppure:

```promql
absent(netmon_last_success_timestamp_seconds)
```

In questo modo è possibile distinguere la scomparsa reale di un servizio da un problema del sistema di raccolta.

Nel complesso, l'utilità del progetto consiste quindi nel trasformare lo stato dei socket del sistema Linux in metriche storicizzabili e interrogabili. Questo permette di passare da una verifica manuale delle porte esposte a un monitoraggio continuo, con dashboard, storico temporale e alert configurabili in base alle esigenze dell'amministratore di sistema.

Netmon non sostituisce , un firewall o un sistema di analisi del traffico: non analizza i pacchetti e non determina se una porta sia effettivamente raggiungibile attraverso il firewall. Il suo obiettivo è fornire una visione semplice e continua dei **servizi che il sistema operativo sta esponendo a livello di socket** e delle loro variazioni nel tempo.

## File principali

|file|descrizione|
|--|--|
|netmon.c|implementazione del monitor|
|Makefile|compilazione|
|start.sh|avvio dell'intero stack|
|compose.yaml|Prometheus e Grafana|
|grafana/netmon-dashboard.json|Dashboard Grafana importabile|

## Tecnologie utilizzate

- C11
- Linux Netlink / `NETLINK_SOCK_DIAG`
- `/proc`
- Linux capabilities (`libcap`)
- Prometheus node_exporter textfile collector
- Prometheus
- Grafana
- Docker Compose
