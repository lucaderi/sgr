# pbridge

**Matteo Luzzetti**  
m.luzzetti1@studenti.unipi.it

---

## Descrizione

`pbridge.c` è un programma C che estende `pcount.c` trasformandolo in un **bridge di rete** tra due interfacce.

Il programma cattura i pacchetti in arrivo su un'interfaccia (`-i`) e li forwarda su una seconda interfaccia (`-o`), operando in modalità bidirezionale tramite `poll()`. È stato aggiunto il parametro `-D <dominio>` che risolve il dominio in IP tramite `getaddrinfo` e installa nel kernel un filtro BPF che scarta i pacchetti provenienti da quell'IP.

Il filtraggio avviene **nel kernel** tramite `pcap_setfilter`, prima che i pacchetti arrivino al programma. Questo significa che `pbridge` non vedrà i pacchetti scartati — è una scelta intenzionale per efficienza, evitando copie inutili di memoria.

### Differenze rispetto a `pcount.c`

- Aggiunto parametro `-o <interfaccia>` per specificare la seconda interfaccia
- Apertura e gestione di un secondo handle pcap (`pd2`)
- Loop principale basato su `poll()` invece di `pcap_loop()` per monitorare entrambe le interfacce contemporaneamente
- Aggiunta funzione `process_and_send()` che legge un pacchetto da un'interfaccia e lo invia sull'altra
- Aggiunto parametro `-D <dominio>` per scartare pacchetti provenienti da un dominio specifico
- Gestione del segnale di uscita tramite `sig_atomic_t stop` per terminare correttamente il loop principale
- Aggiunta funzione `resolve_domain()` che risolve un nome di dominio in indirizzo IPv4 tramite `getaddrinfo`
- Aggiunta funzione `ip_to_filter()` che costruisce la stringa BPF `src host <IP>` a partire dall'IP risolto

### Come funziona il filtro `-D`

```
-D "google.com"
       ↓
resolve_domain("google.com") → "142.250.180.46"
       ↓
ip_to_filter("142.250.180.46") → "src host 142.250.180.46"
       ↓
pcap_compile + pcap_setfilter → filtro installato nel kernel
       ↓
pacchetti da google.com scartati dal kernel prima di arrivare a pbridge
```

### Nota sulla combinazione di filtri

`-f` e `-D` non possono essere usati insieme — `pcap_setfilter` accetta un solo filtro attivo per interfaccia e il secondo sovrascrive il primo. Usare solo uno dei due parametri per volta.

---

## Prerequisiti

```bash
sudo apt-get install libpcap-dev
```

## Compilazione

```bash
gcc pbridge.c -o pbridge -lpcap
gcc pcount.c -o pcount -lpcap
gcc packet_send.c -o packet_send -lpcap
```

## Utilizzo

```
Usage: pbridge -i <device> -o <device> [-f <filter>] [-D <domain>] [-l <len>] [-v <1|2>] [-w <path>]

  -i <device>       Prima interfaccia (input)
  -o <device>       Seconda interfaccia (output)
  -f <filter>       Filtro BPF per la cattura (kernel) - non combinare con -D
  -D <domain>       Dominio da bloccare - scarta pacchetti con src IP del dominio
  -l <len>          Lunghezza di cattura (default: 256)
  -v <1|2>          Verbose
  -w <path>         Salva i pacchetti su file pcap
```

---

## Test

I test sono stati svolti su Ubuntu Linux con le seguenti interfacce:
- `enp0s1` — interfaccia fisica della VM (input)
- `veth1` — interfaccia virtuale (output), creata con:

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
```

Per inviare pacchetti di test è stato usato `packet_send.c`, che costruisce pacchetti raw con MAC sorgente `00:11:22:33:44:55`.

---

### Test 1 — bridge senza filtro

Verifica che il bridge forwardi correttamente i pacchetti da `enp0s1` a `veth1`.

**Terminale 1 — avvia pbridge:**
```bash
sudo ./pbridge -i enp0s1 -o veth1
```

**Terminale 2 — ascolta su veth1:**
```bash
sudo ./pcount -i veth1 -f "ether src 00:11:22:33:44:55" -v 1
```

**Terminale 3 — invia un pacchetto ARP:**
```bash
sudo ./packet_send -i enp0s1 -p arp -c 1
```

**Risultato atteso:** `pcount` mostra 1 pacchetto ARP su `veth1`. ✅

---

### Test 2 — filtro `-D` per dominio

Verifica che i pacchetti provenienti da un dominio specifico vengano scartati.

**Terminale 1:**
```bash
sudo ./pbridge -i enp0s1 -o veth1 -D "www.google.com"
```
Al termine pbridge stampa l'IP risolto:
```
Bridge from enp0s1 and veth1
Resolved www.google.com in 142.250.x.x
```

**Terminale 2:**
```bash
sudo ./pcount -i veth1 -v 1
```

**Terminale 3 — genera traffico verso google:**
```bash
curl https://google.com
```

**Risultato atteso:** `pcount` su `veth1` non vede nulla e `pbridge` non mostra pacchetti in arrivo. Questo è il comportamento corretto — il filtro è installato nel kernel tramite `pcap_setfilter`, quindi i pacchetti provenienti da google.com vengono scartati prima ancora di arrivare a `pbridge`. La prova che il filtro funziona è che senza `-D` `pcount` vedrebbe i pacchetti di risposta di `curl`, mentre con `-D` non vede nulla. ✅

