# pbridge

Obbiettivo: scrivere un file pbridge.c che permetta di fare da bridge a Livello 2 tra due interfacce di rete, inoltrando i pacchetti da una all'altra e viceversa prendendo spunto dai files pcount.c (che catturerà i pacchetti) e psend.c (che li invierà) dati dal docente e fare dei test riproducibili per accertarsi del corretto funzionamento. Codice creato sfruttando **libpcap**.

## Strumenti (files)

### pbridge
Scritto da me. Un **bridge di rete Layer 2** bidirezionale che inoltra frame Ethernet grezzi tra due interfacce usando `select` + `pcap_next_ex` (un fd per interfaccia). Entrambe le interfacce vengono aperte in modalità promiscua. Supporta filtri BPF per ciascuna interfaccia e stampa statistiche di throughput periodiche tramite `SIGALRM`.

```
Uso: pbridge -i <device> -o <device> [-f <filter>] [-F <filter>] [-l <len>] [-v <1|2>]

  -i <device>   Interfaccia di ingresso.
  -o <device>   Interfaccia di uscita.
  -f <filter>   Filtro BPF sull'interfaccia di ingresso (es. "not icmp").
  -F <filter>   Filtro BPF sull'interfaccia di uscita.
  -l <len>      Lunghezza di cattura (snap length).
  -v <1|2>      Verboso: 1 = intestazioni, 2 = intestazioni + payload hex.
```

### pcount
Dato dal docente. Uno strumento di **cattura pacchetti e statistiche**. Cattura da un'interfaccia live o legge da un file `.pcap`. Decodifica frame Ethernet, stampa le informazioni per pacchetto in modalità verbosa e riporta le statistiche di throughput ogni secondo.

```
Uso: pcount -i <device|path> [-f <filter>] [-w <path>] [-l <len>] [-v <1|2>]

  -i <device|path>  Interfaccia live o file pcap.
  -f <filter>       Filtro BPF (es. "tcp port 80").
  -w <path>         Salva i pacchetti catturati su file pcap.
  -l <len>          Lunghezza di cattura (snap length).
  -v <1|2>          Verboso: 1 = intestazioni, 2 = intestazioni + payload hex.
```

### psend
Dato dal docente. Uno strumento di **iniezione di pacchetti grezzi**. Invia uno dei template di frame Ethernet predefiniti (simple, ARP, ICMP echo, TCP SYN o custom) su un'interfaccia specificata tramite `pcap_inject`.

```
Uso: psend -i <interface> [-p <type>] [-c <count>]

  -i <interface>  Interfaccia di rete.
  -p <type>       Tipo di pacchetto: simple, arp, icmp, tcp_syn, custom (default: arp).
  -c <count>      Numero di pacchetti da inviare (default: 1).
```

## Requisiti (dipendenze)

- **libpcap** (`libpcap-dev` su Debian/Ubuntu).
- **Root / sudo** necessario a runtime (la cattura e l'iniezione di pacchetti grezzi richiedono privilegi elevati).
- **make** per compilare più facilmente.
- **gcc** per compilare files .c.

## Ambiente

Per cercare di creare un ambiente stabile, pulito, deterministico e riproducibile sono state create 3 macchine virtuali con [VMWare Fusion](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion) e [debian-13.4.0-arm64-netinst.iso](https://chuangtzu.ftp.acc.umu.se/debian-cd/current/arm64/iso-cd/debian-13.4.0-arm64-netinst.iso) (ARM per Apple Silicon M2).

Rete privata delle VMs, macchina host non connessa su di essa, DHCP disabilitato.<br><br>
Indirizzo di rete (comune a tutte le VM): **192.168.42.0/24**<br><br>
VMA ha nel mio caso interfaccia di rete __ens160__ (MAC: **00:50:56:2A:69:69**) ed avrà IP: **192.168.42.1**<br><br>
VMB ha nel mio caso interfaccia di rete __ens160__ (MAC: **00:50:56:26:74:33**) e __ens192__ (MAC: **00:50:56:38:EA:0E**) ed avrà IP: **NESSUNO, PER PORRE ENFASI CHE STIAMO LAVORANDO LIVELLO 2**<br><br>
VMC ha nel mio caso interfaccia di rete __ens160__ (MAC: **00:50:56:29:1E:74**) (sarebbe stato meglio cambiare nome per non confondersi con VMA, ma non sono riuscito, comunque non ha nulla a che fare con VMA) ed avrà IP: **192.168.42.2**

Ho usato una cartella condivisa tra host e guests per compilare ed eseguire i files, ma questa ovviamente è opzionale per i test.

Ogni macchina virtuale ha un file config.sh che esegue semplicemente alcuni comandi per configurare le impostazioni di rete e impostare manualmente gli IP, **modificarlo prima con i nomi delle proprie schede di rete**, poi effettuare i test.

## Compilazione

```bash
cd src
make clean  # Rimuove i binari compilati.
make        # I binari vengono generati in ../bin/
```

## Testing step by step

1. Scaricare VMWare Fusion (ed installarlo) e la ISO.
2. Creare le reti dalle preferenze di VMware, configurarle con i settings delle immagini di COMMON-SETTINGS.
3. Creare le VMs, configurarle con i settings delle immagini di VMA, VMB-Bridge e VMC ed installarci OS da ISO e se si desidera dare accesso alla cartella condivisa.
4. Riavviare le VMs.
5. Fare login, installare le dipendenze se necessario, in questo caso magari aggiungere un ulteriore adapter per avere la connessione ad internet, poi rimuoverlo.
6. Eseguire su ciascuna macchina il relativo ```sudo ./config-X.sh```.
7. Se si è scelto di usare la cartella condivisa, i config la monteranno in automatico e si potrà fare ```cd /mnt/hgfs/pbridge/src``` in VMB.
8. Su VMB, una volta nella cartella src, ```make && cd ..```.
9. Eseguire con ```sudo ./bin/pbridge``` con le impostazioni desiderate, di seguito l'esempio più articolato, il cui output è riportato in TESTING-RESULTS, che permette il ping da **192.168.42.2** a **192.168.42.1**, ma blocca il viceversa:<br>
Su VMB: ```sudo ./bin/pbridge -i ens160 -o ens192 -v 1 -f "not (icmp[icmptype] == 8) and src host 192.168.42.1 and dst host 192.168.42.2"```<br>
Su VMA: ```ping -c 4 192.168.42.2```<br>
Su VMC: ```ping -c 4 192.168.42.1```<br>
Ovviamente sostituire i nomi delle schede di rete con le proprie.

## Challenges (problemi) affrontati e risolti
Clonare la VMA per fare prima in VMB/VMC non è stata un'idea geniale, dato non riuscivo a capire come mai non funzionasse nulla nè nel bridge nè nella comunicazione tra le macchine, ho perso molto tempo, per poi scoprire che viene di default clonato anche il MAC address ed avere due schede con lo stesso MAC address sulla stessa rete non è un'esperienza piacevole.

## Perché non 2 threads, ma multiplexing?
Su consiglio del docente, per ottimizzare il fatto che nella vita reale solitamente Download Size >> Upload Size e quindi non è fair per i thread.

## Come sono implementati i filtri?
Usando i filtri low level di BPF per non reinventare la ruota.

## Il bridge è bidirezionale?
Sì, fa passare richieste da VMA e risposte da VMC e viceversa da VMC richieste rivolte a VMA e risposte da VMA indietro a VMC.<br>
I filtri sono indipendentemente configurabili su entrambe le schede di rete.

## Struttura delle cartelle

```
pbridge/
├── src/         # Sorgenti.
│   ├── pbridge.c
│   ├── pcount.c
│   ├── psend.c
│   └── Makefile
├── bin/          # Binari compilati (ignorati da git).
│   ├── pbridge
│   ├── pcount
│   └── psend
├── VMA/          # Impostazioni rete macchina A e config.
├── VMB-Bridge/   # Impostazioni rete macchina B e config. Noti 2 schede di rete.
├── VMC/          # Impostazioni rete macchina C e config.
└── COMMON-SETTINGS/ # Impostazioni comuni.
```
