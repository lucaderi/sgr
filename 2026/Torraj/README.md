Autore: Torraj Elio
Mail: e.torraj@studenti.unipi.it

## Descrizione
Ho provato a modificare il programma pcount e renderlo un bridge bidirezionale tra due interfaccie.
Non ho ancora provato ad applicare filtri sui pacchetti ricevuti.
In seguito spiego le modifiche apportate.

## Compilazione
gcc pbridge.c -o pbridge -lpcap -lpthread

## Utilizzo

./pbridge -i <interfaccia_ingresso> -o <interfaccia_uscita> [opzioni] (le opzioni non sono cambiate)


## Modifiche rispetto a pcount.c

### 1. Seconda interfaccia di rete (`pd2`)

È stata aggiunta la variabile globale `pcap_t *pd2` per gestire la seconda interfaccia, con la relativa apertura nel `main` tramite `pcap_open_live` e applicazione del filtro BPF. L'opzione `-o` è stata aggiunta al parsing degli argomenti.

### 2. Struttura `bridge_args`

Per passare più informazioni alla callback di pcap (che accetta un solo parametro `user`), è stata introdotta la struttura:

```c
struct bridge_args {
    pcap_t *in;                  /* interfaccia di ingresso */
    pcap_t *out;                 /* interfaccia di uscita   */
    char name[16];               /* nome del thread per i log */
    unsigned long long pkts;     /* pacchetti inoltrati da questo thread */
    unsigned long long bytes;    /* byte inoltrati da questo thread */
};
```

Questo permette a ogni thread di tenere contatori indipendenti e di sapere su quale interfaccia reinviare i pacchetti.

### 3. Inoltro dei pacchetti in `dummyProcesssPacket`

La callback ora riceve la `struct bridge_args` invece del semplice puntatore a device. È stata aggiunta la chiamata a `pcap_inject` per reinoltrare ogni pacchetto sull'interfaccia di uscita:

### 4. Due thread POSIX per la bidirezionalità

Il problema principale che ho riscontrato nell'usare due `pcap_loop` è che si tratta di una funzione bloccante: una volta avviata non ritorna mai, quindi la seconda non partirebbe mai.

La soluzione adottata è eseguire le due `pcap_loop` in parallelo su thread separati tramite `pthread`:

```c
void* thread_bridge(void *arg) {
    struct bridge_args *a = (struct bridge_args *)arg;
    pcap_loop(a->in, -1, dummyProcesssPacket, (u_char*)a);
    return NULL;
}

// nel main:
pthread_t t0, t1;
pthread_create(&t0, NULL, thread_bridge, &args0);  // eth0 → eth1
pthread_create(&t1, NULL, thread_bridge, &args1);  // eth1 → eth0
pthread_join(t0, NULL);
pthread_join(t1, NULL);
```

Il `main` si blocca su `pthread_join` aspettando che entrambi i thread terminino, cosa che avviene solo dopo Ctrl+C.

### 5. Aggiornamento di `sigproc`

Per fermare entrambi i thread alla pressione di Ctrl+C, è stata aggiunta la chiamata a `pcap_breakloop` anche per `pd2`:

```c
void sigproc(int sig) {
    pcap_breakloop(pd);
    pcap_breakloop(pd2);
}
```

### 6. Statistiche per interfaccia in `print_stats`

La funzione `print_stats` è stata estesa per mostrare le statistiche di entrambe le interfacce tramite `pcap_stats(pd, ...)` e `pcap_stats(pd2, ...)`, oltre ai contatori di pacchetti effettivamente inoltrati da ciascun thread (`args0.pkts`, `args1.pkts`).

---


Ci tenevo a specificare che mi sono fatto aiutare dall'AI, nello specifico per capire meglio il codice originale di pcount e psend, e quindi capire le funzioni pcap_loop e pcap_inject, e inoltre anche per modificare la funzione di print_stat in modo da avere un output decente.

Mi faccia sapere se il lavoro è corretto e se ci possono essere migliorie e/o consigli utili per scrivere meglio questo programma.

