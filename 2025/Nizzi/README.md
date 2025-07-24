per compilare: make 
per eseguire: sudo ./RilevatorePortScan

librerie:
std.h, stdlib.h, string.h 
pcap.h per lo sniffing dei pacchetti
unistd.h per le funzioni POSIX
time.h per gestire i timestamp
signal.h per la gestione dei segnali
netinet/ip.h, netinet/tcp.h, arpa/inet.h

rrdtool (da shell) per immagazzinare i dati raccolti e generare i grafici

costanti:
INTERVAL = numero di secondi ogni quanto viene aggiornato il db RRD e il grafico dei SYN (settato a 1)
HASH_SIZE = dimensione della tabella hash usata per mantenere gli IP e le porte a cui hanno mandato richieste SYN (settato a 64, molto basso per ridurre il carico di lavoro visti i test in locale)
SOGLIA = numero di richieste SYN ricevute da uno stesso indirizzo IP necessarie per generare un allert (settato a 3, molto basso per verifiche piu rapide in locale)
CLEANUP_INTERVAL = numero di secondi ogni quanto viene chiamata chiamata la funzione per ripulire la tabella hash dalle vecchie porte e dagli IP inattivi per non far crescere a dismisura la tabella (settata a 60)

strutture dati:
PortNode = elemento della lista di porte contattate da uno stesso IP 
parametro last_seen, necessario per il cleanup
IPEntry = elemento della lista di IP corrispondenti ad una entry della hash table (a causa delle collisioni l’hash di piu IP puo essere lo stesso, quindi usiamo quedsta struttura)
parametro allert_count, in modo che venga generato un solo allert per IP per ogni sessione di monitoraggio
parametro port_count, necessario per il rilevamento del superamento della soglia da parte di un IP


programma principale:
filtro BPF (Berkeley Packet Filter) per intercettare solo pacchetti TCP SYN senza ACK diretti alle porte 1-1024
file di log per tenere traccia nel tempo dei vari alert di potenziali port scan ricevuti
handler per gestire la ricezione di CTRL+C 
file RRD creto se non già esistente o aggiornato con i nuovi dati ricevuti
–step 1 = registra i dati ogni secondo
syn = Data Source di tipo contatore (se mancano 10 dati il valore viene considerato unknown)
Round Robin Archive che memorizza la media dei valori ogni 1 secondo per 10 minuti
viene richiesto di scegliere l’interfaccia di rete su cui si vuole eseguire il monitoraggio
loop di monitoraggio finché non viene ricevuto CTRL+C:
ricezione e gestione dei pacchetti
cleanup regolari per non far crescere troppo l’hash table
aggiornamento del db RRD 
creazione del grafico, in formato png e aggiornato in tempo reale, generato a partire dal db RRD che mostra il numero dei pacchetti SYN al secondo degli ultimi 10 minuti
dopo il loop chiudiamo e liberiamo tutte le risorse utilizzate

funzioni chiamate:
int_handler = funzione che si occupa della gestione dell’interruzione forzata del programma chiamata con CTRL+C
hash_ip = calcola l’hash dell’IP
free_ip_table = funzione usata per liberare la memoria occupata dalla tabella hash a prima di terminare il programma
insert_ip_port = funzione che aggiorna il parametro last_seen delle porte gia nella tabelle ed eventualmente ne inserisce di nuove controllando che non venga superata la soglia e in caso manda un alert e lo registra nel file di log
cleanup_old_ports = funzione chiamata regolarmente per ripulire la hash table da porte vecchie e IP inattivi
print_ip_table = funzione usata per il debug che stama l’hash table
packet_handler = controlla che il pacchetto sia TCP con flag SYN attivo e ACK non attivo (è solo un controllo visto che la scrematura è stata già fatta dal filtro BPF) e in caso lo inserisce nella tabella hash 

