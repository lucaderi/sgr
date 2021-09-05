# ip_dest
Progetto per l'esame di gestione di reti.

Il programma ip_dest legge i pacchetti contenenti l'intestazione di livello rete IPv4 e per ogni indirizzo IP sorgente calcola il numero di destinazioni diverse a cui sono stati inviati i pacchetti.
Ad ogni host mittente è associata una bitmap compressa in cui vengono inseriti gli indirizzi IP degli host destinatari. Al termine dell'esecuzione calcola la cardinalità di ogni bitmap compressa per stampare in ordine decrescente su stdout il numero dei relativi destinatari a cui sono stati inviati i pacchetti. Per tenere traccia di ogni singolo host mittente viene usata una tabella hash.

È usata la seguente implementazione della bitmap compressa: https://github.com/RoaringBitmap/CRoaring.
Per la cattura dei pacchetti è usata la libreria libpcap.

Per compilare il programma usare il comando make quando ci si trova nella directory contenente il file Makefile.

Negli esempi mostrati sotto si ipotizza di trovarsi nella directory contenente il file eseguibile ip_dest.

SINOSSI

	./ip_dest -h
	./ip_dest -i network_interface [-t hh:mm:ss] [-v]
	./ip_dest -p pcap_file [-v]

DESCRIZIONE

	-h: stampa la sinossi su stdout.
	-i: cattura i pacchetti dall'interfaccia di rete network_interface passata come argomento.
	-p: legge i pacchetti dal file pcap_file passato come argomento.
	
Con l'opzione -t è possibile indicare la durata del tempo di cattura dei pacchetti. Se il tempo non è specificato, cattura i pacchetti per un tempo indeterminato. Per terminare la cattura dei pacchetti è possibile usare la combinazione dei tasti CTRL-C.
Con -v stampa gli indirizzi IP sorgente e destinazione di ogni pacchetto catturato.

REQUISITI

	Un compilatore C che supporta lo standard C99.

ESEMPI

	./ip_dest -h
	Stampa la sinossi.

	./ip_dest -i en0 -t 0:5:0
	Cattura per 5 minuti i pacchetti che passano per l'interfaccia en0 e stampa su stdout il riepilogo.

	./ip_dest -p pcap_file -v
	Legge i pacchetti contenuti nel file pcap_file, stampa su stdout gli indirizzi IP sorgente e destinazione di ogni pacchetto e stampa su stdout il riepilogo.
