**PROGETTO DI GESTIONE DI RETI 2026 — NICOLA BRILLANTE**
Il progetto consiste nello sviluppo di un programma in linguaggio C per il monitoraggio del traffico su un'interfaccia di rete locale. Il programma opera in modalità promiscua, intercettando tutti i pacchetti in transito sull'interfaccia, e ne determina il protocollo applicativo mediante la libreria di deep packet inspection nDPI.
La cattura è suddivisa in intervalli temporali di un secondo, la cui durata è configurabile dall'utente. Per ciascun intervallo vengono conteggiati i byte dei pacchetti transitati, al fine di calcolare il throughput locale e globale relativo a quel periodo.
Al termine di ogni intervallo, il programma produce un report in cui i pacchetti sono raggruppati per protocollo applicativo, corredati dalle seguenti informazioni: il numero di pacchetti rilevati per ciascun protocollo, il volume complessivo di byte a essi associato e un'etichetta che indica se il primo pacchetto dell'intervallo relativo a un dato protocollo abbia avuto origine dall'interfaccia locale monitorata o da un host esterno.
Il programma si avvale principalmente di due librerie: libpcap, per la cattura dei pacchetti, e nDPI, per il riconoscimento e la classificazione dei protocolli applicativi.
È inoltre disponibile una modalità offline, che consente di analizzare sessioni di cattura precedentemente registrate da altri strumenti in formato .pcap.

Per informazioni più dettagliate si rimanda al documento PDF allegato al programma
