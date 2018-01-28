/**
 *  @file iodiceSniffer.h
 *  \brief  Contenitore di macro utililies e funzioni per lo sniffer.
 *  \author Salvatore Iodice
 */ 

#define SPATIATOR "*******************************************************************************************\n"

#define MAXLEN 80			/* max len di una stringa */
#define MAXARR 5000			/* max len array di flussi */
#define SUCCESS 0 			/* booleano di successo */
#define FAIL 1 				/* booleano di fallimento */	
#define SIGNALFAIL -1 			/* fallimento gestione segnali */
#define FLUXARR fluxArr[i]		/* accesso all'array di flussi */

/* macro di controllo chiavi nell'array di flussi */
#define CHECKSRC (strcmp(fluxArr[ind-1]->srcIp,srcIp)==0 && fluxArr[ind-1]->srcPort == srcPort)
#define CHECKDST (strcmp(fluxArr[ind-1]->dstIp,dstIp)==0 && fluxArr[ind-1]->dstPort == dstPort)
#define FINAL_CHECK (CHECKSRC && CHECKDST)

/* struttura per rappresentare il flusso monodirezionale di dati */
struct pktFlusso {

	int srcPort;			/* porta sorgente (chiave) */
	char* srcIp; 			/* Ip sorgente (chiave) */
	int dstPort;  			/* porta destinazione (chiave) */
	char* dstIp; 			/* Ip destinazione (chiave) */
	int totalPkts;			/* numero pacchetti flusso */	
	int totalSize;			/* size totale flusso */	
	char strInittime[MAXLEN];	/* timestamp inizio flusso */
	char strFinaltime[MAXLEN];	/* timestamp fine flusso */
};

/**
   Testa il valore passato come parametro e in caso di errore
   setta errno stampa un messaggio di errore e lo ritorna

   \retval errno se si verifica un errore
   \retval 0     altrimenti
*/
static int checkMeno1(int value);

/**
   Inizializzazione segnali.
   Aggiungo il mio gestore per SIGALRM

   \retval errno se si verifica un errore
   \retval 0     altrimenti
*/
static int sniffSignals(void);

/** 
   Crea un nuovo flusso con tutti i dati sniffati e la inserisce
   nell'array.

   \param srcPort porta sorgente
   \param srcIp Ip sorgente
   \param dstPort porta destinazione
   \param dstIp Ip destinazione
   \param totalPkts numero pacchetti totali
   \param totalSize size flusso
   \strInittime timestamp iniziale
   \strFinaltime timestamp finale
*/
static void createFlux(int srcPort,char* srcIp,int dstPort,char* dstIp,int totalPkts,
		       int totalSize,char strInittime[],char strFinaltime[]);

/** 
   Elimina il tutti i flussi dall'array.

   \param p il flusso da eliminare
*/
static void deleteFlux();
