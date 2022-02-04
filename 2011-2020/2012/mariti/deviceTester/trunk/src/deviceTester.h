#ifndef DEVICETESTER_H
#define DEVICETESTER_H
#include "types.h"

/*
 * se la macro DEBUG e` definita i messaggi di debug vengono scritti
 * nel seguente file, a meno che non sia definita la macro
 * DEBUG_LOG_STDOUT, in tal caso i messaggi vengono scritti su stdout
 */
FILE *dbg_logfile;
#define dbg_logfilename "/tmp/gr-devicetester.log"

/*
 * variabili e funzionalita` per simulare un SUT con ritardi e
 * perdite/filtraggio  
 */
extern int simulate_lostperc;
extern int simulate_sutmaxdelay;
extern int simulate_sutmindelay;
void dt_simulate_init(void);
int dt_simulate_send(pcap_t *p, const void *buf, size_t size);
const u_char *dt_simulate_receive(pcap_t *p, struct pcap_pkthdr *h);

/*
 * valori per i criteri di partizionamento dei pacchetti di test
 */
#define PARTRULE_NONE 0
#define PARTRULE_EO 1
#define PARTRULE_EO_IP 2
#define PARTRULE_EO_MAC 3
#define PARTRULE_RAND 4

/**
 * Converte un criterio di partizionamento dal formato stringa al
 * formato intero. I possibili valori string sono: "none",
 * "evenAndOdd", "ip", "mac", "random"
 */
unsigned char parsePartRule(const char *str);

/**
 * Assegna ad un pacchetto una delle due interfacce usate dal
 * programma di test in base ad un criterio. Possibili criteri:
 * PARTRULE_NONE, PARTRULE_EO, PARTRULE_EO_IP, PARTRULE_EO_MAC,
 * PARTRULE_RAND
 */
unsigned char partitionPcapStream(int dlt, const u_char *bytes, int rule); 

/**
 * Viene eseguita la comparazione di due pacchetti di stesso livello
 * datalink in base al contenuto.
 * \retval 0 i pacchetti sono uguali
 * \retval i (i!=0) i pacchetti sono diversi
 */
int packetData_cmp(int datalinkType, const u_char *d1, unsigned int l1,
		   const u_char *d2, unsigned int l2);

/**
 * Analizza un file pcap e memorizza le informazioni della cattura,
 * utili per il test, in memoria, in una lista di pacchetti
 * \param list lista di pacchetti da costruire in base alla cattura offline
 * \param offline sessione pcap offline
 * \param partitionRule regola con cui i pacchetti vengono assegati ad
 * una delle due possibili interfacce; valori possibili sono
 * PARTRULE_NONE, PARTRULE_EO, PARTRULE_EO_IP, PARTRULE_EO_MAC,
 * PARTRULE_RAND
 * \param fixedDeltas se diverso da 0 e` l'intervallo di tempo fisso
 * tra ciasuna coppia di pacchetti adiacenti letti dalla lista list,
 * altrimenti tali intervalli sono quelli letti nella cattura offline
 * \retval 0 tutto bene
 * \retval -1 in caso di errori, errno settata
 */
int parsePcapFile(struct list *list, pcap_t *offline, int partitionRule,
		  usec_t fixedDeltas);

#endif	/* DEVICETESTER_H */
