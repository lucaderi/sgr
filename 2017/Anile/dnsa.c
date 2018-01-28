/*
 *  DNSmonitor
 *  Copyright (C) 2017  Simone Anile simone.anile@gmail.com
 *
 * This file is part of DNSmonitor.
 *
 *  DNSmonitor is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  DNSmonitor is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with DNSmonitor.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pagine.h"
#include "utils.h"
#define DEFAULT_SNAPLEN 600
#define COPY(T, V)  case T: \
									mail.V = strdup(optarg); \
									break
struct dns_header{ // Header DNS
	u_short id; u_short flags;
	u_short nric; u_short nris;
	u_short naut; u_short nsup;
};
/*
 * Struttura usata per tenere traccia degli host che hanno fatto richieste
 * DNS per pagine (salvando il tipo) non consentite (e quante ne hanno fatte)
 */
struct hosts{
	pthread_mutex_t l;
	char *host;
	char *type;
	int n;
	struct hosts* next;
};

struct _mail{ // Struttura usata per la configurazione delle mail di allarme
	char *to;
	char *from;
	char *oggetto;
	char *server;
	char *utente;
	char *password;
};
struct dns_addr *page = NULL; // Lista indirizzi "speciali"
struct hosts *host = NULL; // Lista host che hanno fatto richieste particolari

pthread_mutex_t lockg = PTHREAD_MUTEX_INITIALIZER; // Lock per lista host
pcap_t *pd; // Handle per la cattura
static FILE *log; // File di log
int verbose = 0, m = 0; // indicatore verbose e mail
int na = 10, nr = 10; // Numero di eventi max, frequenza di azzeramento
struct _mail mail; // Strutura per la configurazione delle mail
volatile sig_atomic_t fine = 0; // Indicatore di terminazione

void printHead(){
	printf("*************************\n");
	printf("*  _____  _   _  _____  *\n");
	printf("* |  __ \\| \\ | |/ ____| *\n");
 	printf("* | |  | |  \\| | (___   *\n");
 	printf("* | |  | |     |\\___ \\  *\n");
 	printf("* | |__| | |\\  |____) | *\n");
 	printf("* |_____/|_| \\_|_____/  *\n");
	printf("*        monitor        *\n");
	printf("*************************\n");
	printf("\n");
}
// Help
void printHelp(){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *devpointer;
	printf("Avvio: sudo ./dnsa args\n");
	printf("Parametri:\n\n");
	printf("-h\t\t\tStampa help\n");
	printf("-v\t\t\tModalita' verbose]\n");
	printf("-i <interfaccia>\tInterfaccia (per la cattura)*\n");
	printf("\nParametri per gli allarmi:\n");
	printf("-a <valore>\t\tNumero di eventi per mandare un allarme (>0)\n");
	printf("-r <valore>\t\tNumero di ripetizioni prima di azzerare\n"
										"\t\t\til contatore per gli allarmi (>=0)\n");
	printf("\nParametri per l'invio di mail di allarme:\n");
	printf("-t <indirizzo>\t\tIndirizzo mail destinatario\n");
	printf("-f <indirizzo>\t\tIndirizzo mail mittente\n");
	printf("-o <oggetto>\t\tOggetto mail\n");
	printf("-s <server>\t\tServer mail in uscita\n");
	printf("-u <utente>\t\tUtente mail\n");
	printf("-p <password>\t\tPassword mail\n");
	// Ricerca interfacce disponibili
	if(pcap_findalldevs(&devpointer, errbuf) == 0) {
		int i = 0;
		pcap_if_t *dev = devpointer;
		printf("\n*Interfacce disponibili (-i):\n");
		while(dev) {
    	printf(" %d. %s\n", i++, dev->name);
      dev = dev->next;
    }
	}
	pcap_freealldevs(devpointer);
}
/*
 * Se l'host non e' presente nella lista (associato al tipo passato)
 * di quelli sotto controllo si aggiunge (in coda)
 * impostando il contatore a 1, altrimenti si incrementa
 * OK: 0, ERRORE: -1;
 */
static void* add_host(void *args){
	struct hosts *prec = NULL, *current;
	char **par = (char**) args;
	int h = 0; long t;
	// Scorro la lista in mutua esclusione
	pthread_mutex_lock(&lockg);
	current = host;
	while(current != NULL){
		pthread_mutex_unlock(&lockg);
		// Se e' presente un nodo con i valori passati
		if(strcmp(par[0], current->host) == 0 &&
				strstr(current->type, par[1]) != NULL){
			// Libero la memoria utilizzata parametri
			free(par[0]); free(par[1]); free(par);
			h = 1; break;
		}
		pthread_mutex_lock(&lockg);
		prec = current; current = current->next;
	}
	// Se h e' 0 allora current e' NULL (nodo corrispondente non trovato).
	// Non controllo direttamente current perche' se e' stato trovato l'host
	// (break) non si possiede la lock
	if(h == 0){
		struct hosts *new;
		new = malloc(sizeof(struct hosts));
		if(new == NULL){
			pthread_mutex_unlock(&lockg);
			t = time(NULL);
			fprintf(stderr, "%ld -E- Malloc new (add_host). Errno: %d.\n", t, errno);
			fprintf(log, "%ld -E- Malloc new (add_host). Errno: %d.\n", t, errno);
			return (void *) -1;
		}
		pthread_mutex_init(&(new->l), NULL);
		new->host = par[0]; new->type = par[1]; new->n = 1;
		new->next = NULL;
		if(prec == NULL) host = new;
		else prec->next = new;
		pthread_mutex_unlock(&lockg);
	}else{
		// Altrimenti ho trovato una corrispondenza quindi incremento il contatore
		pthread_mutex_lock(&(current->l));
		current->n++;
		pthread_mutex_unlock(&(current->l));
	}
	return 0;
}
/*
 * Funzione per liberare la memoria occupata
 * dalla lista degli host
*/
void free_host(){
	struct hosts *del;
	while(host != NULL){
		free(host->host); free(host->type);
		del = host; host = host->next; free(del);
	}
}
/*
 * Funzione per calcolare la lunghezza (in caratteri)
 * delle informazioni di configurazione per le mail
*/
#define leni(CAMPO) len += strlen(CAMPO)
int lenmail(){
	int len = 0;
	leni(mail.to); leni(mail.from);
	leni(mail.oggetto); leni(mail.server);
	leni(mail.utente); leni(mail.password);
	return len;
}
// Funzione per inviare le mail di allarme
int sendmail(char *host, char *type){
	int lentype = 0, i, msglen;
	char *stype, *cmdmail;
	for(i = 0; i < strlen(type); i++){
		switch (type[i]) {
			case UNKNOWN: // "Pagina sconosciuta"
				lentype += strlen("Pagina sconosciuta\n");
				break;
			case WRONG: // "Pagina errata"
				lentype += strlen("Pagina errata\n");
				break;
			case MALWARE: // "Malware"
				lentype += strlen("Malware\n");
				break;
			case PORNOGRAPHY: // "Pornography"
				lentype += strlen("Pornography\n");
		}
	}
	stype = malloc(lentype + 1);
	if(stype == NULL) {
		long t = time(NULL);
		fprintf(stderr,"%ld -E- Malloc stype (sendmail). Errno: %d.\n", t, errno);
		fprintf(log,"%ld -E- Malloc stype (sendmail). Errno: %d.\n", t, errno);
		return -1;
	}

	for(i = 0; i < strlen(type); i++){
		switch (type[i]) {
			case UNKNOWN: // "Pagina sconosciuta"
				strcat(stype, "Pagina sconosciuta\n");
				break;
			case WRONG: // "Pagina errata"
				strcat(stype, "Pagina errata\n");
				break;
			case MALWARE: // "Malware"
				strcat(stype, "Malware\n");
				break;
			case PORNOGRAPHY: // "Pornography"
				strcat(stype, "Pornography\n");
		}
	}
	msglen = strlen("Allarme\nHost: \nTypes:\n")
			+ strlen(host) + lentype + lenmail() +
			strlen("sendemail -f  -t  -u \"\" -s  -xu  -xp  -m \"\"");
	cmdmail = malloc(msglen + 1);
	if(cmdmail == NULL) {
		long t = time(NULL);
  	fprintf(stderr,"%ld -E- malloc cmdmail (sendmail) %d\n", t, errno);
		fprintf(log,"%ld -E- malloc cmdmail (sendmail) %d\n", t, errno);
		return -1;
	}
	sprintf(cmdmail, "sendemail -f %s -t %s -u \"%s\" -s %s"
						" -xu %s -xp %s -m \"Allarme\nHost: %s\nTypes:\n%s\"",
	 					mail.from, mail.to, mail.oggetto, mail.server,
						mail.utente, mail.password, host, stype);
	// Dopo aver preparato il comando per l'invio della mail lo eseguo
	system(cmdmail); free(cmdmail); free(stype);
	return 0;
}

/*
 * Monitor: controlla la lista degli host e se qualcuno ha fatto
 * troppe richieste ad un tipo di pagine "speciali" manda un allarme
 */
static void* monitor(void *args){
	struct hosts *current;
	int reset = 0; long t;
	while(!fine){ // Finche non si riceve il "comando" di terminazione
		// Scorro la lista degli host e controllo qualcuno ha fatto
		// almeno na richieste a pagine "speciali" (se si mando l'allarme)
		// Ogni nr visite della lista azzero il contatore per ogni host
		pthread_mutex_lock(&lockg);
		if(fine) { pthread_mutex_unlock(&lockg); break; }
		current =  host;
		while(current != NULL){
			pthread_mutex_unlock(&lockg);
			pthread_mutex_lock(&(current->l));
			if(current->n >= na){
				current->n = 0;
				pthread_mutex_unlock(&(current->l));
				if(m) sendmail(current->host, current->type);
				t = time(NULL);
				fprintf(log,"%ld -A- Allarme %s %s.\n",
				 			t, current->host, current->type);
				fprintf(stderr,"%ld -A- Allarme %s %s.\n",
							t, current->host, current->type);
				fflush(log);
			}else {
				if(reset == nr) current->n = 0;
				pthread_mutex_unlock(&(current->l));
			}
			pthread_mutex_lock(&lockg);
			current = current->next;
		}
		pthread_mutex_unlock(&lockg);
		if(!fine){
			if(reset == nr){ reset = 1; }
			else reset++;
			sleep(1);
		}
	}
	pcap_breakloop(pd); // Chiamata per fermare la cattura
	return 0;
}

// Funzione che verifica l'indirizzo (usata dalla funzione verifica)
char* riconosciuto(char *addr){
	int r = 0;
	char *tp;
	struct dns_addr *current = page;

	if((tp = malloc(TYPES + 1)) == NULL){
		long t = time(NULL);
		fprintf(stderr, "%ld -E- Malloc types (riconosciuto). Errno: %d.\n",
																	t, errno);
		fprintf(log, "%ld -E- Malloc types (riconosciuto). Errno: %d.\n", t, errno);
		return NULL; // Errore
	}

	while(current != NULL){
		if(strcmp(current->addr, addr) == 0){
			tp[r] = current -> type;
			r++;
		}
		current = current -> next;
	}
	tp[r] = '\0';
	return tp;
}

/*
 * Funzione per verificare se l'indirizzo e' consentito o no.
 * Se non e' consentito avvia il thread che gestisce l'evento
 */
int verifica(char* pageaddr, char* host){
	char **args; long t;
	if((args = malloc(2 * sizeof(char *))) == NULL){
		t = time(NULL);
  	fprintf(stderr, "%ld -E- Malloc args (verifica). Errno: %d.\n", t, errno);
		fprintf(log, "%ld -E- Malloc new (verifica). Errno: %d.\n", t, errno);
		return -1;
	}
	if((args[1] = riconosciuto(pageaddr)) == NULL) return -1;

	if(strlen(args[1]) > 0){
		pthread_t tid;
		args[0] = malloc(strlen(host) + 1);
		if(args[0] == NULL){
			t = time(NULL);
			fprintf(stderr, "%ld -E- Malloc host (verifica). Errno: %d.\n", t, errno);
			fprintf(log, "%ld -E- Malloc host (verifica). Errno: %d.\n", t, errno);
			return -1;
		}
		memcpy(args[0], host, strlen(host) + 1);

		t = time(NULL);
		if(verbose){
			fprintf(stdout, "%ld -A- Richiesta non consentita %s %s.\n",
														t, host, args[1]);
		}
		fprintf(log, "%ld -A- Richiesta non consentita %s %s.\n",
														t, host, args[1]);
		// Creo il thread che "incrementa" il contatore
		// per l'host che ha fatto la richiesta
		// Uso un nuovo thread perche' sulla lista devo lavorare in mutua esclusione
		if((errno = pthread_create(&tid, NULL, add_host, args) != 0)){
			t = time(NULL);
			fprintf(stderr, "%ld -E- Pthread_create (verifica). Errno: %d.\n", t, errno);
			fprintf(log, "%ld -E- Pthread_create (verifica). Errno: %d.\n", t, errno);
			free(args[0]); free(args[1]); free(args);
			return -1;
		}
		return 1;
	}else{ free(args[1]); free(args); }
	return 0;
}
/*
 * Funzione che analizza i frame ricevuti estrae le risposte dns
 * e controlla se si deve incrementare il numero di richieste
 * errate/non consentite per l'host al quale era destinata la risposta
 */
void dns(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p){
	// Si usa n come contatore (Byte) per scorrere i dati ricevuti
	char flags[5], buf1[18], buf2[18];
	char *src, *tsrc, *dest, *tdest;
	u_short n = 0, i, sp, dp;
	u_char se[6], de[6];
	struct dns_header hdr;
	struct ip ip;

	// Controllo se ho catturato tutto il frame
	if(h->caplen != h->len){
		if(verbose){
			fprintf(stderr, "%ld -D- Frame scartato: caplen %d, len %d.\n",
																h->ts.tv_sec, h->caplen, h->len);
		}
		fprintf(log, "%ld -D- Frame scartato: caplen %d, len %d.\n",
														h->ts.tv_sec, h->caplen, h->len);
	}else{
		/*if(verbose){
			fprintf(stdout, "%ld -D- Frame ricevuto: len %d.\n",
															h->ts.tv_sec, h->len);
		}*/
		fprintf(log, "%ld -D- Frame ricevuto: len %d.\n",
														h->ts.tv_sec, h->len);
		// Si leggono gli header IP e DNS saltando gli header Ethernet e UDP
		// Si leggono anche le porte e gli indirizzi fisici
		memcpy(&de, p, 6); // Indirizzo fisico destinatario
		memcpy(&se, p + 6, 6); // Indirizzo fisico sorgente
		// Header IP
		memcpy(&ip, p + (n += sizeof(struct ether_header)), sizeof(struct ip));
		memcpy(&sp, p + (n + sizeof(struct ip)), 2); // Porta sorgente
		memcpy(&dp, p + (n + sizeof(struct ip) + 2), 2); // Porta destinatario
		// Herader DNS
		memcpy(&hdr, p + (n +=  sizeof(struct ip) + 8), sizeof(struct dns_header));
		// Si estraggono alcune informazioni DNS
		// DNS: Transaction ID, Flags
		//      numero di richieste, numero di risposte
		hdr.id = ntohs(hdr.id);
		hdr.flags = ntohs(hdr.flags);
		// Controllo gli ultimi 4 bit del campo flags
		// per cercare l'errore 3 (NXDOMAIN)
		flags[4] = '\0';
		for(i = 4; i > 0; i--){
			flags[i - 1] = (hdr.flags & 1) + '0';
			hdr.flags >>= 1;
		}
		// Indirizzi fisici
		etheraddr_string(se, buf1);
		etheraddr_string(de, buf2);
		// Estraggo IP mittente e destinatario
		tsrc = intoa(ntohl(ip.ip_src.s_addr));
		src = malloc(strlen(tsrc) + 1);
		if(src == NULL){
			fprintf(stderr, "%ld -E- Malloc src (dns). Errno: %d\n",
																		h->ts.tv_sec, errno);
			fprintf(log, "%ld -E- Malloc src (dns). Errno: %d\n",
																		h->ts.tv_sec, errno);
			return;
		}
		memcpy(src, tsrc, strlen(tsrc) + 1);
		tdest = intoa(ntohl(ip.ip_dst.s_addr));
		dest = malloc(strlen(tdest) + 1);
		if(dest == NULL){
			fprintf(stderr, "%ld -E- Malloc dst (dns). Errno: %d\n",
																		h->ts.tv_sec, errno);
			fprintf(log, "%ld -E- Malloc dst (dns). Errno: %d\n",
																		h->ts.tv_sec, errno);
			return;
		}
		memcpy(dest, tdest, strlen(tdest) + 1);
		// Caso NXDOMAIN
		if(strcmp(flags, "0011") == 0){
			if(verbose){
				fprintf(stdout, "\n%ld --- [ %s -> %s ]\n"
									"\t       [ %s:%d -> %s:%d ]\n"
									"\t       [ id %#06x ] A: NXDOMAIN\n",
									h->ts.tv_sec, buf1, buf2, src, ntohs(sp),
									dest, ntohs(dp), hdr.id);
				fprintf(log, "%ld --- [ %s -> %s ]\n"
									"\t       [ %s:%d -> %s:%d ]\n"
									"\t       [ id %#06x ] A: NXDOMAIN\n",
									h->ts.tv_sec, buf1, buf2, src, ntohs(sp),
									dest, ntohs(dp), hdr.id);
			}
			// Verifico se l'indirizzo e' tra quelli non consentiti
			// Controllo degli errori (log) direttamente nella funzione
			verifica(NX, dest);
		}else{
			// Controllo numero di domande/risposte
			hdr.nric = ntohs(hdr.nric); hdr.nris = ntohs(hdr.nris);
			// Se c'e' una richiesta e almeno una risposta
			if(hdr.nric == 1 && hdr.nris > 0){
				int r, v = 0;
				u_short type, lenlabel, len;
				u_long addr; u_char pname;
				// Richiesta DNS
				// Conto la lunghezza dell'indirizzo simbolico della richiesta
				lenlabel = strlen((const char *)p + (n += sizeof(struct dns_header)));
				// Scorro saltando vari Byte
				// lenlabel: indirizzo simbolico
				// 1: carattere fine stringa (indirizzo simbolico)
				// 2: tipo della richiesta
				// 2: classe della richiesta
				n += lenlabel + 1 + 2 + 2;
				// Risposte DNS
				for(r = 0; r < hdr.nris; r++){
					// Copio il primo byte del nome
					// contenuto nella risposta
					memcpy(&pname, p + n, 1);
					// Se il suo valore e' 192 (0xC0)
					// il successivo Byte indica
					// l'indice dei dati al quali si
					// puo' leggere il nome.
					// Altrimenti si scorre della
					//  lunghezza del nome contenuto
					if(pname == 192) n += 2; // 1 Byte 0xC0 + 1 Byte indice
					else n += strlen((const char *)p + n) + 1; // Lunghezza + 1 per \0

					// Si legge il typo della risposta
					memcpy(&type, p + n, 2);
					// Si salta classe (2 Byte) e time to live (4 Byte)
					// I primi 2 Byte sono relativi al tipo
					n += 2 + 2 + 4;
					// Si legge la lunghezza del campo che contiene
					// l'informazione della risposta
					// Nel caso di risposta con indirizzo IPv4 (tipo A)
					// si usa per leggerlo
					// altrimenti serve per sapere quanti Byte saltare
					memcpy(&len, p + n, 2);
					n += 2;

					if(ntohs(type) == 1){
						char *pageaddr;
						// Si legge l'indirizzo
						memcpy(&addr, p + n, ntohs(len));
						pageaddr = intoa(ntohl(addr));
						if(verbose && v == 0){
							fprintf(stdout, "\n%ld --- [ %s -> %s ]\n"
															"\t       [ %s:%d -> %s:%d ]\n"
															"\t       [ id %#06x ] A: %s\n",
															h->ts.tv_sec, buf1, buf2, src,ntohs(sp),
															dest, ntohs(dp), hdr.id, pageaddr);
							fprintf(log, "%ld --- [ %s -> %s ]\n"
															"\t       [ %s:%d -> %s:%d ]\n"
															"\t       [ id %#06x ] A: %s\n",
															h->ts.tv_sec, buf1, buf2, src,ntohs(sp),
															dest, ntohs(dp), hdr.id, pageaddr);
							v = 1;
						}
						// Se non e' gia' stato trovato un indirizzo
						// "sotto controllo" si verifica il corrente
						//if(!al) if((al = verifica(pageaddr, dest)) < 0) al = 0;
						if(verifica(pageaddr, dest) == 1) break;
					}
					n += ntohs(len);
				}
			}
		}
		free(src); free(dest);
		fflush(log);
	}
}
// Verifica dei parametri e-mail (Se m e' a 1 servono tutti i parametri)
int mail_conf(){
	if(m)
		if(mail.to == NULL && mail.from == NULL &&
			mail.oggetto == NULL && mail.server == NULL &&
			mail.utente == NULL && mail.password == NULL){
			printf("Configurazione:\n");
			printf("non tutti i parametri per l'invio delle mail di allarme\n");
			printf("sono stati impostati. Controllare e riprovare o avviare\n");
			printf("senza il parametro -m per disattivare le mail.\n");
			return 1;
		}
	return 0;
}
// Gestore del segnale SIGINT per la terminazione del programma
static void gestore(int signum){
	if(!fine){
		printf("\n***\nRicevuto segnale %d\n***\n", signum);
		fine = 1;
	}else printf("\n***\nChiusura in corso... attendi...\n***\n");
}

int main(int argc, char* argv[]) {
	char *device = NULL, errbuf[PCAP_ERRBUF_SIZE];
	char *bpfFilter = "ip and udp and src port 53", *logfile;
	int c, snaplen = DEFAULT_SNAPLEN; long t;
	struct bpf_program fcode;
	struct sigaction g;
	pthread_t tid;

	printHead();
	if((logfile = malloc(24)) == NULL){
		fprintf(stderr, "%ld -E- Malloc logfile (main). Errno: %d.\n",
												time(NULL), errno);
		return(-1);
	}
	t = time(NULL);
	sprintf(logfile, "logs/%ld_log.txt", t);
	if((log = fopen(logfile, "w")) == NULL){
		fprintf(stderr, "%ld -E- Fopen logfile %s (main). Errno: %d.\n",
												t, logfile, errno);
		return(-1);
	}
	fprintf(stdout, "%ld --- Avvio.\n", t);
	fprintf(log, "%ld --- Avvio.\n", t);
	free(logfile);
	// Controllo gli argomenti
	while((c = getopt(argc, argv, "hvmi:t:f:o:s:u:p:a:r")) != '?'){
		if(c == -1) break;
		switch(c){
			case 'h': // Help
				printHelp();
				fprintf(log, "%ld --- Chiusura (arg -h).\n", time(NULL));
				fclose(log);
				return(0);
			case 'v':
				verbose = 1;
				fprintf(log, "%ld --- Verbose (arg -v).\n", time(NULL));
				break;
			case 'i': // Imposto l'interfaccia
				device = strdup(optarg);
				fprintf(log, "%ld --- interfaccia %s (arg -i).\n", time(NULL), device);
				break;
			case 'a':
				na = atoi(optarg);
				if(na <= 0){
					fprintf(stderr, "%ld -E- Parametro a: il numeri di eventi\n"
													"deve essere > 0!!!\n", time(NULL));
					fprintf(log, "%ld -E- Parametro a: il numeri di eventi\n"
													"deve essere > 0!!!\n", time(NULL));
					fclose(log);
					return(-1);
				}
				break;
			case 'r':
				nr = atoi(optarg);
				if(nr < 0){
					fprintf(stderr, "%ld -E- Parametro r: il numeri di ripetizioni\n"
													"deve essere >= 0!!!\n", time(NULL));
					fprintf(log, "%ld -E- Parametro r: il numeri di ripetizioni\n"
													"deve essere >= 0!!!\n", time(NULL));
					fclose(log);
					return(-1);
				}
				break;
			case 'm':
				m = 1;
				break;
			COPY('t', to);
			COPY('f', from);
			COPY('o', oggetto);
			COPY('s', server);
			COPY('u', utente);
			COPY('p', password);
		}
	}
	t = time(NULL);
	fprintf(stdout, "%ld --- Configurazione...\n", t);
	fprintf(log, "%ld --- Configurazione...\n", t);
	// Se non e' stata impostata cerco un'interfaccia
	if(device == NULL){
		if((device = pcap_lookupdev(errbuf)) == NULL){
			t = time(NULL);
    	fprintf(stderr, "%ld -E- pcap_lookup: %s (main).\n", t, errbuf);
			fprintf(log, "%ld -E- pcap_lookup: %s (main).\n", t, errbuf);
			fclose(log);
			return -1;
		}
	}
	t = time(NULL);
	fprintf(log, "%ld --- Interfaccia %s (auto).\n", t, device);
	
	// Verifico il comportamento del dns
	if(dns_page(&page, log) != 0) {
		fclose(log);
		free_page(page);
		return -1;
	}
	
	fprintf(log,"%ld --- Catturo da %s.\n", t, device);
	fprintf(stdout, "%ld --- Catturo da %s.\n", t, device);
	// Ottengo l'handle per la cattura /* promisc = 1 */
	if((pd = pcap_open_live(device, snaplen, 1, 500, errbuf)) == NULL) {
		t = time(NULL);
		fprintf(stderr, "%ld --- pcap_open_live: %s.\n", t, errbuf);
		fprintf(log, "%ld --- pcap_open_live: %s.\n", t, errbuf);
		fclose(log);
		return(-1);
	}
	t = time(NULL);
	fprintf(stdout, "%ld --- Selezione interfaccia \xE2\x9C\x93.\n", t);
	fprintf(log, "%ld --- Selezione interfaccia \xE2\x9C\x93.\n", t);
	// Imposto il filtro per la cattura
	if(pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
		t = time(NULL);
		fprintf(stderr, "%ld -E- pcap_compile: %s.\n",
											t, pcap_geterr(pd));
		fprintf(log, "%ld --- pcap_compile: %s.\n",
										t, pcap_geterr(pd));
		fclose(log);
		return(-1);
	} else {
		if(pcap_setfilter(pd, &fcode) < 0) {
			t = time(NULL);
			fprintf(stderr, "%ld -E- pcap_setfilter: %s.\n",
												t, pcap_geterr(pd));
			fprintf(log, "%ld -E- pcap_setfilter: %s.\n",
												t, pcap_geterr(pd));
			fclose(log);
			return(-1);
		}
	}
	
	// Avvio il thread che gestisce l'invio degli allarmi
	if((errno = pthread_create(&tid, NULL, monitor, NULL)) != 0){
		t = time(NULL);
		fprintf(log, "%ld -E- pthread monitor %d\n", t, errno);
		fprintf(log, "%ld -E- pthread monitor %d\n", t, errno);
		fclose(log);
		free_page(page);
		return (-1);
	}

	// Imposto il segnale per la terminazione
	memset(&g, 0, sizeof(g));
	g.sa_handler = gestore;

	if(sigaction(SIGINT, &g, NULL)){
		t = time(NULL);
		fprintf(stderr, "%ld -E- sigaction: %d.\n", t, errno);
		fprintf(log, "%ld -E- sigaction: %d.\n", t, errno);
		fine = 1;
		pthread_join(tid, NULL);
		free_page(page);
		fclose(log);
		return (-1);
	}
	t = time(NULL);
	fprintf(stdout, "%ld --- Avvio pcap_loop.\n", t);
	fprintf(log, "%ld --- Avvio pcap_loop.\n", t);
	fflush(log);
	// Avvio la lettura dei pacchetti
	while(pcap_loop(pd, -1, dns, NULL) == -1){
		char *err = pcap_geterr(pd);
		if(strcmp(err, "The interface went down") != 0){
			t = time(NULL);
			fprintf(stderr, "%ld -E- pcap_loop: %s.\n", t, err);
			fprintf(log, "%ld -E- pcap_loop: %s.\n", t, err);
			fine = 1;
			pthread_join(tid, NULL);
			free_page(page);
			return -1;
		}else{
			t = time(NULL);
			printf("%ld --- %s!\n", t, err);
			sleep(5);
			fprintf(stdout, "%ld --- RiAvvio pcap_loop: %s.\n", t, errbuf);
			fprintf(log, "%ld --- RiAvvio pcap_loop: %s.\n", t, errbuf);
		}
	}
	pcap_close(pd);
	free_page(page); free_host();
	t = time(NULL);
	fprintf(log, "%ld --- Chiusura.\n", t); fclose(log);
	fprintf(stdout, "%ld --- Chiusura\n", t);
	return 0;
}
