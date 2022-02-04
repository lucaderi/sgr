/*
 *  DNSmonitor
 *  Copyright (C) 2017  Simone Anile simone.anile@gmail.com
 *
 *  This file is part of DNSmonitor.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "pagine.h"
#include "utils.h"
/*
 * Funzioni per stampare la lista
 * degli indirizzi speciali (e il tipo)
 */
void print_node_dns(struct dns_addr *node) {
	if(node == NULL) return;
	printf("->[ %s %c ]", node->addr, node->type);
	print_node_dns(node->next);
}
void print_list_dns(struct dns_addr *head){
	printf("|"); print_node_dns(head); printf("<-|\n");
}
/*
 * Aggiunge la pagina e il tipo relativo
 * alla lista di indirizzi "speciali" (in testa)
 */
int add_page(struct dns_addr **head, char *addr, char t, FILE *log){
	struct dns_addr *new;
	// Nuovo nodo
	new = malloc(sizeof(struct dns_addr));
	if(new == NULL){
		long t = time(NULL);
		fprintf(stderr, "%ld -E- Malloc new (add_page). Errno: %d.\n", t, errno);
		fprintf(log, "%ld -E- Malloc new (add_page). Errno: %d.\n", t, errno);
		return -1;
	}
	// Copio valori
	new->addr = malloc(strlen(addr) + 1);
	if(new->addr == NULL){
		long t = time(NULL);
		fprintf(stderr, "%ld -E- Malloc addr (add_page). Errno: %d\n", t, errno);
		fprintf(log, "%ld -E- Malloc addr (add_page). Errno: %d.\n", t, errno);
		return -1;
	}
	new->addr = strcpy(new->addr, addr);
	new->type = t;
	if(*head == NULL) new->next = NULL;
	else new->next = *head;
	// Aggiorno puntatore lista
	*head = new;
	return 0;
}
/*
 * Funzione per risolvere un'indirizzo simbolico
 * in caso di errore si restituisce NULL
 * in caso di errore 3 (NXDOMAIN) si restituisce
 * una stringa apposita
 */
char* risoluzione(char *label, FILE* log){
	struct hostent *tmp;
	tmp = gethostbyname(label);
	if (!tmp) {
		if(h_errno == HOST_NOT_FOUND) { return NX; }
		if(h_errno == NO_ADDRESS || h_errno == NO_DATA) { return NX; }
		fprintf(log, "%ld -E- Risoluzione dns (risoluzione). Errore: h_errno %d\n", time(NULL), h_errno);
		return NULL;
	}
  return (char *)
			inet_ntoa((struct in_addr) *((struct in_addr *) tmp->h_addr_list[0]));
}
/*
 * Funzione per generare domini
 * a partire dalla data (anno, mese, giorno)
 * Algoritmo:
 * https://en.wikipedia.org/wiki/Domain_generation_algorithm
 */
void dga(unsigned long year, unsigned long month, unsigned long day, char *d) {
	unsigned short i;
	for(i = 0; i < DOMAINLEN; i++) {
		year  = ((year ^ 8 * year) >> 11) ^ ((year & 0xFFFFFFF0) << 17);
		month = ((month ^ 4 * month) >> 25) ^ 16 * (month & 0xFFFFFFF8);
		day   = ((day ^ (day << 13)) >> 19) ^ ((day & 0xFFFFFFFE) << 12);
		d[i] = (unsigned char)(((year ^ month ^ day) % 25) + 97);
	}
	d[DOMAINLEN] = '\0' ;
}
/*
 * Funzione per generare un dominio usando la funzione dga
 */
char* search_dga_page(FILE *log){
	char* addr;
	time_t timer;
	struct tm* tm_info;
	char day[3], month[3], year[5];

	if((addr = malloc((DOMAINLEN + 1) * sizeof(char))) == NULL) {
		long t = time(NULL);
		fprintf(stderr, "%ld -E- Malloc addr (search_dga_page)."
							" Errno: %d\n", t, errno);
		fprintf(log, "%ld -E- Malloc addr (search_dga_page)."
							" Errno: %d\n", t, errno);
		return NULL;
	}
	time(&timer);
	tm_info = localtime(&timer);
	strftime(day, 3, "%d", tm_info);
	strftime(month, 3, "%m", tm_info);
	strftime(year, 5, "%Y", tm_info);
	dga(atoi(year), atoi(month), atoi(day), addr);

	return addr;
}

/*
 * Funzione per cercare le pagine "speciali"/"di cortesia"
*/
int dns_page(struct dns_addr **head, FILE *log){
	char *u, *w, *a, *b; long t;
	// Pagina sconosciuta. Esempio: sehccrlyfadifehn
	if((u = search_dga_page(log)) == NULL){
		t = time(NULL);
		fprintf(stderr, "%ld -E- DGA error.\n", t);
		fprintf(log, "%ld -E- DGA error.\n", t);
		return -1;
	}
	if((a = risoluzione(u, log)) == NULL){
		t = time(NULL);
		fprintf(stderr, "%ld --- Unknown page \xE2\x9C\x97.\n", t);
		fprintf(log, "%ld --- Unknown page \xE2\x9C\x97.\n", t);
		return -1;
	}
	
	//if(strcmp(a, "NX") == 0){
	add_page(head, a, UNKNOWN, log);
	/*}else{
		t = time(NULL);
		fprintf(stdout, "%ld --- Nessun comportamento trovato per pagine sconosciute.\n", t);
		fprintf(log, "%ld --- Nessun comportamento trovato per pagine sconosciute.\n", t);
	}*/
	t = time(NULL);
	fprintf(stdout, "%ld --- Unknown page \xE2\x9C\x93.\n", t);
	fprintf(log, "%ld --- Unknown page \xE2\x9C\x93.\n", t);
	// Pagina errata. Esempio: sehccrlyfadifehn.sehccrlyfadifehn
	if((w = malloc((DOMAINLEN * 2 + 2) * sizeof(char))) == NULL){
		t = time(NULL);
		fprintf(stderr, "%ld -E- Malloc wrong page (dns_page). Errno: %d\n",
										t, errno);
		fprintf(stderr, "%ld -E- Malloc wrong page (dns_page). Errno: %d\n",
										t, errno);
		return -1;
	}
	strcpy(w, u); strcat(w, "."); strcat(w, u);

	if((a = risoluzione(w, log)) == NULL){
		t = time(NULL);
		fprintf(stderr, "%ld --- Wrong page \xE2\x9C\x97.\n", t);
		fprintf(log, "%ld --- Wrong page \xE2\x9C\x97.\n", t);
		return -1;
	}

	
	//if(strcmp(a, "NX") == 0){
	add_page(head, a, WRONG, log);
	/*}else{
		t = time(NULL);
		fprintf(stdout, "%ld --- Nessun comportamento trovato per pagine errate.\n", t);
		fprintf(log, "%ld --- Nessun comportamento trovato per pagine errate.\n", t);
	}*/

	t = time(NULL);
	fprintf(stdout, "%ld --- Wrong page \xE2\x9C\x93.\n", t);
	fprintf(log, "%ld --- Wrong page \xE2\x9C\x93.\n", t);
	// Si usano vari indirizzi per riconoscere il comportamento
	// del server DNS
	// Per riconoscere una pagina di cortesia si eseguono due richieste
	// e si confrontano
	// Si usano 2 indirizzi aggiuntivi in caso di problemi con i primi

	// Pagina malware
	if((a = risoluzione(M11, log)) == NULL){
		t = time(NULL);
		fprintf(stderr,
					"%ld --- Malware page: part one, first attempt \xE2\x9C\x97.\n", t);
		fprintf(log,
					"%ld --- Malware page: part one, first attempt \xE2\x9C\x97.\n", t);

		if((a = risoluzione(M12, log)) == NULL){
			t = time(NULL);
			fprintf(stderr,
					"%ld --- Malware page: part one, second attempt \xE2\x9C\x97.\n", t);
			fprintf(log,
					"%ld --- Malware page: part one, second attempt \xE2\x9C\x97.\n", t);
			return -1;
		}
		if((b = malloc(strlen(a) + 1)) == NULL){
			t = time(NULL);
			fprintf(stderr, "%ld -E- malloc malware page (dns_page). Errno: %d\n",
											t, errno);
			fprintf(stderr, "%ld -E- malloc malware page (dns_page). Errno: %d\n",
											t, errno);
			return -1;
		}
		strcpy(b, a);
		if((a = risoluzione(M21, log)) == NULL){
			t = time(NULL);
			fprintf(stderr,
					"%ld --- Malware page: part two, first attempt \xE2\x9C\x97.\n", t);
			fprintf(log,
					"%ld --- Malware page: part two, first attempt \xE2\x9C\x97.\n", t);
			if((a = risoluzione(M22, log)) == NULL){
				t = time(NULL);
				fprintf(stderr,
					"%ld --- Malware page: part two, second attempt \xE2\x9C\x97.\n", t);
				fprintf(log,
					"%ld --- Malware page: part two, second attempt \xE2\x9C\x97.\n", t);
				return -1;
			}
		}
	}
	if((b = malloc(strlen(a) + 1)) == NULL){
		t = time(NULL);
		fprintf(stderr, "%ld -E- malloc malware page (dns_page). Errno: %d\n",
										t, errno);
		fprintf(stderr, "%ld -E- malloc malware page (dns_page). Errno: %d\n",
										t, errno);
		return -1;
	}
	strcpy(b, a);

	if((a = risoluzione(M21, log)) == NULL){
		t = time(NULL);
		fprintf(stderr,
				"%ld --- Malware page: part two, first attempt \xE2\x9C\x97.\n", t);
		fprintf(log,
				"%ld --- Malware page: part two, first attempt \xE2\x9C\x97.\n", t);
		if((b = risoluzione(M22, log)) == NULL){ // OK
			t = time(NULL);
			fprintf(stderr,
				"%ld --- Malware page: part two, second attempt \xE2\x9C\x97.\n", t);
			fprintf(log,
				"%ld --- Malware page: part two, second attempt \xE2\x9C\x97.\n", t);
			return -1;
		}
	}
	if(strcmp(a, b) == 0) add_page(head, a, MALWARE, log);
	else{
		t = time(NULL);
		fprintf(stdout, "%ld --- Nessun comportamento trovato per pagine malware.\n", t);
		fprintf(log, "%ld --- Nessun comportamento trovato per pagine malware.\n", t);
	}
	free(b);

	t = time(NULL);
	fprintf(stdout, "%ld --- Malware page \xE2\x9C\x93.\n", t);
	fprintf(log, "%ld --- Malware page \xE2\x9C\x93.\n", t);
	// Pagina pornografia
	if((a = risoluzione(P11, log)) == NULL){
		t = time(NULL);
		fprintf(stderr,
			"%ld --- Pornography page: part one, first attempt \xE2\x9C\x97.\n", t);
		fprintf(log,
			"%ld --- Pornography page: part one, first attempt \xE2\x9C\x97.\n", t);
		if((a = risoluzione(P12, log)) == NULL){
			t = time(NULL);
			fprintf(stderr,
			"%ld --- Pornography page: part one, second attempt \xE2\x9C\x97.\n", t);
			fprintf(log,
			"%ld --- Pornography page: part one, second attempt \xE2\x9C\x97.\n", t);
			return -1;
		}
		if((b = malloc(strlen(a) + 1)) == NULL){
			t = time(NULL);
			fprintf(stderr, "%ld -E- Malloc pornography page (dns_page). Errno: %d\n",
											t, errno);
			fprintf(stderr, "%ld -E- Malloc pornography page (dns_page). Errno: %d\n",
											t, errno);
			return -1;
		}
		strcpy(b, a);
		if((a = risoluzione(P21, log)) == NULL){
			t = time(NULL);
			fprintf(stderr,
				"%ld --- Pornography page: part two, first attempt \xE2\x9C\x97.\n", t);
			fprintf(log,
				"%ld --- Pornography page: part two, first attempt \xE2\x9C\x97.\n", t);
			if((a = risoluzione(P22, log)) == NULL){
				t = time(NULL);
				fprintf(stderr, "%ld --- Pornography page: part two,"
												" second attempt \xE2\x9C\x97.\n", t);
				fprintf(log, "%ld --- Pornography page: part two,"
										 " second attempt \xE2\x9C\x97.\n", t);
				return -1;
			}
		}
	}
	if((b = malloc(strlen(a) + 1)) == NULL){
		t = time(NULL);
		fprintf(stderr, "%ld -E- Malloc pornography page (dns_page). Errno: %d\n",
										t, errno);
		fprintf(stderr, "%ld -E- Malloc pornography page (dns_page). Errno: %d\n",
										t, errno);
		return -1;
	}
	strcpy(b, a);
	if((a = risoluzione("pornhub.com", log)) == NULL){
		t = time(NULL);
		fprintf(stderr,
			"%ld --- Pornography page: part two, second attempt \xE2\x9C\x97.\n", t);
		fprintf(log,
			"%ld --- Pornography page: part two, second attempt \xE2\x9C\x97.\n", t);
		if((b = risoluzione("tube8.com", log)) == NULL){
			t = time(NULL);
			fprintf(stderr, "%ld --- Pornography page: part two,"
											" second attempt \xE2\x9C\x97.\n", t);
			fprintf(log, "%ld --- Pornography page: part two,"
											" second attempt \xE2\x9C\x97.\n", t);
			return -1;
		}
	}

	if(strcmp(a, b) == 0) add_page(head, a, PORNOGRAPHY, log);
	else{
		t = time(NULL);
		fprintf(stdout, "%ld --- Nessun comportamento trovato per pagine pornografia.\n", t);
		fprintf(log, "%ld --- Nessun comportamento trovato per pagine pornografia.\n", t);
	}
	free(b);
	t = time(NULL);
	fprintf(stdout, "%ld --- Pornography page \xE2\x9C\x93.\n", t);
	fprintf(log, "%ld --- Pornography page \xE2\x9C\x93.\n", t);
	fprintf(stdout, "%ld --- ", t); print_list_dns(*head);

	return 0;
}
/*
 * Funzione per liberare la memoria occupata
 * dalla lista delle pagine "speciali"
*/
void free_page(struct dns_addr *head){
	struct dns_addr *del;
	while(head != NULL){
		free(head->addr);
		del = head; head = head->next;
		free(del);
	}
}