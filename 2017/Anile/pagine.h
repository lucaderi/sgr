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
#define NX "NX"
#define DOMAINLEN 16 // Per Domain generation algorithm
// Tipi di pagine da monitorare
#define TYPES 4
#define MALWARE 'm'
#define PORNOGRAPHY 'p'
#define WRONG 'w'
#define UNKNOWN 'u'

//Pagine MALWARE
#define M11 "wittyvideos.com"
#define M12 "3dpsys.com"
#define M21 "ancientroom.com"
#define M22 "365tc.com"

//Pagine PORNOGRAPHY
#define P11 "redtube.com"
#define P12 "youporn.com"
#define P21 "pornhub.com"
#define P22 "tube8.com"
/*
 * Struttura che contiene gli indirizzi
 * delle "pagine di cortesia" relativi al
 * DNS corrente per i tipi che si vogliono
 * monitorare. (Nel campo indirizzi puo' essere
 * presente anche la rappresentazione di NXDOMAIN,
 * definita sopra)
 */
struct dns_addr{
	char *addr;
	char type;
	struct dns_addr *next;
};
/*
 * Funzione per generare un dominio
 * usando la funzione dga
 */
char* search_dga_page(FILE *log);
/*
 * Funzione per cercare le pagine "speciali"/"di cortesia"
*/
int dns_page(struct dns_addr **head, FILE *log);
/*
 * Funzione per liberare la memoria occupata
 * dalla lista delle pagine "speciali"
*/
void free_page();
