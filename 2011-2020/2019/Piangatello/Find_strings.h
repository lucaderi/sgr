#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>

/*
funzione chje prende una stringa di due caratteri, scorre l'array en_impossible_bigrams, se trova una corrispondenza
ritorna 1, 0 altrimenti
*/
int find_non_eng_bigrams(char *string);

/*
Legge il prossimo crattere, ritorna -1 se non è disponibile

input
buffer_size : dimensione del buffer
buffer : puntatore al buffer
*/
long get_char (int *buffer_size,char **buffer);

/*
Ritorna il numero di stringhe di caratteri ASCII (lunga almeno string_min) trovate nel buffer, -1 in caso di errore.
Vengono scartate le stringhe con caratteri non alfanumerici e quelle contenenti bigrammi
non appartenenti alla lingua inglese

input
buffer_size : dimensione del buffer
buffer : puntatore al buffer
string_min : lungezza minima stringa cercata
*/
int find_strings (int buffer_size, char *buffer, int string_min);
