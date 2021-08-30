//contiene l'interfaccia delle funzioni di hash utilizzabili 
#include <stdlib.h>
/*
Prende una stringa (key), il numero di righe (depth), la posizione dei due valori da ritornare (a,b)
*/
void hash_function(const char* key, u_int32_t depth, u_int32_t *a, u_int32_t *b );
u_int32_t hash_increment(u_int32_t depth, u_int32_t *a, u_int32_t *b, int i);