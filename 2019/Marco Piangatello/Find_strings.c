#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include "Find_strings.h"

/*
dizionario dei bigrammi che non si possono trovare nella lingua inglese
*/
static const char *en_impossible_bigrams[] = {
  "bk","bq","bx",
  "cb","cf","cg", "cj", "cp", "cv", "cw", "cx",
  "dx",
  "fk","fq","fv","fx","fz",
  "gq","gv","gx",
  "hh","hk","hv","hx","hz",
  "iy","ii",
  "jb","jd", "jf","jg","jh","jk","jl","jm","jn","jp","jq","jr","jt","jv","jw","jx","jy","jz",
  "kg","kq", "kv","kx","kz","kp",
  "lq","lx",
  "mj","mq","mx","mz",
  "pq","pv","px",
  "qb","qc","qd","qe","qf","qg","qh","qj","qk","ql","qm","qn","qo","qp","qr","qs","qt","qv","qw","qx","qy",
  "uu","qz",
  "sx","sz",
  "tq","tx",
  "vb","vc","vd","vf","vg","vh","vj","vm","vn","vq","vt","vw","vx","vz",
  "wq","wv","wx","wz","wb",
  "xg","xj","xk","xv","xz","xw","xy","wk",
  "yd","yj","yq","yv","yz","yw",
  "zb","zc","zg","zh","zj","zn","zq","zs","zx","zk",
  NULL};

//funzione chje prende una stringa di due caratteri, scorre l'array en_impossible_bigrams, se trova una corrispondenza
//ritorna 1, 0 altrimenti
int find_non_eng_bigrams(char *string){
    int i;
    // passo alle lettere minuscole poiche del 'dizionario' sono presenti
    //solo i bigrammi in minuscolo
    if ( string[0] > 65 && string[0] < 90 ){
        string[0] = tolower(string[0]);
    }
    if ( string[1] > 65 && string[1] < 90 ){
        string[1] = tolower(string[1]);
    }
    for(i=0; en_impossible_bigrams[i] != NULL;i++){
        if ( (strncmp(string,en_impossible_bigrams[i],2) == 0) ){
            return 1;
        }
    }
    return 0;
}
/*
Legge il prossimo crattere, ritorna -1 se non è disponibile

input
buffer_size : dimensione del buffer
buffer : puntatore al buffer
*/
long get_char (int *buffer_size,char **buffer){

    int c, i;
    long r = -1;
    unsigned char buf[4];
    int encoding_bytes = 1;

    for (i = 0; i < encoding_bytes; i++){
        if(*buffer_size > 0){
            (*buffer_size)--;
            c = *(*buffer)++;
        }
        else{
            return -1;
        }
    buf[i] = c;
    }
    r = buf[0];
    return r;
}

/*
Ritorna il numero di stringhe di caratteri ASCII (lunga almeno string_min) trovate nel buffer, -1 in caso di errore.
Vengono scartate le stringhe con caratteri non alfanumerici e quelle contenenti bigrammi
non appartenenti alla lingua inglese

input
buffer_size : dimensione del buffer
buffer : puntatore al buffer
string_min : lungezza minima stringa cercata
*/
int find_strings (int buffer_size, char *buffer, int string_min){

    int count = 0;
    char *buf = (char *) malloc (sizeof (char) * (string_min + 1 ));

    if ( string_min <= 1){
        string_min = 2;
    }
    if(buffer_size <= 0){
        return 0;
    }

    while (1){
        int i;
        long c;
        tryline:
        for (i = 0; i < string_min; i++){
            c = get_char (&buffer_size, &buffer);
            if (c == -1){
                return count;
            }
            // ASCII
            // 48 < x < 57 => numeri
            // 65 < x < 90 => lettere maiuscole
            // 97 < x < 122 => lettere minuscole
            if ( ( c < 65 || c > 90 ) &&  ( c < 97 || c > 122 ) && ( c < 48 || c > 57) ){
                goto tryline;
            }

            buf[i] = c;
            /*
            controllo se due caratteri consecutivi formano un bigramma non presente
            nella lingua inglese. In caso affermativo scarto la stringa.
            */
            if ( i > 0 ){
                char string[2];
                string[0] = buf[i-1];
                string[1] = buf[i];
                if (find_non_eng_bigrams(string) == 1){
                    goto tryline;
                }
            }

        }
        //stampa dei caratteri utilizzata per i test
        buf[i] = '\0';
        fputs (buf, stdout);

        char bigram[2];
        bigram[0] = buf[3];

        while (1){
            c = get_char (&buffer_size, &buffer);
            if (c == -1){
                break;
            }
            // ASCII
            // 48 < x < 57 => numeri
            // 65 < x < 90 => lettere maiuscole
            // 97 < x < 122 => lettere minuscole
            if ( ( c < 65 || c > 90 ) &&  ( c < 97 || c > 122 ) && ( c < 48 || c > 57) ){
                break;
            }
            /*
            controllo per ogni nuovo carattere se forma un bigramma con il precedente.
            */
            bigram[1] = c;
            if( find_non_eng_bigrams(bigram) == 1 ){
                break;
            }
            //stampa dei caratteri utilizzata per i test
            putchar (c);
            bigram[0] = c;
        }
        count++;
        //stampa dei caratteri utilizzata per i test
        putchar ('\n');
    }
    free(buf);
    return count;
}
