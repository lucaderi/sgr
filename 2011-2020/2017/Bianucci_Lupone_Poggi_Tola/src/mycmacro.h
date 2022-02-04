/* 
   File:            sysmacro.h
   Specifica:       macro per impieghi generici

*/

#ifndef MYCMACRO_H
#define MYCMACRO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef MEMSET /* necessita di string.h*/
#define bzero(a, b) memset(a, 0, b)
#endif

#ifndef STDIN
#define STDIN 0
#endif

#ifndef STDOUT
#define STDOUT 1
#endif

#ifndef STDERR
#define STDERR 2
#endif

/****************************************************
 * Macro per il controllo degli codici di errore 
 * restuiti da chiamate di funzioni di sistema
 * */

/* controlla se != 0; stampa errore e termina */
#define ec_notzero(s, m) \
    if ((s) != 0)        \
    {                    \
        perror(m);       \
        exit(errno);     \
    }

/* controlla se = -1; stampa errore e termina */
#define ec_meno1(s, m) \
    if ((s) == -1)     \
    {                  \
        perror(m);     \
        exit(errno);   \
    }

/* controlla se = NULL; stampa errore e termina (NULL) */
#define ec_null(s, m) \
    if ((s) == NULL)  \
    {                 \
        perror(m);    \
        exit(errno);  \
    }

/* controlla se =-1 V2; stampa errore ed esegue c */
#define ec_meno1_c(s, m, c) \
    if ((s) == -1)          \
    {                       \
        perror(m);          \
        c;                  \
    }

/**************************************************
 *  Definizioni retrompatibili con vecchie implementazioni
 * */
#define CIFERROR(s, m) ec_meno1(s, m)
#define CIFERROR3(s, m, c) ec_meno1_c(s, m, c)

/***************************************************
 * MACRO per DEBUG condizionate dal "#define DEBUG_ON"  
 *
 * eventualente attivabile nel makefile con apposito .PHONY:... debug..
 * 
 * #aggiunge a cflags la dichiarazione a compilazione della macro DEBUG_ON	
 * debug: CFLAGS+= -DDEBUG_ON
 * debug: all	
 * .... etc etc ...
 *  */

#ifdef DEBUG_ON
#define debug_block(b) \
    {                  \
        b              \
    }
#else
#define debug_block(b) \
    {                  \
        ;              \
    }
#endif
/*
 * ESEMPIO DI UTILIZZO!!
 *
 * debug_block(printf("Riga di debug %d\n",3);)
 * 
 * oppure:
 *   debug_block(printf("Riga di debug %d\n",3);\
 *                 x=x*x;\
 *                printf("nuovo valore di x=%d",x);)
 *  
*/

#define MAX_PORTS 65536

#endif
