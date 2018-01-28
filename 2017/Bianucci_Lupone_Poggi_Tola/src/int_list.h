/*****************************************************************************
Libreria liste di interi
*/

/**************************************************************************/
/*                          intestazioni                                  */
/**************************************************************************/

#ifndef __LIB_INT_LIST_
#define __LIB_INT_LIST_ 002

/**************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

typedef struct int_node
{
    int value;
    struct int_node *next;
} int_node;

typedef int_node *int_list;

/**********************************************
    crea una lista vuota
   \retval NULL il puntatore alla lista vuota */
int_list newList();

/***********************************************************************/
void freeList(int_list *l);

/** iserisce n nella lista l creando un nuovo nodo  (inserisce in testa)
   \param l  la lista 
   \param n  elemento da inserire
 
   \retval p puntatore alla nuova lista se l'allocazione ha avuto successo
   \retval NULL in caso di errore
 
    */
int_list insertList(int_list l, int n);

/**************************************************************** 
   cancella n dalla lista (se c'e')
   \param l  la lista 
   \param n  elemento da cancellare
 
   \retval p puntatore alla nuova lista
    */
int_list removeFromList(int_list l, int n);

/**************************************************************** 
   cancella e preleva dallatesta della lista (se non vuota) il primo elemento
   \param  l  la lista 
   \param *n  Ptr al dato prelevato 
   \param *esito_estrazione  (se ritorna 1 il valore di *n e' valido)
                             (se ritorna 0 il valore di *n non e' stato modificato perche' la lista era vuota
 
   \retval p puntatore alla nuova lista eventalmente NULL se la lista si e' svuotata
    */
int_list removeFromHeadList(int_list l, int *n, int *esito_estrazione);

/*stampa la lista dalla testa alla coda separando con -> i valori */
void print_list(int_list);

/*Fa' la Map della lista applicandom "f" a tutti gli elementi*/
void mapList(int (*f)(int), int_list l);

/***********************************************************************/
/* 
la reduce applica una funzione binaria a tutti i termini della klista pertendo dall' ultimo risalendo a ritroso fine al primo
*/
/***********************************************************************/
/*Difatto opera come applicando la funzione  a due elementi della lista, 
 posizione attuale posizione successiva, di solito si opera in modo ricorsivo fine ad arrivare in fondo alla lista 
 ritornando indietro dalla ricorsione si calcola la F
 L'ultimo elemeto verr� calcolato fra se stesso e l'elemento neutro.
 Se f f� la somma, l'elemento neutro non potr� essere che 0.
*/
/** combina gli elementi della lista l usando un operatore binario associativo 
   \param l la lsita
   \param f l'operatore binario
   \param en l'elemento neutro di f
 
   \return la 'somma' degli elementi di l secondo f (l1, f ( l2 , f (... f (lN, en)))...))*/
int reduceList(int (*f)(int, int), int en, int_list l);

/* Restituisce un array contenente tutti gli elementi della lista */
int *toArray(int_list l, int num);

/**************************************************************************/
#endif
/**************************************************************************/
/*                          fine HEADER                                   */
/**************************************************************************/
