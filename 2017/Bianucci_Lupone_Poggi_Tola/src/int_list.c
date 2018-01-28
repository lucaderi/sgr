/*
Funzioni di libreria per Liste di interi
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "int_list.h"

/***********************************************************************/
int_list newList(void)
{
  int_list Aux;
  Aux = NULL;
  return Aux;
}
/***********************************************************************/
void freeList(int_list *l)
{
  int_list Aux;
  while (*l != NULL)
  {
    Aux = *l;
    *l = (*l)->next;
    free(Aux);
  }
  *l = NULL;
}

/***********************************************************************/
int_list insertList(int_list l, int n)
{
  int_list Aux;
  Aux = malloc(sizeof(int_node));
  if (Aux == NULL)
  {
    printf("\nproblemi allocazione memoria lista\n");
    exit(1);
  }
  Aux->value = n;
  if (l == NULL)
    Aux->next = NULL;
  else
    Aux->next = l;
  return Aux;
}

/***********************************************************************
Elimina un elemento se esiste nella lista
*/
int_list removeFromList(int_list l, int n)
{
  int_list prec, curr;
  int intesta = 1;
  /*se l'elemeto da eliminare è quello di testa la procedura è più  particolare*/
  if (l != NULL)
  {
    while ((l != NULL) && (intesta))
    {
      if (l->value == n)
      {
        curr = l;
        l = l->next;
        free(curr);
        return l;
      }
      else
        intesta = 0;
    }
    /*l'perazione precedente potrebbe avere svuotato la lista se di un unico elemto con il valore desiderato 
          ma se non l'ha fatto devo continuare il controllo*/
    if (l != NULL)
    {
      prec = l;
      curr = prec->next;
      while (curr != NULL)
      {
        if ((curr->value) == n)
        {
          prec->next = curr->next;
          free(curr);
          curr = prec->next; /*riga eliminabile importata da un codice modificato*/
          return l;
        }
        else
        {
          prec = curr;
          curr = curr->next;
        }
      }
    }
  }
  return l;
}

/**************************************************************** 
   cancella e preleva dallatesta della int_list (se non vuota) il primo elemento
*/
int_list removeFromHeadList(int_list l, int *n, int *esito_estrazione)
{
  int_list curr;
  *esito_estrazione = 0;
  /*sel'elemeto da eliminare è quello di testa la procedura è più  particolare*/
  if (l != NULL)
  {
    *n = l->value;
    curr = l;
    l = l->next;
    free(curr);
    *esito_estrazione = 1;
  }
  return l;
}
/***********************************************************************/
void print_list(int_list l)
{
  while (l != NULL)
  {
    printf("%d -> ", l->value);
    l = l->next;
  }
  printf("nil\n");
}

/***********************************************************************/
/*fà la map - cioè applica la funzione "f" a tutti gli elemti della lista 
*/
void mapList(int (*f)(int), int_list l)
{
  while (l != NULL)
  {
    l->value = f(l->value);
    l = l->next;
  }
}

/***********************************************************************/
/*Difatto opera come applicando la funzione  a due elementi della lista, 
 posizione attuale posizione successiva, di solito si opera in modo ricorsivo fine ad arrivare in fondo alla lista 
 ritornando indietro dalla ricorsione si calcola la F
 L'ultimo elemeto verrà calcolato fra se stesso e l'elemento neutro.
 Se f fà la somma, l'elemento neutro non potrà essere che 0.
*/
/** combina gli elementi della lista l usando un operatore binario associativo 
   \param l la lsita
   \param f l'operatore binario
   \param en l'elemento neutro di f
 
   \return la 'somma' degli elementi di l secondo f (l1, f ( l2 , f (... f (lN, en)))...))*/
int reduceList(int (*f)(int, int), int en, int_list l)
{
  if (l == NULL)
    return en;
  else
    return f(l->value, reduceList(f, en, l->next)); /*RICORSIVA*/
}

int *toArray(int_list l, int num)
{
  if (l == NULL || num <= 0)
    return NULL;
  int i = 0;
  int *array = (int *)malloc((num + 1) * sizeof(int));
  if (array == NULL)
  {
    printf("\nproblemi allocazione memoria lista\n");
    exit(1);
  }
  int_list corr = l;
  while (corr != NULL)
  {
    array[i] = corr->value;
    corr = corr->next;
    i++;
  }
  array[num] = -1;
  return array;
}
