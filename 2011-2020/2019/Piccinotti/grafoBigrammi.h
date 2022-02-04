#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct nodo{
	char valore[3];
	int numeroFrequenza; //quante volte ho visto il nodo come primo
	int numeroTransazioni; //quante volte esco dal nodo

	struct nodo* next;
	struct bigrammiSuccessivi* prossimo;
}nodo;

typedef struct bigrammiSuccessivi{
	int numeroFrequenzaTransazione;

	struct nodo* bigramma;
	struct bigrammiSuccessivi* next;
}bigrammiSuccessivi;

nodo* creaNodo(char* valore);

void grafoFree();

nodo* cercaNodo(char* valore);

void stampaGrafo(nodo* nodo);

nodo* cercaBigrammaSuccessivo(bigrammiSuccessivi* bigrammaSucc, char* bigramma);

bigrammiSuccessivi* cercaBigrammaSuccessivoBigramma(bigrammiSuccessivi* bigrammaSucc, char* bigramma);

int cercaSequenza(char* bigrammi[], int numeroBigrammi);

void inserisciSequenza(char* bigrammi[], int numeroBigrammi);
