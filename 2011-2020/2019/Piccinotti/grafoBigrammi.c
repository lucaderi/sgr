#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "grafoBigrammi.h"

int numeroNodiGrafo=0;
nodo* nodoIniziale = NULL;

nodo* creaNodo(char* valore){
	nodo* nuovoNodo = (nodo*)malloc(sizeof(nodo));
	strcpy(nuovoNodo->valore, valore);
	nuovoNodo->numeroFrequenza=0;
	nuovoNodo->numeroTransazioni=0;
	nuovoNodo->next = nodoIniziale;
	nuovoNodo->prossimo = NULL;
	nodoIniziale = nuovoNodo;
	return nuovoNodo;
}

void grafoFree(){
	while(nodoIniziale != NULL){
		struct nodo* nodoFree = nodoIniziale;
		nodoIniziale = nodoFree->next;
		//elimino i bigrammi successivi
		while(nodoFree->prossimo != NULL){
			struct bigrammiSuccessivi* bigrammaFree = nodoFree->prossimo;
			nodoFree->prossimo = bigrammaFree->next;
			free(bigrammaFree);
		}
		free(nodoFree->prossimo);
		free(nodoFree);
	}
}

nodo* cercaNodo(char* valore){
	nodo* tmp = nodoIniziale;

	while(tmp!=NULL){
		if(!strcmp(tmp->valore, valore))
			return tmp;
		tmp = tmp->next;
	}
	return NULL;
}

void stampaGrafo(nodo* nodo){
	while(nodo!=NULL){
		printf("%s\n", nodo->valore);
		nodo = nodo->next;
	}
}

nodo* cercaBigrammaSuccessivo(bigrammiSuccessivi* bigrammaSucc, char* bigramma){
	while(bigrammaSucc != NULL){
		if(!strcmp(bigrammaSucc->bigramma->valore, bigramma))
			return bigrammaSucc->bigramma;
		bigrammaSucc = bigrammaSucc->next;
	}
	return NULL;
}

bigrammiSuccessivi* cercaBigrammaSuccessivoBigramma(bigrammiSuccessivi* bigrammaSucc, char* bigramma){
	while(bigrammaSucc != NULL){
		if(!strcmp(bigrammaSucc->bigramma->valore, bigramma))
			return bigrammaSucc;
		bigrammaSucc = bigrammaSucc->next;
	}
	return NULL;
}

int cercaSequenza(char* bigrammi[], int numeroBigrammi){
	//cerco il nodo di partenza
	int numeroSequenza=0;
	nodo* tmp = cercaNodo(bigrammi[0]);
	if(tmp!=NULL){
		for(numeroSequenza=1; numeroSequenza<numeroBigrammi; numeroSequenza++){
			tmp = cercaBigrammaSuccessivo(tmp->prossimo, bigrammi[numeroSequenza]);
			if(tmp==NULL)
				return numeroSequenza;
		}
	}
	return numeroSequenza;
}

void inserisciSequenza(char* bigrammi[], int numeroBigrammi){

	//cerco il nodo iniziale
	nodo* tmp = cercaNodo(bigrammi[0]);
	if(tmp == NULL)
		tmp = creaNodo(bigrammi[0]);
	
	tmp->numeroFrequenza++;
	numeroNodiGrafo++;

	for(int i=1; i<numeroBigrammi; i++){
		tmp->numeroTransazioni++;
		//controllo se nela lista dei biagrammi successivi c'è il nodo successivo cioè bigramma[1]	

		bigrammiSuccessivi* bigramma = cercaBigrammaSuccessivoBigramma(tmp->prossimo, bigrammi[i]);
		if(bigramma == NULL){
			//non esiste il collegamento

			nodo* nodoSuccessivo = cercaNodo(bigrammi[i]);
			if(nodoSuccessivo == NULL)
				nodoSuccessivo = creaNodo(bigrammi[i]);

			bigramma = (bigrammiSuccessivi*)malloc(sizeof(bigrammiSuccessivi));
			bigramma->bigramma = nodoSuccessivo;
			bigramma->numeroFrequenzaTransazione=0;
			bigramma->next = tmp->prossimo;
			tmp->prossimo = bigramma;
		}
		bigramma->numeroFrequenzaTransazione++;
		tmp = bigramma->bigramma;
	}
}	