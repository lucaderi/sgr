#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "creazioneBigrammi.h"


char** bigrammiArray(char* parola, int* num){
	int lunghezzaParola= strlen(parola)-1;
	int numeroBigrammi = strlen(parola)/2;
	char** bigrammi = malloc(sizeof(char*)*numeroBigrammi);
	*num=numeroBigrammi;
	int j=0;
	for(int i=0; i< numeroBigrammi; i++){
		bigrammi[i] = (char*) malloc(3*sizeof(char));
		bigrammi[i][0] = parola[j];
		if(parola[++j] == '\n')
			bigrammi[i][1] = '/';
		else
			bigrammi[i][1] = parola[j];
		bigrammi[i][2]='\0';
		j++;
	}
	return bigrammi;
}

void freeBiagrammaArray(char** bigrammi, int numeroBigrammi){
	for(int i=0; i<numeroBigrammi; i++)
		free(bigrammi[i]);
	free(bigrammi);
}