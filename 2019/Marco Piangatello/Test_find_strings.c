#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include "Find_strings.h"

/*
funzione di supporto per i test
legge contenuto del file 'name' e lo inserisce in un buffer
*/
unsigned char* ReadFile(char *name, int* size){
	FILE *file;
	unsigned char *buffer;
	int fileLen;

	//Open file
	file = fopen(name, "rb");
	if (!file)
	{
		perror("Errore apertura file");
		return NULL;
	}

	//Get file length
	fseek(file, 0, SEEK_END);
	fileLen=ftell(file);
	fseek(file, 0, SEEK_SET);
	*size = fileLen;


	//Allocate memory
	buffer=(unsigned char *)malloc(fileLen+1);
	if (!buffer){
		perror("Errore allocazione memoria");
                fclose(file);
		return NULL;
	}

	//Read file contents into buffer
	fread(buffer, fileLen, 1, file);
	fclose(file);

	return buffer ;
}

int main(int argc, char *argv[]){

    int i = 0;
    unsigned char *tmp = ReadFile(argv[1],&i);
    if ( tmp != NULL){
        printf("%d\n",find_strings (i, (char*) tmp,4));
    }
    free(tmp);
    return 0;

} 
