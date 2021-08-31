#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "lib/count_min_sketch.h"
#include "generale.h"


u_int32_t errore;

typedef struct {
    int *valore;        //c=colonne, p = profondità
    char **nome;
    int n,              //numero di stringhe target da controllare
        target;         //numero totale di stringhe lette
    char * nome_test;
} test_t;

void check_value(test_t *test, cmsketch_t * table );
void free_test(test_t *test);
test_t* new_test_t(u_int32_t n, u_int32_t target, char* nome_test);
void read_example_file(cmsketch_t* table, char* esempi);
test_t* read_risultati_file(char* risultati);
u_int32_t count_table(cmsketch_t * table );




//*********************MAIN*********************************************************

int main(int argc, char *argv[]){
    errore = 0;
    
    
    //***************************small_table*******************************************************************************************************
    cmsketch_t* small_table = new_count_min_sketch(SMALLR, SMALLC);
    read_example_file(small_table, SMALLES1);
    test_t* small_test = read_risultati_file(SMALLRIS1); //creazione struttura dati ausiliaria
    check_value(small_test, small_table);                //controllo dei valori

    cmsketch_t* small_table2 = new_count_min_sketch(SMALLR, SMALLC);
    read_example_file(small_table2, SMALLES2);
    
    cmsketch_t * sum_small_table = sum_count_min_sketch(small_table, small_table2);
    print_table(small_table);
    print_table(small_table2);
    print_table(sum_small_table);


    //***************************table1******************************************************************************************************* 
    cmsketch_t* table = new_count_min_sketch(RIGHE, COLONNE);
    read_example_file(table, ES1);
    test_t* test = read_risultati_file(RIS1);
   
    if(argc!=1) print_table(table); //argc viene usato come discriminante tra test1 e test2
    check_value(test, table);   


    //***************************table2******************************************************************************************************
    cmsketch_t* table2 = new_count_min_sketch(RIGHE, COLONNE);
    read_example_file(table2, ES2);
    test_t* test2 = read_risultati_file(RIS2);

    if(argc!=1) print_table(table2);//argc viene usato come discriminante tra test1 e test2
    check_value(test2, table2);

   //**************SUM,CLONE************************************************************************************************************************
   

    cmsketch_t* sum_table;
    if((sum_table = sum_count_min_sketch(table, table2))!=NULL){
         if(argc!=1) print_table(sum_table);//argc viene usato come discriminante tra test1 e test2
    }
    cmsketch_t* table_clone = clone_count_min_sketch(sum_table);
    if(argc!=1) print_table(table_clone);

    cmsketch_t* table_s;
    if((table_s = sum_count_min_sketch(table, small_table))!=NULL){
         print_table(table_s);
    }
    
    
    //******free****************************************************************
    free_count_min_sketch(table);
    free_count_min_sketch(table2);
    free_count_min_sketch(sum_table);
    free_count_min_sketch(table_clone);
    free_count_min_sketch(small_table);
    free_count_min_sketch(small_table2);
    free_count_min_sketch(sum_small_table);
    free_test(test);
    free_test(test2);
    free_test(small_test);
    
    if(errore==0){printf("Nessun errore riscontrato \n");
        }else{
            printf("%d errori riscontrati \n", errore);
        }


}
//Legge un File di esempio e riempe un Count Min Sketch 
void read_example_file(cmsketch_t* table, char* esempi){
    char *aux = malloc(sizeof(char)*BUF_FGETS);
    char *s ;
    int n = 0, contatore =0, c_tabella=0;
    FILE *ifp;
    CHECK_EQ(ifp=fopen(esempi, "r"),NULL, "fopen");

    while(fgets(aux, BUF_FGETS, ifp)!=NULL){
        s = strtok(aux, "\n");
        add_min_count_sketch(table, aux);
          
    }
    free(aux);
    fclose(ifp);
}


/*Legge un file di risultato, che contiene il numero di volte che è stata inserita una determinata stringa,
  ritorna una struttura dati test_t che contiene i valori del file*/
test_t* read_risultati_file( char* risultati){
    //apertura file
    test_t* test;
    char *aux;
    u_int32_t n, i, target;
    FILE *ifp;
    CHECK_EQ(ifp=fopen(risultati, "r"),NULL, "fopen");
    //legge una riga
    char *s= malloc(sizeof(char)*BUF_FGETS);
    CHECK_EQ(fgets(s, BUF_FGETS, ifp),NULL, "fgets");  
    target= atoi(s);

    CHECK_EQ(fgets(s, BUF_FGETS, ifp),NULL, "fgets"); 
    n = atoi(s);

    test= new_test_t(n, target, risultati);


    for(i=0 ; i<test->target ; i++){
        CHECK_EQ(fgets(s, BUF_FGETS, ifp),NULL, "fgets");
        CHECK_EQ((aux=strtok(s, ":")),NULL, "strtok");
        test->nome[i]= strcpy(calloc(BUF_FGETS, sizeof(char)), aux);
        CHECK_EQ((aux=strtok(NULL, ":")),NULL, "strtok");
        test->valore[i]= atoi(aux);
    }  
    free(s);
    fclose(ifp);

    return test;

}

//struttura dati di supporto per eseguire il Test
test_t* new_test_t(u_int32_t n, u_int32_t target, char* nome_test){
    test_t* test;
    test = malloc(sizeof(test_t));
    test->valore = malloc(sizeof(int)*target);
    test->nome = malloc(sizeof(char*)*target);
    //test->nome_test = malloc(sizeof(char)*BUF_FGETS);
    test->n =n;
    test->target = target;
    test->nome_test = nome_test;
    return test;
}
void free_test(test_t *test){
    for( int i = 0; i<test->target; i++){
        free(test->nome[i]);
    }
    free(test->valore);
    free(test->nome);
   // free(test->nome_test);
    free(test);

}


//controlla che i valori della riga della tabella non siano minori del numero effettivo di inserimenti
void check_value(test_t *test, cmsketch_t * table ){
    
    for(int i = 0 ; i< test->target; i++){        
        u_int32_t * aux =riga_count_min_sketch( table, test->nome[i]);
        for(int j =0 ; j<table->c; j++){
                if(test->valore[i]>aux[j]){ printf("errore in %s : per stringa %s \n",test->nome_test, test->nome[i]); errore++;}
        }
        free(aux);
    }
    if(count_table(table)/table->c != test->n) {printf("errore : il numero di elementi non combacia  cardinalità : %d check : %d  \n ", test->n, count_table(table)/table->c);errore++;}
}

//Esegue la somma di tutti le righe e le colonne del Count Min Sketch
u_int32_t count_table(cmsketch_t * table ){
     u_int32_t c_tabella = 0;
        for(int i = 0 ; i< table->r; i++){        
                for(int j =0 ; j<table->c; j++){
                    c_tabella = c_tabella +table->t[i][j];
                }
            }
            return c_tabella;   
}