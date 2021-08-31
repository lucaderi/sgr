#include <stdlib.h> 
#include <string.h>
#include <limits.h>
#include "count_min_sketch.h"
#include "fun_hash.h"

#include <stdio.h>

/*
    @brief : print the matrix of cmsketch
    @param : table = the data struct to print
   */
void print_table(cmsketch_t* table){
    if(table == NULL) return ;
    printf("\n");
    for(int i = 0 ; i< table->r; i++){
        for(int j=0; j< table->c; j++){
            printf(" %-4d", table->t[i][j]);
        }
         printf("\n");
    }
    printf("\n");
    printf("\n");
}


/*
  @brief   : create a new data struct with r row and c columns
  @param   : r  = row of the matrix of new cmsketch_t
  @param   : c  = columns of the matrix
  @return  : new cmsketch_t
  */
cmsketch_t* new_count_min_sketch(u_int32_t r, u_int32_t c){
    cmsketch_t* table;
    table = malloc(sizeof(cmsketch_t));
    table->r = r;
    table->c = c;
    table->t = malloc( r*sizeof(u_int32_t*));

    for( int i = 0; i< r; i++){
        table->t[i] = calloc(c,sizeof(u_int32_t*));
    } 
    return table;
}

/*
  @brief : free the memory pointed by a cmsketch_t
  @param : table = the cmsketch_t to free
  */
void free_count_min_sketch(cmsketch_t* table){
    if(table == NULL) return ;
    for(int i = 0; i<table->r; i++){
        free(table->t[i]);
    }            
    free(table->t);
    free(table);
}

/*
  @brief : add a count of a string in a cmsketch_t
  @param : table = cmskestch_t to which the string is added
  @param : str = string to add
  */
void add_min_count_sketch(cmsketch_t* table, char *str){
     if(table == NULL|| str==NULL) return ;
    u_int32_t a, b,hash;

    hash_function(str,table->r, &a, &b);
    for(int i=0; i<table->c; i++){
        hash = hash_increment(table->r, &a, &b, i); 
        table->t[hash][i]++; 
    }    
}

/*
  @brief  : read the value in a cmsketch_t, associated with a string
  @param  : table = cmsketch_t to read
  @param  : str = string to search for
  @return : value associated with str in table
  */
u_int32_t read_count_min_sketch(cmsketch_t * table, char *str){

    if(table == NULL || str==NULL) return -1 ;

    u_int32_t a, b, hash, min=UINT_MAX;

    hash_function(str, table->r, &a, &b);
    for(int i=0; i<table->c; i++){
        hash = hash_increment(table->r, &a, &b, i); 
        if(table->t[hash][i] <min ) min =table->t[hash][i];
    }
    return min;
}

/*
  @brief : create a new cmsketch_t that is the sum of two cmsketch_t
  @param : table1 & table2 = cmsketch_t to sum
  @return: new cmsketch_t which is the sum of table1 and table2
  */
cmsketch_t* sum_count_min_sketch(cmsketch_t * table1, cmsketch_t * table2){
    if(table1->c == table2->c && table1->r==table2->r){
        int i,j;
        cmsketch_t * sum = new_count_min_sketch(table1->r, table1->c);
        for(i=0; i<table1->r; i++){
            for(j=0; j<table1->c; j++){
                sum->t[i][j] = table1->t[i][j]+table2->t[i][j];
            }
        } 
        return sum;
    }else return NULL;
}

/*
  @brief : return a copy of the parameter
  */
cmsketch_t* clone_count_min_sketch(cmsketch_t * table){
        if(table == NULL) return NULL ;
        int i,j;
        cmsketch_t * clone = new_count_min_sketch(table->r, table->c);
        for(i=0; i<table->r; i++){
            for(j=0; j<table->c; j++){
                clone->t[i][j] = table->t[i][j];
            }
        } 
        return clone;
}

/*
  @brief  :  return the value associated with a string for each columns
  @param  :  table = cmsketch_t to read
  @param  :  str = string to search in
  @return :  array of lenght table->c (number of columns),
               with the value of position i is the value associated with str in column i
  */
u_int32_t * riga_count_min_sketch(cmsketch_t* table, char* str){
    if(table == NULL || str==NULL) return NULL;
   u_int32_t a, b,hash;
   u_int32_t * aux = malloc(sizeof(u_int32_t)*table->c);
    hash_function(str,table->r, &a, &b);
    for(int i=0; i<table->c; i++){
        hash = hash_increment(table->r, &a, &b, i); //hash
        aux[i]=table->t[hash][i]; 
    }
    return aux;
}
