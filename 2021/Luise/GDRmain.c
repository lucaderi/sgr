#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include "ndpi_api.h"

//BUILD IN FASE DI TESTING

float alpha = 0.75;
float beta = 0.75;
int sleeptime = 10;
struct ndpi_des_struct *Instances;
int notif = 0;

//Funzione per averrtire a linea di comando
void alert(int type,char *source){
    if(type==0){printf("High spike of data from %s\n",source);}
    else{printf("Low spike of data from %s\n",source);}
}

//Funzione per generare una nuova istanza di DES
//L'array Instances contiene tutti gli struct di DES creati, così che scorrendolo si possano aggiornare tutti.
int newDES(char *line, int lines){
    char *DES = strtok(line," ");
    printf("Initialized DES for %s\n",DES);
    DES = strtok(NULL," ");
    struct ndpi_des_struct desI;
    int check = ndpi_des_init(&desI, alpha, beta, 0.05);
    if(check != 0){return 1;}
    Instances[lines] = desI;
    return 0;
}

//Funzione principale del programma
//Dopo aver controllato eventuali input, il programma legge /proc/net/dev e crea un'istanza di DES per ogni interfaccia di rete.
//Successivamente parte un while infinito, in cui si leggono i dati ogni X secondi e si comunicano eventuali spike di traffico.
//Le funzioni gettimeofday() sono utilizzate per fornire un quanto più accurato loop, e se le notifiche sono attive si stampa l'operazione.
int main(int argc, char *argv[]){
    if(argc > 1){
      sleeptime = atoi(argv[1]);
      if(sleeptime <= 0){
        printf("Input error\n");
        return 1;
    }}
    if(argc > 3){
      alpha = atof(argv[2]);
      beta = atof(argv[3]);
      if(alpha>=1 || alpha<=0 || beta>=1 || beta<=0){
        printf("Input error\n");
        return 1;
    }}
    if(argc > 4){
      if(strcmp(argv[4],"yes")==0){
        notif = 1;
      }else{
        if(strcmp(argv[4],"no")!=0){
          printf("Input error\n");
          return 1;
    }}}
    printf("Starting service with alpha = %.2f and beta = %.2f, checking every %d seconds\n",alpha,beta,sleeptime);
    FILE *dev1 = fopen("/proc/net/dev","r");
    char buff[255];
    for(int i = 0; i<2; i++){
        fgets(buff, 255, dev1);
    }
    int lines = 0;
    int n = 0;
    Instances = calloc(lines,sizeof(struct ndpi_des_struct));
    if(Instances == NULL){printf("Memory allocation error\n");return 1;}
    while(fgets(buff, 255, dev1) != NULL){
        int check = newDES(buff,lines);
        if(check!=0){printf("DES Instancing error\n");return 1;}
        lines++;
    }
    fclose(dev1);
    struct timeval Begin;
    struct timeval End;
    struct timeval Elapsed;
    int bytes;
    while(1){
        gettimeofday(&Begin,NULL);
        n++;
        for(int i = 0; i < lines; i++){
            FILE *dev = fopen("/proc/net/dev","r");
            for(int j = 0; j<3 + i; j++){
                fgets(buff, 255, dev);
            }
            char *slice = strtok(buff," ");
            bytes = atoi(strtok(NULL," "));
            double prediction, confidence_band;
            double lower, upper;
            int rc = ndpi_des_add_value(&Instances[i], bytes, &prediction, &confidence_band);
            lower = prediction - confidence_band;
            upper = prediction + confidence_band;
            if(bytes < lower && rc != 0){alert(1,slice);}
            if(bytes > upper && rc != 0){alert(0,slice);}
            if(notif == 1){printf("Loop %d for %s Expected %f, got %d\n",n,slice,prediction,bytes);}
            fclose(dev);
        }
        gettimeofday(&End,NULL);
        timersub(&End,&Begin,&Elapsed);
        usleep(sleeptime * 1000000 - Elapsed.tv_sec*1000000 - Elapsed.tv_usec);
    }
}
