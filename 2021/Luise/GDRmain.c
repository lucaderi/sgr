#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include "ndpi_api.h"

float alpha = 0.8;
float beta = 0.8;
int sleeptime = 10;
struct ndpi_des_struct *Instances;
int notif = 0;
struct timeval Begin, End, Elapsed;
int bytesIn, bytesOut, n, lines;
double predictionIn, predictionOut, confidence_band, lower, upper;

//Funzione per avvertire a linea di comando, chiamata se il DES rileva irregolarità
void alert(int type,char *source){
    if(type==0){printf("%s High spike of data received\n",source);}
    else if(type==1){printf("%s Low spike of data received\n",source);}
    else if(type==2){printf("%s High spike of data transmitted\n",source);}
    else if(type==3){printf("%s Low spike of data transmitted\n",source);}
}

//Funzione per generare una nuova istanza di DES, chiamata più volte a inizio programma
//L'array Instances contiene tutti gli struct di DES creati, così che scorrendolo si possano aggiornare tutti.
int newDES(char *line, int num){
    char *DESname = strtok(line," ");
    printf("Initialized DES for %s\n",DESname);
    struct ndpi_des_struct des1;
    int check = ndpi_des_init(&des1, alpha, beta, 0.05);
    if(check != 0){return 1;}
    Instances[num*2] = des1;
    struct ndpi_des_struct des2;
    check = ndpi_des_init(&des2, alpha, beta, 0.05);
    if(check != 0){return 1;}
    Instances[num*2 + 1] = des2;
    return 0;
}

//Funzione chiamata a ogni ciclo del programma, legge /proc/net/dev e aggiorna i DES
void cycle(char* buff){
  //Apertura del file e rimozione delle prime due linee
  FILE *dev = fopen("/proc/net/dev","r");
  for(int j = 0; j<2; j++){
    fgets(buff, 255, dev);
  }
  n++;
  //Loop principale, uno per interfaccia di rete
  for(int i = 0; i < lines; i++){
    fgets(buff, 255, dev);
    char *slice = strtok(buff," ");
    bytesIn = atoi(strtok(NULL," "));
    for(int j=0;j<7;j++){
      atoi(strtok(NULL," "));
    }
    bytesOut = atoi(strtok(NULL," "));
    int rc = ndpi_des_add_value(&Instances[i*2], bytesIn, &predictionIn, &confidence_band);
    lower = predictionIn - confidence_band;
    upper = predictionIn + confidence_band;
    if(bytesIn < lower && rc != 0){alert(1,slice);}
    if(bytesIn > upper && rc != 0){alert(0,slice);}
    rc = ndpi_des_add_value(&Instances[i*2 + 1], bytesOut, &predictionOut, &confidence_band);
    lower = predictionOut - confidence_band;
    upper = predictionOut + confidence_band;
    if(bytesOut < lower && rc != 0){alert(3,slice);}
    if(bytesOut > upper && rc != 0){alert(2,slice);}
    //Se l'utente ha scelto la modalità estesa, qui viene stampato un recap 
    if(notif == 1){printf("Loop %d for %s  Expected %.2f in, got %d;  Expected %.2f out, got %d\n",n,slice,predictionIn,bytesIn,predictionOut,bytesOut);}
  }
  fclose(dev);
}

//Funzione principale del programma
int main(int argc, char *argv[]){
    //Controllo e applicazione di  eventuali argomenti
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
    //Preparazione del servizio: si legge per la prima volta il file, contandone le interfacce, e per ognuna si creano due DES,
    //Uno per l'input e uno per l'output. Entrambi vengono inseriti nell'array Instances.
    lines = -2;
    n = 0;
    FILE *dev1 = fopen("/proc/net/dev","r");
    char buff[255];
    while(fgets(buff, 255, dev1) != NULL){ //Conteggio delle interfacce attive
        lines++;
    }
    fclose(dev1);
    dev1 = fopen("/proc/net/dev","r");
    for(int i = 0; i<2; i++){ //Rimozione delle prime due linee e allocazione dell'array per i DES
        fgets(buff, 255, dev1);
    }
    Instances = calloc(lines*2,sizeof(struct ndpi_des_struct));
    if(Instances == NULL){printf("Memory allocation error\n");return 1;}
    for(int i = 0; i < lines; i++){ //Creazione delle istanze di DES
        fgets(buff, 255, dev1);
        int check = newDES(buff,i);
        if(check!=0){printf("DES Instancing error\n");return 1;}
    }
    fclose(dev1);
    while(1){ //Il while chiama cycle fino alla terminazione del programma
        gettimeofday(&Begin,NULL);
        cycle(buff);
        gettimeofday(&End,NULL);
        timersub(&End,&Begin,&Elapsed);
        //La sleep viene effettuata tenendo conto del tempo impiegato a eseguire i comandi
        usleep(sleeptime * 1000000 - Elapsed.tv_sec*1000000 - Elapsed.tv_usec);
    }
}
