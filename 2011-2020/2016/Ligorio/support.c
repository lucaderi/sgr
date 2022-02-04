/*
 * support.c
 * 
 * Progetto gestione di reti 2015/2016
 *
 * Realizzato da Francesco Ligorio  
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <pcap/pcap.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include "cJSON-master/cJSON.h"

#define MAX_ESSID_LENGTH 32
#define CHANNEL_NUMBER 13

#define IFERRORM1(x) if(x == -1){		\
    printf("%s\n", strerror(errno));		\
    exit(EXIT_FAILURE);				\
  }

typedef struct _node{
  u_char station[6];
  struct timeval tv;
  int status; 
  struct _node *next;  
} node;

typedef node *list;

typedef struct _info{
  uint16_t channel;
  int8_t signal;
  list stations;
} info;

typedef struct _ap_node{
  char essid[MAX_ESSID_LENGTH];
  u_char bssid[6];
  int chsist_index;
  info chsist[CHANNEL_NUMBER];
  int status;
  struct timeval tv;
  struct _ap_node *next;
} ap_node;

typedef ap_node *ap_list;

/*Funzioni comparazione, copia e stampa MAC*/
void mac_copy(u_char *mac1, u_char *mac2){
  int i = 0;

  for(i = 0; i < 6; i++)
    *(mac1 + i) = *(mac2 + i);
}

int mac_compare(u_char *mac1, u_char *mac2){
  int i =0, found = 0;

  for(i = 0; i < 6 && !found; i++)
    if((int) *(mac1 + i) != (int) *(mac2 + i))
      found ++;
  
  return found;
}

/* Funzione usata per la rappresentazione del mac
 * address nella notazione tipica
 */
void make_bssid(u_char *mac, char *dest){

  int i = 0, j = 0, bytes;

  for(i = 0; i < 6; i++){
    bytes = sprintf(dest + j, "%x", *(mac + i));
    if (i != 5)
      *(dest + j + bytes) = ':';
    else
      *(dest + j + bytes) = '\0';
    j = j + bytes + 1;
  }

}

void print_mac(u_char *mac){

  int i = 0;
  
  for(i = 0; i < 6; i++)
    if (i != 5)
      printf("%x:", *(mac+i));
    else
      printf("%x  ", *(mac+i));
  
}
/* </Funzioni comparazione, copia e stampa MAC> */


/* Creazione nuova lista di stazioni */
list new_list(){
  list l = NULL;
  return l;
}

/* Creazione nuova lista di access points */
ap_list new_ap_list(){
  ap_list l = NULL;
  return l;
}

/* <Aggiornamento struttura> */

/* Controllo sull'ultimo aggiornamento */
int check_last_update(time_t current_time, time_t last_update, double timeout){

  int outofdate = 0; 
  double diff = difftime(current_time, last_update);

  if (diff >= timeout)
    outofdate++;

  return outofdate;
}

/* Invalida l'access point che non e' stato aggiornato negli ultimi "timeout secondi" */
void rem_ap_node(ap_list *l, time_t current_time, double timeout){

  ap_list temp = *l;
  
  if (check_last_update(current_time, (temp->tv).tv_sec, timeout))
    temp->status = 0;
 
}

/* Invalida tutte le stazioni che non sono state aggiornate negli ultimi "timeout" secondi */
int rem_node(list *l, time_t current_time, double timeout){

  list temp = *l;
  int count = 0;
  
  while(temp != NULL){
    if (temp->status)
      if (check_last_update(current_time, (temp->tv).tv_sec, timeout)){
	temp->status = 0;
	count++;
      }
    temp = temp->next;
  }

  return count;
  
}

void clean(ap_list *apl, double timeout, int verbose){

  int index = 0,
    count_rem = 0;
  ap_list temp1 = *apl;
  list temp2 = NULL, stations = NULL;
  struct timeval current_time;

  /* Scorre la struttura e per ogni canale di ogni access point controlla
   * che ogni stazione collegata sia ancora valida. Nel caso in cui venga
   * rilevata una stazione non valida in un canale qualsiasi di un certo
   * access point allora viene controllata anche la validita' di quel paricolare
   * AP (ha perso una stazione dunque sospetto che non sia piu' raggiungibile) .
   */
  
  while(temp1 != NULL){
    if (temp1->status){
      count_rem = 0;
      if (verbose){
	printf("******** AP %s ", temp1->essid);
	print_mac(temp1->bssid);
	printf("********\n");
      }
      for(index = 0; index < temp1->chsist_index; index++){
	temp2 = (*(temp1->chsist + index)).stations;
	IFERRORM1(gettimeofday(&current_time, NULL));
	stations = temp2;
	if (verbose){
	  while(temp2 != NULL){
	    if (temp2->status){
	      printf("Validity check station ");
	      print_mac(temp2->station);
	      printf("\n");
	      printf("Current time: %s", ctime(&current_time.tv_sec));
	      printf("Last update: %s", ctime(&((temp2->tv).tv_sec)));
	      printf("The station has not been updated for %.0f seconds\n\n",
		     difftime(current_time.tv_sec, (temp2->tv).tv_sec));
	    }
	    temp2 = temp2->next;
	  }
	}
	count_rem = count_rem + rem_node(&stations, current_time.tv_sec, timeout);
      }
      if (count_rem > 0){
	if (verbose){
	  printf("Validity check access point %s ", temp1->essid);
	  print_mac(temp1->bssid);
	  printf("\n");
	  printf("Current time: %s", ctime(&current_time.tv_sec));
	  printf("Last update: %s", ctime(&((temp1->tv).tv_sec)));
	  printf("The access point has not been updated for %.0f seconds\n\n",
		 difftime(current_time.tv_sec, (temp1->tv).tv_sec));
	}
	rem_ap_node(&temp1, current_time.tv_sec, timeout);
      }
    }
    temp1 = temp1->next;
  }
}  
/* </Aggiornamento struttura> */

/* Deallocazione memoria dinamica */
void free_stations(list *l){

  list temp = *l,
    target = NULL;

  while(temp != NULL){
    target = temp;
    temp = temp->next;
    free(target);
  }
  *l = NULL;
  
}

void free_aps(ap_list *apl){

  ap_list temp1 = *apl,
    target = NULL;
  list temp2 = NULL;
  int index = 0;

  while(temp1 != NULL){
    for(index = 0; index < temp1->chsist_index; index++){
      temp2 = (*(temp1->chsist + index)).stations;
      free_stations(&temp2);
    }
    target = temp1;
    temp1 = temp1->next;
    free(target);
  }
  *apl = NULL;
  
}
/* </Deallocazione memoria dinamica> */


/* <Funzioni di utilita' per ap_list> */

/* Restituisce il nodo associato all'AP avente 
 * come mac address il parametro "bssid" 
 */
ap_list get_node(ap_list *l, u_char *bssid){
  ap_list temp = *l, pointer = NULL;
  int found = 0;
  
  while(temp != NULL && !found){
    if (mac_compare(temp->bssid, bssid) == 0){
      found ++;
      pointer = temp;
    }
    temp = temp->next;
  }

  return pointer;
}

/* Controllo la presenza di un certo canale per un particolare AP,
 * se il canale e' assente restituisce -1.
 */
int get_index(ap_node *ap, uint16_t new_channel){

  int index = 0,
    found = 0;

  while(index < ap->chsist_index && !found)
    if (new_channel == (*(ap->chsist + index)).channel)
      found ++;
    else
      index++;

  if(!found)
    index = -1;

  return index;
  
}

void add_ap_node(ap_list *l, char *essid, u_char *bssid,
		 uint16_t channel, int8_t signal, struct timeval tv){

  ap_node *n = NULL, *pointer = NULL;
  int index;
  
  if ((pointer = get_node(l, bssid)) == NULL){
    n = malloc(sizeof(ap_node));
    strcpy(n->essid, essid);
    mac_copy(n->bssid, bssid);
    n->chsist_index = 0;
    (*(n->chsist + n->chsist_index)).channel = channel;
    (*(n->chsist + n->chsist_index)).signal = signal;
    (*(n->chsist + n->chsist_index)).stations = new_list();
    n->chsist_index++;
    n->status = 1;
    n->tv = tv;
    n->next = *l;
    *l = n;
  }
  else{
    /* L'AP e' gia' presente, controllo allora la presenza del canale */
    if ((index = get_index(pointer, channel)) == -1){
      (*(pointer->chsist + pointer->chsist_index)).channel = channel;
      (*(pointer->chsist + pointer->chsist_index)).signal = signal;
      (*(pointer->chsist + pointer->chsist_index)).stations = new_list();
      pointer->chsist_index++;
    }
    /* Aggiornamento stato (validita') e timeval */
    pointer->status = 1;
    pointer->tv = tv; 
  }
}

void update_ap(ap_list *apl, char *essid, u_char *bssid, uint16_t channel,
	       int8_t signal, const struct pcap_pkthdr h){

  add_ap_node(apl, essid, bssid, channel, signal, h.ts);

}
/* </Funzioni di utilita' per ap_list> */


/* <Funzioni di utilita' per list> */

list isIn(list l, u_char *station){

  int found = 0;
  list temp = l;
  
  while(temp != NULL && !found){
    if (mac_compare(temp->station, station) == 0)
      found ++;
    else
      temp = temp->next;
  }

  return temp;
  
}

void add_node(list *l, u_char *station, struct timeval tv){

  list n = NULL,
    pointer = NULL;
  
  if ((pointer = isIn(*l, station)) == NULL){
    n = malloc(sizeof(node));
    mac_copy(n->station, station);
    n->tv = tv;
    n->status = 1;
    n->next = *l;
    *l = n;
  }
  else{
    pointer->tv = tv;
    pointer->status = 1;
  }
  
}

void update_stations(ap_list *apl, u_char *bssid, u_char *station, uint16_t channel, const struct pcap_pkthdr h){

  ap_list pointer = NULL;
  int index;

  if ((pointer = get_node(apl, bssid)) != NULL)
    if ((index = get_index(pointer, channel)) != -1)
      add_node(&((*(pointer->chsist + index)).stations), station, h.ts);
       
}
/* </Funzioni di utilita' per list> */


/* <Stampa informazioni> */
void print_beacon(const struct pcap_pkthdr h, char *essid, u_char *bssid,
		  uint16_t channel, int8_t signal){

  struct tm *tm = localtime(&(h.ts.tv_sec));
  
  printf("%d:%d:%d %d out of %d bytes beacon frame %s %u MHz %ddB ",
	 tm->tm_hour, tm->tm_min, tm->tm_sec, h.caplen, h.len, essid, channel, signal);
  print_mac(bssid);
  printf("\n");

}

void print_data(const struct pcap_pkthdr h, u_char *bssid, u_char * station,
		  uint16_t channel, int8_t signal){

  struct tm *tm = localtime(&(h.ts.tv_sec));
  
  printf("%d:%d:%d %d out of %d bytes data frame %u MHz %ddB from station: ",
	 tm->tm_hour, tm->tm_min, tm->tm_sec, h.caplen, h.len, channel, signal);
  print_mac(station);
  printf("to AP: ");
  print_mac(bssid);
  printf("\n");

}
/* </Stampa informazioni>  */

/* Parsing in JSON */
void make_json(ap_list l){

  ap_list temp1 = l;
  list temp2 = NULL;
  int index = 0;
  char bssid[18];
  cJSON *root = cJSON_CreateObject(),
    *ap,
    *chsist,
    *stations;
  char *json_string = NULL;
  
  cJSON_AddStringToObject(root, "name", "Access Points");

  while(temp1 != NULL){
    if(temp1->status == 1){
      ap = cJSON_CreateObject();
      cJSON_AddStringToObject(ap, "essid", temp1->essid);
      make_bssid(temp1->bssid, bssid);
      cJSON_AddStringToObject(ap, "bssid", bssid);
      chsist = cJSON_CreateObject();
      for(index = 0; index < temp1->chsist_index; index++){
	stations = cJSON_CreateObject();
	temp2 = (*(temp1->chsist + index)).stations;
	cJSON_AddNumberToObject(chsist, "channel", (*(temp1->chsist + index)).channel);
	cJSON_AddNumberToObject(chsist, "signal", (*(temp1->chsist + index)).signal);
	while(temp2 != NULL){
	  if (temp2->status == 1){
	    make_bssid(temp2->station, bssid);
	    cJSON_AddStringToObject(stations, "station", bssid);
	  }
	  temp2 = temp2->next;
	}
	cJSON_AddItemToObject(chsist, "stations", stations);	  
      }
      cJSON_AddItemToObject(ap, "info", chsist);
      cJSON_AddItemToObject(root, "ap", ap);
    }
    temp1 = temp1->next;
  }
  json_string = cJSON_Print(root);
  printf("%s\n", json_string);
  free(json_string);
  cJSON_Delete(root);
}
/* Parsing in JSON */
