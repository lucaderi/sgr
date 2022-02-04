/*
 * support.h
 * 
 * Progetto gestione di reti 2015/2016
 *
 * Realizzato da Francesco Ligorio  
 *
 */


#define MAX_ESSID_LENGTH 32
#define CHANNEL_NUMBER 13

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
  struct timeval tv;
  struct _ap_node *next;
} ap_node;

typedef ap_node *ap_list;

ap_list new_ap_list();
void update_ap(ap_list *apl, char *essid, u_char *bssid, uint16_t channel,
	       int8_t signal, const struct pcap_pkthdr h);
void update_stations(ap_list *apl, u_char *bssid, u_char *station, uint16_t channel,
		     const struct pcap_pkthdr h);
void print_beacon(const struct pcap_pkthdr h, char *essid, u_char *bssid,
		  uint16_t channel, int8_t signal);
void print_data(const struct pcap_pkthdr h, u_char *bssid, u_char * station,
		uint16_t channel, int8_t signal);
void make_json(ap_list l);
void clean(ap_list *apl, double timeout, int verbose);
void free_aps(ap_list *apl);


