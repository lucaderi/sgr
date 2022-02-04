/* File contenente le definizioni di strutture dati */

/* Ethernet frame messaggi ARP */ 
typedef struct eth_pkt { 
  struct ether_header ethdr;    /* Ethernet Header            */
  u_int16_t htype;              /* Tipo Hardware              */ 
  u_int16_t ptype;              /* Protocollo                 */ 
  u_char hlen;                  /* Lunghezza indirizzo MAC    */ 
  u_char plen;                  /* Lunghezza indirizzo IP     */ 
  u_int16_t oper;               /* Codice operazione          */ 
  u_char sha[6];                /* Indirizzo MAC mittente     */ 
  u_char spa[4];                /* Indirizzo IP mittente      */ 
  u_char tha[6];                /* Indirizzo MAC destinatario */ 
  u_char tpa[4];                /* Indirizzo IP destinatario  */ 
}eth_pkt_t;


/* Elemento hashmap */
typedef struct hash_node {
  u_char sha[6];    /* Indirizzo MAC mittente */ 
  u_char spa[4];    /* Indirizzo IP mittente  */
  int lastUsed;     /* Flag di presenza       */
}hash_node_t;


/* Struttura statistiche rete */
typedef struct net_stats {
  int len;      /* Numero di utenti globale */
  int online;   /* Numero di utenti online  */
}net_stats_t;
