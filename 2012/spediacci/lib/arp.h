#pragma once

#include "includes.h"

extern int arp_init(PfSocket *skt);
extern int arp_kill(PfSocket *skt);
extern int arp_get(struct ether_addr *mac, struct in_addr addr, DnaSocket *skt);
extern int arp_put(struct ether_addr mac, struct in_addr ip, int unlock, PfSocket *skt);
extern void arp_send_signals(PfSocket *skt);

extern int send_arp_req(struct in_addr dest_addr, PfSocket *skt);
extern int send_arp_reply(struct in_addr ip_dest, struct ether_addr dest_mac, PfSocket *skt);

extern struct ether_addr mac_broadcast;
extern struct ether_addr mac_null;
