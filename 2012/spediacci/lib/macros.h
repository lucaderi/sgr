#pragma once

#define IPV4_LEN 4
#define IPV4_HDR_LEN 20
#define UDP_HDR_LEN 8
#define UDP_PROTO 17
#define ETHER_PROTO 1
#define ARP_HDR_LEN 28

#define min(a, b) (a < b ? a : b)

#define STORE(p, v, t) *(t*)(p) = htons(v) ; p += sizeof(t) /* *(t*)p++ = v */
#define STORES(p, v, t) *(t*)(p) = v ; p += sizeof(t) /* *(t*)p++ = v */
#define STOREL(p, v, t) *(t*)(p) = htonl(v) ; p += sizeof(t) /* *(t*)p++ = v */
#define STORE_MC(p, p2, l) memcpy(p, p2, l); p += l
#define STORE_MAC(p, p2) memcpy(p, p2, ETH_ALEN); p += ETH_ALEN
#define STORE_IPV4(p, p2) memcpy(p, p2, IPV4_LEN); p += IPV4_LEN
#define MAC_CMP(p, p2) memcmp(p, p2, ETH_ALEN)
#define IPV4_CMP(p, p2) ((p)->s_addr - (p2)->s_addr)

#define MAC_CPY(dest, src) memcpy(dest, src, ETH_ALEN)




