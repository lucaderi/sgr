#define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define ETHERTYPE_ARP           0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_REVARP        0x8035  /* reverse Addr. resolution protocol */
#define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPV6          0x86dd  /* IPv6 */
#define ETHERTYPE_LOOPBACK      0x9000  /* used to test interfaces */

struct ether_header {
  jbyte ether_dest[6],ether_src[6];
  jchar ether_type;
};
