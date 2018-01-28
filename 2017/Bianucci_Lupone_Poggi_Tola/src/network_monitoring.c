#include "network_monitoring.h"

#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sched.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/poll.h>

#include <pcap/pcap.h>

/* ******************************* */
/* LOCAL Global var                */
static char hex[] = "0123456789ABCDEF";
static int err;
static int ThreadExitStatus = 0;
static FILE *f = NULL;

int verbose = 0;
unsigned char request_terminate_process = 0;

/* ******************************* */
/* LOCAL Global func               */
static void Exit_cleanup(void);
int main(int argc, char *args[]);

/* ********************************************************* */
static void Exit_cleanup(void)
{
  if (request_terminate_process)
    return;

  request_terminate_process = 1;
  fprintf(stderr, "network_monitoring CLEANUP_EXECUTE...  END_process...\n");

  if (f != NULL)
    fclose(f);

  if (fp != NULL)
    pclose(fp);

  /*send request terminate thread before exit*/
  if ((err = pthread_join(tdem, (void *)&ThreadExitStatus)) != 0)
  {
    fprintf(stderr, "ERROR join thread DEMON: %d \n", ThreadExitStatus);
  }
  if ((err = pthread_join(tscan, (void *)&ThreadExitStatus)) != 0)
  {
    fprintf(stderr, "ERROR join thread Interface: %d \n", ThreadExitStatus);
  }
  if ((err = pthread_join(tput, (void *)&ThreadExitStatus)) != 0)
  {
    fprintf(stderr, "ERROR join thread put: %d \n", ThreadExitStatus);
  }

  delete_ports();
}

//***********************************
char *etheraddr_string(const u_char *ep, char *buf)
{
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for (i = 5; (int)--i >= 0;)
  {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

char *proto2str(u_short proto)
{
  static char protoName[8];

  switch (proto)
  {
  case IPPROTO_TCP:
    return ("TCP");
  case IPPROTO_UDP:
    return ("UDP");
  case IPPROTO_ICMP:
    return ("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return (protoName);
  }
}

char *_intoa(unsigned int addr, char *buf, u_short bufLen)
{
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do
  {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0)
    {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
        *--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char *)(cp + 1);

  return (retStr);
}

char *intoa(unsigned int addr)
{
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return (_intoa(addr, buf, sizeof(buf)));
}

/*************************************** */
/*
 * The time difference in microseconds
 */
long delta_time(struct timeval *now,
                struct timeval *before)
{
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds = now->tv_sec - before->tv_sec;
  delta_microseconds = now->tv_usec - before->tv_usec;

  if (delta_microseconds < 0)
  {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000; /* 1e6 */
    --delta_seconds;
  }
  return ((delta_seconds * 1000000) + delta_microseconds);
}

/* *************************************************** 
*	Restituisce l'indirizzo ip dell'interfaccia passata come parametro
*/
char *get_inter_ip(char *inter)
{
  char buf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs, *device;
  if (inter == NULL)
    return NULL;
  if (pcap_findalldevs(&alldevs, buf))
    return NULL;
  device = alldevs;
  while (device)
  {
    if (!strcmp(device->name, inter))
    {
      pcap_addr_t *addr;
      for (addr = device->addresses; addr != NULL; addr = addr->next)
      {
        if (addr->addr->sa_family == AF_INET)
        {
          return (char *)inet_ntoa(((struct sockaddr_in *)addr->addr)->sin_addr);
        }
      }
    }
    device = device->next;
  }
  return NULL;
}

void pkt_handler(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p)
{
  struct ether_header ehdr;
  u_short eth_type;
  struct ip ip;

  static arrQueueElem_t elem;

#ifdef DEBUG_BLOCK_ON
  char buf1[32], buf2[32];
#endif

  int ps = 0, pd = 0, ipLen = 0;
  int ipHl = 0, tcpHl = 0;

  // if (contPktRx >= 1000) return;
  contPktRx++;

#ifdef DEBUG_BLOCK_ON
  printf("[caplen=%u][len=%u]\n", h->caplen, h->len);
#endif

  memcpy(&ehdr, p, sizeof(struct ether_header));
  eth_type = ntohs(ehdr.ether_type);

#ifdef DEBUG_BLOCK_ON
  printf("[%s -> %s] ",
         etheraddr_string(ehdr.ether_shost, buf1),
         etheraddr_string(ehdr.ether_dhost, buf2));
#endif
  if (eth_type == 0x0800)
  {
    memcpy(&ip, p + sizeof(ehdr), sizeof(struct ip));
    if (strcmp(intoa(ntohl(ip.ip_src.s_addr)), myIp) == 0)
    {
      elem.direction = 1; //out
    }
    else
      elem.direction = 0;
    elem.Protocol = ip.ip_p;

#ifdef DEBUG_BLOCK_ON
    printf("[%s]", proto2str(ip.ip_p));
    printf("[%s ", intoa(ntohl(ip.ip_src.s_addr)));
    printf("-> %s]\n", intoa(ntohl(ip.ip_dst.s_addr)));
#endif

    ipHl = ((uint8_t) * (p + 14)) & 0x000F;
    ipLen = ((uint8_t) * (p + 16)) * 256 + (uint8_t) * (p + 17);
    ps = ((uint8_t) * (p + 14 + (ipHl * 4))) * 256 + (uint8_t) * (p + 15 + (ipHl * 4));
    pd = ((uint8_t) * (p + 16 + (ipHl * 4))) * 256 + (uint8_t) * (p + 17 + (ipHl * 4));

#ifdef DEBUG_BLOCK_ON
    printf("ps:%d pd:%d ipHl:%d ipLen: %d\n", ps, pd, ipHl, ipLen);
#endif

    if (elem.direction == 1)
      elem.Port = ps;
    else
      elem.Port = pd;
    if (ip.ip_p == IPPROTO_TCP) //tcp
    {
      elem.byteLen = ipLen - (ipHl * 4) - (tcpHl * 4);
    }
    else if (ip.ip_p == IPPROTO_UDP) //udp
    {
      elem.byteLen = ipLen - (ipHl * 4) - 8;
    }
    else
    {
      contUnricognizable++;
      return;
    }
    if (!putArrQueueElem(&queuePkt, &elem))
      contUnricognizable++;
  }
  else
  {
    contUnricognizable++;
  }
}

//***************************************   MAIN BLOCK  ********************************************
int main(int argc, char *args[])
{

  char errbuf[PCAP_ERRBUF_SIZE];
  char pidmax[10];

  fp = NULL;
  if ((f = fopen("/proc/sys/kernel/pid_max", "r")) == NULL)
    pid_max = 65535 / 2;
  else
  {
    if (fgets(pidmax, 10, f) == NULL)
    {
      exit(ERRORFILE);
    }
    fclose(f);
    f = NULL;
  }

  //printf("File caricato\n");
  if (sscanf(pidmax, "%d", &pid_max) == 0)
  {
    perror("error sscanf pidmax");
    exit(ERRORFILE);
  }
  //printf("scanf ok\n");
  process_list = (process_t *)malloc(pid_max * sizeof(process_t));
  if (process_list == NULL)
  {
    perror("error malloc process_list");
    exit(ERRORMEMORY);
  }

  queueMiss.headID = 0;
  queueMiss.tailID = 0;
  queuePkt.headID = 0;
  queuePkt.tailID = 0;

  if (argc > 1)
  {
    device = args[1];
  }
  else
  {
    fprintf(stderr, "Parameter invalid or not found: network device");
    exit(ERRINPUTPARAM);
  }
  //printf("device ok\n");
  if ((myIp = get_inter_ip(device)) == NULL)
  {
    fprintf(stderr, "Error get_inter_ip func or network not connect!");
    exit(ERRDEVICE);
  }
  //printf("Ip ok\n");

  //*** installing cleanup
  ec_meno1(atexit(Exit_cleanup), "installing cleanup func...");
  myPortScanIsUpdate = 0;
  portScanIsUpdate = 1;
  myDeadProcIsUpdate = 0;
  deadProcIsUpdate = 1;
  //*** open tables udp & tcp ports/pid
  update_ports();

  printf("Capturing from %s\n", device);
  int promisc = 1;
  int snaplen = 128;
  pktFullPcap = 0;
  contUnricognizable = 0;

  if ((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL)
  {
    printf("pcap_open_live: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  //*** thread start...
  if ((err = pthread_create(&tdem, NULL, &ThreadDemon, NULL) != 0))
  {
    perror("Error ThreadDemon build");
  }
  if ((err = pthread_create(&tscan, NULL, &ThreadScan, NULL) != 0))
  {
    perror("Error Thread scan  build");
  }
  if ((err = pthread_create(&tput, NULL, &ThreadPut, NULL) != 0))
  {
    perror("Error Thread put  build");
  }

  pcap_loop(pd, -1, pkt_handler, NULL);
  pcap_close(pd);

  /*send request terminate thread before exit*/
  if ((err = pthread_join(tdem, (void *)&ThreadExitStatus)) != 0)
  {
    fprintf(stderr, "ERROR join thread DEMON: %d \n", ThreadExitStatus);
  }
  if ((err = pthread_join(tscan, (void *)&ThreadExitStatus)) != 0)
  {
    fprintf(stderr, "ERROR join thread scan: %d \n", ThreadExitStatus);
  }
  if ((err = pthread_join(tput, (void *)&ThreadExitStatus)) != 0)
  {
    fprintf(stderr, "ERROR join thread put: %d \n", ThreadExitStatus);
  }

  delete_ports();

  exit(EXIT_SUCCESS);
}
