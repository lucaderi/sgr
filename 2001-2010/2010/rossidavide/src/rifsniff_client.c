/************************************************************************************
 * rifsniff.c                             "Remote InterFace SNIFFer" (Client), v0.1 *
 * (C) 2011  Davide Rossi                                                           *
 *                                                                                  *
 * This program is free software; you can redistribute it and/or                    *
 * modify it under the terms of the GNU General Public License                      *
 * as published by the Free Software Foundation; either version 2                   *
 * of the License, or (at your option) any later version.                           *
 *                                                                                  *
 * This program is distributed in the hope that it will be useful,                  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of                   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                    *
 * GNU General Public License for more details.                                     *
 *                                                                                  *
 * You should have received a copy of the GNU General Public License                *
 * along with this program; if not, write to the Free Software                      *
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.  *
 *                                                                                  *
 *                                                                                  *
 *      Progetto per il corso di "Gestione di Rete" dell' Universita' di Pisa       *
 * Anno Accademico 2009 - 2010                                   Docente: Luca Deri *
 *                                                                                  *
 *                                                                                  *
 * Receives packets sniffed on a remote interface by server application,            *
 * then writes them onto a virtual tun/tap interface on local host.                 *
 * Server application is developed by affiliate student Samuel Panicucci.           *
 ***********************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

/* Minor version on less significant byte, major on third */
#define VERSIONMAGIC 0x66009901
#define VERSION "v0.1"

/* Some space over 1500 bytes, common MTU for ethernet devices */
#define BUFSIZE 1600

/* Macro and variadic macro utilities for errors */
#define PERROR1(x) do { perror(x); close_fds(); exit(EXIT_FAILURE); } while(0)
#define ERROR(x) do { fprintf(stderr, x); exit(EXIT_FAILURE); } while(0)
#define ERROR1(x, args...) do { fprintf(stderr, x, ## args); exit(EXIT_FAILURE); } while(0)

/* Single byte identifying server capabilities */
#define COMMAND_LISTIFS 'L'
#define COMMAND_SNIFF 'S'
/* Server single byte response for successfully initialization */
#define RESPONSE_OK 'O'
/* Server single byte response for recognized errors */
#define BAD_FILTER 'F'
#define BAD_IFACE 'I'

char *progname; /* Program name */

/* File descriptors for socket and virtual interface,
 * globally declared to attempt to close them from
 * inside sig_handle() and close_fds() functions, which
 * are aware of them
 */
int sock_fd = -1, tap_fd = -1; 

/* The standard function to allocate a virtual TUN/TAP interface*/
int tun_alloc(char *, int);

/* An attempt to gracefully close file descriptors on errors */
void close_fds(void) {
  if (sock_fd > -1)
    if (close(sock_fd) < 0)
      perror("Closing connection");
  if (tap_fd > -1)
    if (close(tap_fd) < 0)
      perror("Closing virtual interface");
}

/* Handler function for signals */
void sig_handle(int sig) {
  signal(sig, SIG_IGN);
  char signame[8] = "UNKNOWN";
  
  switch(sig) {
    case SIGHUP:
      strcpy(signame, "SIGHUP");
      break;
    case SIGINT:
      strcpy(signame, "SIGINT");
      break;
    case SIGQUIT:
      strcpy(signame, "SIGQUIT");
      break;
    case SIGTERM:
      strcpy(signame, "SIGTERM");
      break;
    default:
      break;
  }
  
  fprintf(stderr, "\n\nSignal received: [%s]\nShutting down...\n"
	  ,signame);
  
  close_fds();
  exit(EXIT_FAILURE);
}

/* Ensures that we read 'exactly' n bytes, checking for errors */
int read_n(int fd, unsigned char *buf, uint16_t n) {
  int nread, left = n; /* Number of bytes read/left to read from fd */
  
  while(left > 0) {
    if ((nread = read(fd, buf, left)) == 0)
      return 0;
    else if (nread < 0)
      PERROR1("Reading data");     
    else {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

void usage(int code) {
  fprintf(stderr,
	  "Usage: %s -t targetip:port [-i ifname] -I ifname [-f filter] [-s snaplen] [-q]\n"
	  "       %s -t targetip:port -L\n"
	  "  -t ip:port : [mandatory] Remote server address\n"
	  "  -L         : Lists available remote interfaces (if any) and exits\n"
	  "  -I ifname  : [mandatory] Remote interface name\n"
	  "  -i ifname  : Virtual interface name (default: [tap0])\n"
	  "  -f filter  : BPF Filter to attach to remote interface (default: [none])\n"
	  "  -s snaplen : Truncate packet at length (default: [1500] - valid: [29 - %d])\n"
	  "  -q         : Quiet mode (default: [off])\n"
	  "  -h         : Prints this screen and exits\n"
	  "  -v         : Prints program version and exits\n"
	  ,progname, progname, BUFSIZE);
  exit(code);
}

void version(void) {
  fprintf(stderr,
	  "Remote InterFace SNIFFer Client, %s\n"
	  "(C) 2011 Davide Rossi <rossidavide@cli.di.unipi.it>\n"
	  ,VERSION);
//  fprintf(stderr, "\n");
  exit(EXIT_SUCCESS);
//  usage(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
  /* Signal handling initialization */
  signal(SIGINT, sig_handle);
  signal(SIGTERM, sig_handle);
  signal(SIGHUP, sig_handle);
  signal(SIGQUIT, sig_handle);
  
  /* Variables declaration */
  struct sockaddr_in rs; /* Socket address and port */
  short count = 1; /* A counter for the list of interfaces among the server */
  char request_ifs = 0; /* Turns to 1, when -L is specified */
  int option; /* Options on the command line */
  char if_name[IFNAMSIZ+1] = "tap0"; /* Default name for virtual if */
  unsigned char buffer[BUFSIZE+1]; /* Buffer for receiving a single packet */
  uint16_t nread, nwrite, plength; /* Packet length, bytes written/read */
  
  /* Flags for tun/tap configuration
   * IFF_TAP to get a virtual ethernet device
   * IFF_NO_PI to not provide packet information (raw packet only)
   */
  int flags = IFF_TAP | IFF_NO_PI;
  char *p, *ip = NULL; /* Pointers for ip:port line parsing */
  int port; /* Port number converted from command line */
  unsigned char command; /* Command to activate different server function */
  char quiet = 0; /* Be verbose, if not asked to be quiet */
  char *remote_if = NULL; /* Name of remote interface requested */
  uint16_t slen = 1500; /* Default max packet length to capture */
  
  /* Lengths of parameters sent to the server */
  uint16_t rdlen, dlen, flen = 0;
  /* Pointers to string of available devices as stated by the server */
  char *devices, *dev_string;
  char *filter; /* Pcap-filter string to attach to remote interface */
  uint32_t lver, rver; /* Local/remote version numbers */
  unsigned char cres = 0; /* The server will reply something, after our requests */

  progname = argv[0];
  
  /* Command line option parsing */
  while ((option = getopt(argc, argv, "t:i:I:f:s:vhqL")) != -1) {
    switch (option) {
      case 'v':
	version();
	break;
      case 'h':
	usage(EXIT_SUCCESS);
	break;
      case 'q':
	quiet = 1;
	break;
      case 'L':
	request_ifs = 1;
	break;
      case 'I':
	remote_if = optarg;
	break;
      case 'i':
	strncpy(if_name, optarg, IFNAMSIZ);
	break;
      case 'f':
	filter = optarg;
	flen = strlen(filter);
	break;
      case 's':
	slen = atoi(optarg);
	if (slen < 29 || slen > BUFSIZE)
	  ERROR1("Invalid -s argument: [%d]\n", slen);
	break;
      case 't':
	p = memchr(optarg, ':', 16);
	if (!p)
	  ERROR1("Invalid -t argument: [%s]\n", optarg);
	*p = 0;
	ip = optarg;
	port = atoi(p+1);
	if (port < 0)
	  ERROR1("Invalid -t argument: [%s]\n", optarg);
	break;
      default:
	usage(EXIT_FAILURE);
    }
  }
  
  /* These two argoments are mandatory! */
  if (ip == NULL) {
    fprintf(stderr, "error: valid targetip:port required (-t)\n");
    usage(EXIT_FAILURE);
  }
  if (!request_ifs && remote_if == NULL) {
    fprintf(stderr, "error: must specify remote interface name (-I)\n");
    usage(EXIT_FAILURE);
  }
  
  if (!request_ifs) {	/* Brings up virtual interface, we'll need that */
    if ((tap_fd = tun_alloc(if_name, flags)) < 0)
      ERROR1("error: connecting to tun/tap interface %s!\n", if_name);
    printf("... Virtual tun/tap interface bound: [%s]\n", if_name);
  }
  
  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    PERROR1("error: socket()");
  
  /* Initializes socket structure */
  memset(&rs, 0, sizeof(rs));
  rs.sin_family = AF_INET;
  rs.sin_addr.s_addr = inet_addr(ip);
  rs.sin_port = htons(port);
  
  /* Connection request to server */
  if (connect(sock_fd, (struct sockaddr*) &rs, sizeof(rs)) < 0)
    PERROR1("error: connect()");
  
  printf("... Connected to [%s] on port [%d]\n", ip, port);
  
  /* Sends version magic number and reads it back as a response */
  lver = htonl(VERSIONMAGIC);
  if (write(sock_fd, &lver, sizeof(lver)) < 0)
    PERROR1("error: sending version number");
  if (read(sock_fd, &rver, sizeof(rver)) < 0)
    PERROR1("error: receiving version number");
 
  rver = ntohl(rver);
  if (rver == VERSIONMAGIC)	/* Protocol version is the same */
    printf("... Version Ok!  Local:[v%d.%d]   Remote:[v%d.%d]\n",
	   (VERSIONMAGIC >> 16) & 0xff, VERSIONMAGIC & 0xff, (rver >> 16) & 0xff, rver & 0xff);
  else		/* Bad response... maybe wrong version? */
    ERROR1("Version mismatch!  Local:[v%d.%d]   Remote:[v%d.%d]\n",
	   (VERSIONMAGIC >> 16) & 0xff, VERSIONMAGIC & 0xff, (rver >> 16) & 0xff, rver & 0xff);
 
  
  if (request_ifs) {	/* Asks for available interfaces on server side */
    printf("\nRequesting remote interfaces list...\n");
    
    command = COMMAND_LISTIFS;
    
    if (write(sock_fd, (unsigned char *)&command, sizeof(command)) < sizeof(command))
      PERROR1("error: sending remote command [COMMAND_LISTIFS]");
    
    if (read(sock_fd, (unsigned char *)&rdlen, sizeof(rdlen)) != sizeof(rdlen))
      PERROR1("error: retrieving remote interfaces list length");
    
    rdlen = ntohs(rdlen);
    if (rdlen > 0) {
      devices = (char *) malloc(rdlen+1);
      
      if (read(sock_fd, devices, rdlen) != rdlen)
	PERROR1("error: retrieving remote interfaces list");
      
      devices[rdlen]='\0';
      dev_string = strtok(devices, ":");
      do {
	printf("[%d]: %s\n", count, dev_string);
	count++;
      }
      while ((dev_string = strtok(NULL, ":")) != NULL);
    }
    
    exit(EXIT_SUCCESS);	/* Program done */
  }
  else /* We know what interface we want, sniff it! */
    command = COMMAND_SNIFF;
  
  /* Sends 'sniff' command */
  if (write(sock_fd, (unsigned char *)&command, sizeof(command)) < sizeof(command))
    PERROR1("error: sending remote command [COMMAND_SNIFF]");
  
  /* Sends length of target device string, then string itself */
  dlen = strlen(remote_if);
  dlen = htons(dlen);
  printf("Requesting [%s] as target device... ", remote_if);
  
  if (write(sock_fd, (unsigned char *)&dlen, sizeof(dlen)) < sizeof(dlen))
    PERROR1("error: sending 'remote interface' string length");
  
  dlen = ntohs(dlen);
  if (write(sock_fd, (unsigned char *)remote_if, dlen) < dlen)
    PERROR1("error: sending 'Remote interface' string");
  
  printf("Ok!\n");
  
  /* Sends filter string length, then filter string if present */
  flen = htons(flen);
  if (write(sock_fd, (unsigned char *)&flen, sizeof(flen)) < sizeof(flen))
    PERROR1("error: sending 'BPF Filter' string length");
  
  flen = ntohs(flen);
  if (flen > 0) { /* BPF Filter is not empty, sends it */
    printf("Requesting BPF Filter [%s]... ", filter);
    if (write(sock_fd, (unsigned char *)filter, flen) < flen)
      PERROR1("error: sending 'BPF Filter' string");
    
    printf("Ok!\n");
  }
  
  /* Sends max packet size (snaplen) value */
  printf("Requesting max packet size [%d]... ", slen);
  slen = htons(slen);
  if (write(sock_fd, (unsigned char *)&slen, sizeof(slen)) < sizeof(slen)) {
    close(sock_fd);
    close(tap_fd);
    PERROR1("error: sending 'SnapLen' value");
  }
  
  printf("Ok!\n");
  
  /* If everything wents OK, the server will reply with byte RESPONSE_OK */
  
  if (read(sock_fd, &cres, sizeof(cres)) < sizeof(cres)) {
    close(sock_fd);
    close(tap_fd);
    PERROR1("error: reading server response");
  }
  
  if (cres != RESPONSE_OK) {	/* Bad response, something went wrong */
    close_fds();
    
    switch (cres) {
      case BAD_FILTER:
	ERROR1("\nFilter syntax is wrong, please check. [%s]\n\nExiting.\n", filter);
	break;
      case BAD_IFACE:
	ERROR1("\nRemote interface is wrong, please check. [%s]\n\nExiting.\n", remote_if);
	break;
      default :
	ERROR1("\nSomething weird happened (Unknown response [%d])\n\nExiting.\n", cres);
    }
  }
  
  printf("\n... Beginning communication ...\n\n");

  while(1) { /* MAIN LOOP: receiving packets till user/server interruction */

    if(read(sock_fd, (unsigned char *)&plength, sizeof(plength)) == 0) {
      /* End of stream, perhaps server closed connection? */
      printf("\n\nOther end closed connection... ");
      close(sock_fd);
      close(tap_fd);
      printf("Exiting.\n");
      exit(EXIT_SUCCESS);	/* Exit normally */
    }

    /* ## my_note: should i check for zero even here? ## */
    nread = read_n(sock_fd, buffer, ntohs(plength));
    
    /* Got a packet from the network, write it on virtual if */
    if((nwrite = write(tap_fd, buffer, nread)) < 0)
      PERROR1("error: writing data");
    
    /* Shows a message for every packet wrote on virtual if */
    if (!quiet)
      printf("Packet received! [%4d] bytes wrote on [%s]\n\r", nwrite, if_name);
  }
  
  return(0);
}

/* Opens and set up a virtual tun/tap interface
 * (mostly copied from tun/tap interface documentation)
 */
int tun_alloc(char *dev, int flags) {
  struct ifreq ifr;
  int fd, err;
  
  if( (fd = open("/dev/net/tun" , O_RDWR)) < 0 ) {
    perror("error: opening /dev/net/tun");
    return fd;
  }
  
  memset(&ifr, 0, sizeof(ifr));
  
  ifr.ifr_flags = flags;
  
  if (*dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  
  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("error: ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }
  
  strcpy(dev, ifr.ifr_name);
  
  return fd;
}
