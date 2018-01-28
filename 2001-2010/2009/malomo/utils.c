#include "utils.h"
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <string.h>
#include <pcap.h>
#include <pwd.h>

#ifdef linux
#include <pthread.h>
#endif

int get_mac_addr(char *dev_name , u_char *mac)
{
	
#ifdef linux
	struct ifreq ifr;
	
    int sock;
    int ok = 0;
	
	if (!dev_name || !mac)
		return -1;
	
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
		perror("socket");
		return -1;
    }
	strcpy(ifr.ifr_name, dev_name);	
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
		if (! (ifr.ifr_flags & IFF_LOOPBACK))
			if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
				ok = TRUE;
	
    if (close(sock) == EINTR)
		close(sock);
	
    if (ok)
	{
        bcopy(ifr.ifr_hwaddr.sa_data, mac, 6);
		return 0;
    }
#endif
	
#ifdef __APPLE__
	struct ifaddrs *ifap, *ifa;
	int ok=0;
	
	if (!dev_name || !mac)
		return -1;
	
	if (getifaddrs(&ifap) == -1)
	{
		perror("getifaddrs");
		return -1;
	}
	
	if (ifap == NULL)
		return -1;
	
	for (ifa = ifap; ifa != NULL && !ok; ifa = ifa->ifa_next)
	{
		if (!strcmp(ifa->ifa_name, dev_name) && ifa->ifa_addr->sa_family == AF_LINK)
		{
			bcopy(LLADDR((struct sockaddr_dl *)ifa->ifa_addr), mac, 6);
			ok = TRUE;
		}
	}
	freeifaddrs(ifap);
	
	if (ok) return 0;
#endif
	return -1;
}

int datalinktooffset(int dl_id)
{
	int header_len;
	switch(dl_id)
	{
		case DLT_LOOP:
		case DLT_NULL:
		case DLT_PPP: header_len=4; break;
		case DLT_LINUX_SLL: header_len=16; break;
		case DLT_EN10MB: header_len=sizeof(struct ether_header); break;
		case DLT_IEEE802: header_len=22; break;
		case DLT_IEEE802_11: header_len=32; break;
		case DLT_RAW: header_len=0; break;
		default: header_len=-1; break;
	}
	return header_len;
}

/* Sets user to nobody in case current user is root */
void changeUser() {
	struct passwd *pw = NULL;
	
	if(getuid() == 0)
	{
		/* We're root */
		char *user;
		
		pw = getpwnam(user = "nobody");
		
		if(pw != NULL) 
		{
			if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0))
				printf("Unable to change user to %s [%d: %d]: sticking with root\n", user, pw->pw_uid, pw->pw_gid);
			else
				printf("Program changed user to %s\n", user);
		}
	}
}


char buffer[BUFLEN];

/*
 Return a human-readable string from a struct sockaddr containing
 ipv6 or ipv4 address
 */
static char* getStringFromSockAddr(struct sockaddr* addr)
{
	int offset;
	switch (addr->sa_family)
	{
		case AF_INET : offset = 2; break;
		case AF_INET6 : offset = 6; break;
#ifdef __APPLE__
		case AF_LINK : 
		{
			u_char* mac = (u_char *)LLADDR((struct sockaddr_dl *)addr);
			strncpy(buffer, ether_ntoa((struct ether_addr*) mac), BUFLEN);
			/*sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x\n",
				   (int)mac[0],
				   (int)mac[1],
				   (int)mac[2],
				   (int)mac[3],
				   (int)mac[4],
				   (int)mac[5]);*/
			return buffer;
		}
#endif
		default : offset = 0;
	}
	
	return (char*)inet_ntop(addr->sa_family,
							((char*)&(addr->sa_data))+offset,
							(char*)&buffer,
							BUFLEN);
}

char *separator = "------------------------------";

char* selectInterface(int verbose)
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *devices_list;
	pcap_if_t *device;
	int ixNo, select;
	
	/* List all interfaces */
	if (pcap_findalldevs(&devices_list, errbuf))
	{
		fprintf(stderr, "Unable to list devices: %s\n", errbuf);
		return NULL;
	}
	
	device = devices_list;
	ixNo = 0;
	
	while (device)
	{
		pcap_addr_t *addr;
		if (verbose)
			printf("%s%s\n", separator, separator);
		printf(" %-2d: %s ", ixNo++, device->name);
		if (device->description)
			printf("%s\n", device->description);
		if (device->flags & PCAP_IF_LOOPBACK)
			printf("(loopback interface)");
		
		printf("\n\n");
		if (verbose)
		{
			addr = device->addresses;
			while (addr)
			{
				sa_family_t fam = addr->addr->sa_family;
				if ( fam == AF_INET || fam == AF_INET6 )
				{
					char* dotquad = getStringFromSockAddr(addr->addr);
					
					switch (fam)
					{
						case AF_INET : printf("ipv4"); break;
						case AF_INET6 : printf("ipv6"); break;
					}
					
					printf(" Address: %s\n", dotquad);
					
					if (addr->netmask)
					{
						dotquad = getStringFromSockAddr(addr->netmask);
						printf("     Mask: %s\n", dotquad);
					}
					
					if (addr->broadaddr)
					{
						dotquad = getStringFromSockAddr(addr->broadaddr);
						printf("     Bcast: %s\n", dotquad);
					}
				}
				addr = addr->next;
			}
		}
		device = device->next;
	}
	
	/* No devices found */
	if (!ixNo)
	{
		printf("No available devices!\n");
		return NULL;
	}
	else if (verbose)
		printf("%s%s\n", separator, separator);
    
	printf("\n");
    
	/* Let the user choose an interface */
	select = -1;
	do
	{
		printf("Choose an interface (0-%d): ", ixNo-1);
		fflush(stdout);
		scanf("%d", &select);
		scanf("%*[^\n]");
	}
	while ( select < 0 || select >= ixNo );
	
	/* Get the device struct */
	device = devices_list;
	while (select)
	{
		device = device->next;
		select--;
	}
	
	/* Save choosen interface name */
	MALLOC(dev, strlen(device->name)+1, NULL);
	strcpy(dev, device->name);
	
	/* Free devices list */
	pcap_freealldevs(devices_list);
	
	return dev;
}

/* Spin lock implementation */
#ifdef __APPLE__
int create_spinlock(spinlock_t * lock)
{
	if (!lock)
		return -1;
	*lock = 0;
	return 0;
}

int destroy_spinlock(spinlock_t * lock)
{
	if (!lock)
		return -1;
	return 0;
}
#endif

#ifdef linux
int create_spinlock(spinlock_t * lock)
{
	return pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE);
}

int destroy_spinlock(spinlock_t * lock)
{
	return pthread_spin_destroy(lock);
}
#endif
