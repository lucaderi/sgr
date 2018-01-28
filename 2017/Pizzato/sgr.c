#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h>

#define REQUEST_NUMBER 0 //Number of packet to be captured

//Contains the dns header
struct dnshdr{
	unsigned short id; // identification number
	unsigned char rd :1;
	unsigned char tc :1;
	unsigned char aa :1;
	unsigned char opcode :4;
	unsigned char qr :1; // query/response flag
	unsigned char rcode :4; // response code
	unsigned char cd :1;
	unsigned char ad :1;
	unsigned char z :1;
	unsigned char ra :1;
	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count;
	unsigned short add_count;
};

//Contains a request
struct request {
	unsigned short id;
	unsigned int good; //If had a valid answer
	unsigned int portClient;
	unsigned int portServer;
	long long int sendTime;
	long long int responseTime;
	struct request* next;
};

//Contains the dns
struct dns {
	char ip[16];
	unsigned int requestNumber;
	struct request *requestList; //Request made to this dns
	struct dns *next;
};

//Contains the client
struct client {
	char ip[16];
	unsigned int requestNumber;
	struct dns *dnsList; //list of dns contacted
	struct client *next;
};

//Function to handle captured packet
void packet_handler(
    u_char *args,
    const struct pcap_pkthdr* header,
    const u_char* packet
);

/* When a request is captured, it's added with these three functions
 * addData() handle the client section
 * addDns() handle the dns section
 * addRequest() handle the request section
 */
void addData(
	const struct pcap_pkthdr* pktHeader,
	struct iphdr *ipHeader,
	struct dnshdr *dnsHeader
);

struct dns * addDns(
	struct dns *dnsList,
	const struct pcap_pkthdr* pktHeader,
	struct iphdr *ipHeader,
	struct dnshdr *dnsHeader
);

struct request * addRequest(
	struct request *requestList,
	const struct pcap_pkthdr* pktHeader,
	struct iphdr *ipHeader,
	struct dnshdr *dnsHeader
);

//When is captured a response this function is called to handle it
void addResponse(
	const struct pcap_pkthdr* pktHeader,
	struct iphdr *ipHeader,
	struct dnshdr *dnsHeader
);

void printList();

//Main structure with all the data
struct client *root = NULL;

int main(int argc, char **argv) {
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device = (char *)calloc(1, 100);
    int snapshot_len = 1028;
    int promiscuous = 0;
    int timeout = 1000;
    struct bpf_program filter;
    char filter_exp[] = "port 53"; //Filter only this (common port for dns)
    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
    int lookup_return_code;

    int i = 0;

    while (i < argc) {
    	if (strcmp(argv[i], "-h") == 0) {
    		printf("sgr help (read makefile or):\n");
    		printf("  -h             : help\n");
    		printf("  -i [Interf] : start capturing at interface Interf\n");
    		return 0;
    	}

    	if (strcmp(argv[i], "-i") == 0) {
    		i = i + 1;
    		if (i < argc) {
    			strcpy(device, argv[i]);
    		}
    		else {
    			printf("Device not specified\n");
    		}
    		break;
    	}
    	i++;
    }

    if (strcmp(device, "") == 0) {
    	printf("Using first available device\n");
    	//Take 'standard' device
	    device = pcap_lookupdev(error_buffer);
	    if (device == NULL) {
	    	printf("Error: %s\n", error_buffer);
	    	return 1;
	    }
    }

    printf("Device: %s\n", device);

    //Get device information
    lookup_return_code = pcap_lookupnet(
        device,
        &ip_raw,
        &subnet_mask_raw,
        error_buffer
    );
    if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;
    }

    //Open the 'flow'
    handle = pcap_open_live(device, snapshot_len, promiscuous, timeout, error_buffer);
    if (handle == NULL) {
    	printf("Error: %s\n", error_buffer);
    	return 1;
    }

    //Apply filter
    if (pcap_compile(handle, &filter, filter_exp, 0, ip_raw) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    //Capture and handle REQUEST_NUMBER packet
    pcap_loop(handle, REQUEST_NUMBER, packet_handler, NULL);
    pcap_close(handle);
    printf("Bye bye\n");
    return 0;
}

void packet_handler(
    u_char *args,
    const struct pcap_pkthdr* header,
    const u_char* packet
) {
		struct sockaddr_in source, dest;
    struct ether_header *eth_header;
    struct iphdr *ipHeader;
    struct dnshdr *dnsHeader;

    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    ipHeader = (struct iphdr *) (packet + 14);
    dnsHeader = (struct dnshdr *)(packet + 14 + (ipHeader->ihl * 4) + 8);

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ipHeader->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ipHeader->daddr;

    if (!!(dnsHeader->qr)) {
    	addResponse(header, ipHeader, dnsHeader);
    }
    else {
    	addData(header, ipHeader, dnsHeader);
    }

    printList();
}

void addData(const struct pcap_pkthdr* pktHeader, struct iphdr *ipHeader, struct dnshdr *dnsHeader) {
	struct client *newClient = NULL;
	struct sockaddr_in sourceIp;

	memset(&sourceIp, 0, sizeof(sourceIp));
	sourceIp.sin_addr.s_addr = ipHeader->saddr;

	if (root == NULL) {
		newClient = (struct client *)calloc(1, sizeof(struct client));
		memset(newClient->ip, '\0', sizeof(newClient->ip));
		strcpy(newClient->ip, inet_ntoa(sourceIp.sin_addr));
		newClient->requestNumber = 1;
		newClient->dnsList = NULL;
		newClient->next = NULL;

		newClient->dnsList = addDns(newClient->dnsList, pktHeader, ipHeader, dnsHeader);

		root = newClient;
	}
	else {
		struct client *curr = root;

		while (curr != NULL &&
			strcmp(curr->ip, inet_ntoa(sourceIp.sin_addr)) != 0) {
			curr = curr->next;
		}

		if (curr == NULL) {
			newClient = (struct client *)calloc(1, sizeof(struct client));
			memset(newClient->ip, '\0', 16);
			strcpy(newClient->ip, inet_ntoa(sourceIp.sin_addr));
			newClient->requestNumber = 1;
			newClient->dnsList = NULL;
			newClient->next = root;

			newClient->dnsList = addDns(newClient->dnsList, pktHeader, ipHeader, dnsHeader);
			root = newClient;
		}
		else {
			curr->requestNumber = curr->requestNumber + 1;
			curr->dnsList = addDns(curr->dnsList, pktHeader, ipHeader, dnsHeader);
		}
	}
}

struct dns * addDns(struct dns *dnsList, const struct pcap_pkthdr* pktHeader, struct iphdr *ipHeader, struct dnshdr *dnsHeader) {
	struct dns *newDns = dnsList;
	struct sockaddr_in destIp;

	memset(&destIp, 0, sizeof(destIp));
	destIp.sin_addr.s_addr = ipHeader->daddr;

	while (newDns != NULL && strcmp(newDns->ip, inet_ntoa(destIp.sin_addr)) != 0) {
		newDns = newDns->next;
	}

	if (newDns == NULL) {
		newDns = (struct dns *)calloc(1, sizeof(struct dns));
		memset(newDns->ip, '\0', 16);
		strcpy(newDns->ip, inet_ntoa(destIp.sin_addr));
		newDns->requestNumber = 1;
		newDns->requestList = NULL;
		newDns->next = dnsList;

		newDns->requestList = addRequest(newDns->requestList, pktHeader, ipHeader, dnsHeader);

		return newDns;
	}
	else {
		newDns->requestNumber = newDns->requestNumber + 1;
		newDns->requestList = addRequest(newDns->requestList, pktHeader, ipHeader, dnsHeader);

		return dnsList;
	}
}

struct request * addRequest(struct request *requestList, const struct pcap_pkthdr* pktHeader, struct iphdr *ipHeader, struct dnshdr *dnsHeader) {
	struct request *newRequest = NULL;

	newRequest = (struct request *)calloc(1, sizeof(struct request));
	newRequest->id = dnsHeader->id;
	newRequest->sendTime = ((long long int) pktHeader->ts.tv_sec) * 1000000ll + 
						(long long int) pktHeader->ts.tv_usec;
	newRequest->good = 0;
	newRequest->responseTime = 0;
	newRequest->next = requestList;
	return newRequest;
}

void addResponse(const struct pcap_pkthdr* pktHeader, struct iphdr *ipHeader,	struct dnshdr *dnsHeader) {
	struct client *tmp = root;
	struct dns *dns;
	struct request *req;
	struct sockaddr_in ip;

	memset(&ip, 0, sizeof(ip));
	ip.sin_addr.s_addr = ipHeader->daddr;

	while (tmp != NULL && strcmp(tmp->ip, inet_ntoa(ip.sin_addr))) {
		tmp = tmp->next;
	}

	if (tmp == NULL) {
		printf("Unknown response\n");
	}
	else {
		dns = tmp->dnsList;

		memset(&ip, 0, sizeof(ip));
		ip.sin_addr.s_addr = ipHeader->saddr;

		while (dns != NULL && strcmp(dns->ip, inet_ntoa(ip.sin_addr))) {
			dns = dns->next;
		}

		if (dns == NULL) {
			printf("Unknown response\n");
		}
		else {
			req = dns->requestList;

			while (req != NULL && req->id != dnsHeader->id) {
				req = req->next;
			}

			if (req == NULL) {
				printf("Unkown response\n");
			}
			else {
				req->responseTime = ((long long int) pktHeader->ts.tv_sec) * 1000000ll + 
							(long long int) pktHeader->ts.tv_usec;
				if (ntohs(dnsHeader->ans_count) != 0 && ntohs(dnsHeader->rcode) == 0) {
					req->good = 1;
				}
			}
		}
	}
}

void printList() {
	FILE *output = NULL;
	struct client *tmp = root;
	struct dns *tmpD = NULL;
	struct request *tmpR = NULL;
	long long int minC, minD, maxC, maxD, totC, totD;
	int res, goodRes, totRes, totGoodRes, dns;

	int i = 0;
	output = fopen("results.txt", "w");

	if (output == NULL) {
		printf("Error saving data\n");
		return;
	}

	fprintf(output, "\n----------PRINTING----------\n\n");
	while (tmp != NULL) {
		fprintf(output, "Client   : %s\n", tmp->ip);
		fprintf(output, "Requests : %d\n", tmp->requestNumber);
		tmpD = tmp->dnsList;
		minC = tmpD->requestList->sendTime;
		maxC = 0;
		totC = 0;
		totRes = 0;
		totGoodRes = 0;
		dns = 0;

		while (tmpD != NULL) {
			minD = tmpD->requestList->sendTime;
			maxD = 0;
			totD = 0;
			res = 0;
			goodRes = 0;

			fprintf(output, "  Server DNS: %s\n", tmpD->ip);

			tmpR = tmpD->requestList;

			while (tmpR != NULL) {
				fprintf(output, "    Request id     : %d\n", tmpR->id);

				if (tmpR->responseTime != 0) {
					if (tmpR->responseTime - tmpR->sendTime > maxD) {
						maxD = tmpR->responseTime - tmpR->sendTime;
					}
					if (tmpR->responseTime - tmpR->sendTime < minD) {
						minD = tmpR->responseTime - tmpR->sendTime;
					}

					totD = totD + tmpR->responseTime - tmpR->sendTime;

					if (tmpR->good == 0) {
						fprintf(output, "    --- Answer not good in %lld usec\n", tmpR->responseTime - tmpR->sendTime);
					}
					else {
						fprintf(output, "    --- Answer good in %lld usec\n", tmpR->responseTime - tmpR->sendTime);
						goodRes++;
					}
					res++;
				}
				else {
					fprintf(output, "    --- Not responded\n");
				}

				tmpR = tmpR->next;
			}

			fprintf(output, "\n  DNS stats: \n");
			fprintf(output, "   - Requests              : %d\n", tmpD->requestNumber);
			fprintf(output, "   - Responses             : %d\n", res);
			fprintf(output, "   - Useful responses      : %d\n", goodRes);
			fprintf(output, "   - Not useful responses  : %d\n", res - goodRes);
			fprintf(output, "   - Queries not responded : %d\n", tmpD->requestNumber - res);
			fprintf(output, "   - Min response-time     : %lld usec\n", minD);
			fprintf(output, "   - Max response-time     : %lld usec\n", totD/tmpD->requestNumber);
			fprintf(output, "   - Avg response-time     : %lld usec\n", maxD);
			tmpD = tmpD->next;

			if (minD < minC) {
				minC = minD;
			}
			if (maxD > maxC) {
				maxC = maxD;
			}
			totC = totC + totD;
			totRes = totRes + res;
			totGoodRes = totGoodRes + goodRes;
			dns++;
		}

		fprintf(output, "\nClient stats: \n");
		fprintf(output, " - Servers DNS used      : %d\n", dns);
		fprintf(output, " - Requests              : %d\n", tmp->requestNumber);
		fprintf(output, " - Response              : %d\n", totRes);
		fprintf(output, " - Useful responses      : %d\n", totGoodRes);
		fprintf(output, " - Not useful responses  : %d\n", totRes - totGoodRes);
		fprintf(output, " - Queries not responded : %d\n", tmp->requestNumber - totRes);
		fprintf(output, " - Min response-time     : %lld usec\n", minC);
		fprintf(output, " - Max response-time     : %lld usec\n", totC/tmp->requestNumber);
		fprintf(output, " - Avg response-time     : %lld usec\n", maxC);
		tmp = tmp->next;
		i++;
	}

	fclose(output);
}