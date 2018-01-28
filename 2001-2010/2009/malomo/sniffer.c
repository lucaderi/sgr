#include "sniffer.h"

/* PROCESSING FUNCTIONS */
void process_tcp(u_char *ptr)
{
	stats->tcp++;
	stats->tcp_bytes += p_size;
	/* Print tcp infos */
#ifdef DEBUG
		printf("Type: TCP\n");
		printf("Src Port: %d\n", ntohs(*(u_short*)ptr));
		printf("Dst Port: %d\n", ntohs(*((u_short*)ptr + 1)));
#endif
	if (flow)
	{
		pdecode.src_port = ntohs(*(u_short*)ptr);
		pdecode.dst_port = ntohs(*((u_short*)ptr + 1));
	}
}

void process_udp(u_char *ptr)
{
	stats->udp++;
	stats->udp_bytes += p_size;
	
	/* Print udp infos */
#ifdef DEBUG
		printf("Type: UDP\n");
		printf("Src Port: %d\n", ntohs(*(u_short*)ptr));
		printf("Dst Port: %d\n", ntohs(*((u_short*)ptr + 1)));
#endif
	if (flow)
	{
		pdecode.src_port = ntohs(*(u_short*)ptr);
		pdecode.dst_port = ntohs(*((u_short*)ptr + 1));
	}
}

void process_ip6(u_char *ptr, const struct pcap_pkthdr* header)
{
#ifdef DEBUG
	char ip6Str[64];
#endif
	u_short ip6_len;
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)ptr;
	if (header_len + sizeof(struct ip6_hdr) > header->caplen)
		return;
	network_len = sizeof(struct ip6_hdr);
	if ((ip6_header->ip6_vfc & 0xf0) != 0x60)
	{
		stats->not_ip++; /* not IPv6*/
		stats->not_ip_bytes += p_size;
		return;
	}
	
	ip6_len = ntohs(ip6_header->ip6_plen);
	
	stats->ip6++;
	stats->ip6_bytes += p_size;
	
	/* Print ip infos */
#ifdef DEBUG
		printf("IP version: 6\n");
		printf("IP lenght: %d\n", ip6_len);
		printf("Src IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_src,ip6Str, 64));
		printf("Dst IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_dst,ip6Str, 64));
#endif
	
	/* Check next header (layer 4) */
	switch (ip6_header->ip6_nxt)
	{
		case IPPROTO_TCP :
			process_tcp(ptr + network_len); break;
		case IPPROTO_UDP :
			process_udp(ptr + network_len); break;
		default:
			stats->other++;
			stats->other_bytes += p_size;
#ifdef DEBUG
			{
				struct protoent *protodesc;
				if ((protodesc = getprotobynumber(ip6_header->ip6_nxt)))
					puts(protodesc->p_name);
				else
					puts("Unknown protocol");
			}
#endif
	}
}

void process_ip(u_char *ptr, const struct pcap_pkthdr* header)
{
	struct ip *ip_header = (struct ip *)ptr;
	u_short ip_len;
	
	if (ip_header->ip_v != IPVERSION)
	{ /* Fallback IPv6 */
		process_ip6(ptr, header);
		return;
	}
	/* Get ip_header length */
	network_len = ip_header->ip_hl*4;
	
	/* Check availability */
	if ( header_len + network_len > header->caplen)
		return;
	ip_len = ntohs(ip_header->ip_len);
	
#ifdef DEBUG
		printf("IP version: %d\n", ip_header->ip_v);
		printf("IP header lenght: %d\n", network_len);
		printf("IP lenght: %d\n", ip_len);
		printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
		printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
#endif
	
	if (header_len + ip_len > header->caplen)
		return;
	
	stats->ip++;
	stats->ip_bytes += p_size;
	
	/* Check next header (layer 4) */
	switch (ip_header->ip_p)
	{
		case IPPROTO_TCP :
			process_tcp(ptr + network_len); break;
		case IPPROTO_UDP :
			process_udp(ptr + network_len); break;
		default :
		{
			stats->other++;
			stats->other_bytes += p_size;
#ifdef DEBUG
			{
				struct protoent *protodesc;
				if ((protodesc = getprotobynumber(ip_header->ip_p)))
					puts(protodesc->p_name);
				else
					puts("Unknown protocol");
			}
#endif
			if (flow)
			{
				pdecode.src_port = 0;
				pdecode.dst_port = 0;
			}
		}
	}
	
	if (flow)
	{
		pdecode.time = header->ts;
		pdecode.size = p_size;
		pdecode.proto = ip_header->ip_p;
		pdecode.src = ip_header->ip_src;
		pdecode.dst = ip_header->ip_dst;
		pdecode.hash = hash(&pdecode);
		/* Enqueue packet */
		enqueue(&q[pdecode.hash >> (HASHHIGHBIT - QUEUE_NO_HIGHBIT)], &pdecode);
	}
}

void process_pkt (u_char* args, const struct pcap_pkthdr* header, const u_char* pkt)
{
	u_short type;
	u_char *ptr;
	stats_cont_t *st;
	ptr = (u_char*)pkt;
	type = ETHERTYPE_IP;
	
	/*Get stats structure location*/
	st = get_stats_container();
	
	/* Time update*/
	st->last_up = header->ts.tv_sec;
	
#ifdef DEBUG
		printf("-- Packet %u ----------------------------\nLength: %d\nTime: %u.%06u\n",
			   ++pkts_tot, header->len, (uint)header->ts.tv_sec, (uint)header->ts.tv_usec);
#endif
	
	/* Malformed packet */
	if (header_len > header->caplen)
	{
		errors++;
		return;
	}
	
	/* Check datalink layer */
	switch (datalink) {
		case DLT_EN10MB:
		{
			struct ether_header *eth_header = (struct ether_header *)ptr;
			if (inout_traffic_control && !bcmp(&mac, &(eth_header->ether_shost), 6))
				stats = &st->stats_out;
			else
				stats = &st->stats_in;
			type = ntohs(eth_header->ether_type);
			
#ifdef DEBUG
				printf("MAC Src: %s\n", ether_ntoa((struct ether_addr*)eth_header->ether_shost));
				printf("MAC Dst: %s\n", ether_ntoa((struct ether_addr*)eth_header->ether_dhost));
#endif
			break;
		}
		case DLT_IEEE802_11 : /* Not tested */
		{
			if ((char)*pkt & 0x01)
				header_len = 32;
			else
				header_len = 30;
			return;
		}
		default:
			stats = &st->stats_in;
			break;
	}
	
	/* Move to layer 3 */
	ptr+=header_len;
	
	/* Get effective packet size */
	p_size = header->len - header_len;
	
	/* Stats: bytes update */
	stats->bytes += p_size;
	
	if (header_len == header->caplen)
	{
		errors++;
		return;
	}
	
	stats->pkts_no++;
	
	switch (type)
	{
		case ETHERTYPE_IP : /* IP protocol */
			process_ip(ptr, header);
			break;
		case ETHERTYPE_IPV6 : /* IPv6 */
			process_ip6(ptr, header);
			break;
		case ETHERTYPE_ARP :
		case ETHERTYPE_LOOPBACK :
		case ETHERTYPE_PUP :
		case ETHERTYPE_REVARP :
		case ETHERTYPE_VLAN :
		default :
			stats->not_ip++;
			stats->not_ip_bytes += p_size;
#ifdef DEBUG
				printf("Unknown\n");
#endif
	}
}

/* CLEANUP FUNCTIONS */
void dispose(pcap_t* handle)
{
	pcap_close(handle);
	free(dev);
	dispose_stats();
}

void usage()
{
	printf("usage: malSniffer [-v] [-b] [-f] [-i <interface>] [-r [<rrdfile>]] [-p <pcap_file>]\n");
	printf("\t-v : verbose mode\n");
	printf("\t-b : if supported enable bidirectional monitoring mode (MAC address based)\n");
	printf("\t-f : enable flow aggregation (flows are emitted on stdout)\n");
	printf("\t-i <interface> : capture from specified device\n");
	printf("\t-r <rrdfile> : store statistics on specified file (if doesn't exist will be created)\n");
	printf("\t               if -b option is set the program attempts to create two files: \"in_<rrdfile>\" and \"out_<rrdfile>\"\n");
	printf("\t-p <pcap_file> : [BENCHMARK PURPOSE ONLY] capture offline from specified file (can be used only with -f and -v options)\n");
	exit(0);
}

char *options = ":vi:r:bfp:";

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE], opt;
	const char *datalinkStr;
	char* rrdfile;
	
	pcap_t *handle;
	pcap_handler process = &process_pkt;
	
	rrdfile = NULL;
	
	init_stats();
	
	/* Options management */
	while ((opt = getopt(argc, argv, options)) != -1)
	{
		switch (opt) {
			case 'v':
				verbose = TRUE;
				break;
			case 'i':
			{
				int len = strlen(optarg);
				if (!len)
					usage();
				MALLOC(dev, len+1, 3);
				memcpy(dev, optarg, len+1);
				break;
			}
			case 'p':
			{
				int len = strlen(optarg);
				if (!len)
					usage();
				MALLOC(pcap_f, len+1, 3);
				memcpy(pcap_f, optarg, len+1);
				break;
			}
			case 'r':
			{
				if (optarg && *optarg != '-')
				{
					int len = strlen(optarg);
					if (!len)
						usage();
						MALLOC(rrdfile, len+1, 3);
					memcpy(rrdfile, optarg, len+1);
					rrdtool = TRUE;
					break;
				}
				optind--;
			}
			case ':':
			{
				if (optopt == 'r')
				{
					rrdfile = DEFAULT_RRD_NAME;
					rrdtool = TRUE;
				}
				else
					usage();
				break;
			}
			case 'b' :
				inout_traffic_control = TRUE;
				break;
			case 'f' :
				flow = TRUE;
				break;
			case '?':
			default:
				usage();
		}
	}
	
	if (argc > optind)
		usage();
	
	if (!pcap_f)
	{
	/* Interactively select the device */
		if (!dev && !(dev = selectInterface(verbose)))
			return 1;
		
		printf("\nCapturing from device: %s ...\n", dev);
		
		/* Open the interface for live packet capture */
		if (!(handle = pcap_open_live(dev, CAPSIZE, PROMISC, TIMEOUT, errbuf)))
		{
			fprintf(stderr, "Error opening device %s:\n%s\n", dev, errbuf);
			return 3;
		}
	}
	else
	{
		if (rrdtool || inout_traffic_control || dev)
			usage();
		
		printf("\nCapturing from file: %s ...\n", pcap_f);
		
		if (!(handle = pcap_open_offline(pcap_f, errbuf)))
		{
			fprintf(stderr, "Error opening file %s:\n%s\n", pcap_f, errbuf);
			return 3;
		}
	}
	
	/* Switch user in case we're root */
	changeUser();
	
	/* Get infos about datalink layer */
	datalink = pcap_datalink(handle);
	printf("Datalink Layer Type: %s\n", datalinkStr = pcap_datalink_val_to_name(datalink));
	if (!datalinkStr || (header_len = datalinktooffset(datalink)) == -1)
	{
		fprintf(stderr, "Unsupported link layer for the device: %s\n", dev);
		dispose(handle);
		return 1;
	}
	
	/* Bidirectional traffic monitoring */
	if (inout_traffic_control && get_mac_addr(dev, mac))
	{
		inout_traffic_control = FALSE;
		puts("Bidirectional traffic control not supported: continuing happily ...");
	}
	
	if (inout_traffic_control)
		printf("MAC: %s\n", ether_ntoa((struct ether_addr*)mac));
	
	/* Thread for periodic updates of rrd stats */
	if (rrdtool)
	{
		pthread_t tid;
		rrd_args.verbose = verbose;
		rrd_args.inout_traffic = inout_traffic_control;
		if (inout_traffic_control)
		{
			MALLOC(in_rrdfile, strlen(rrdfile)+4, 3);
			strcpy(in_rrdfile, "in_");
			strcat(in_rrdfile, rrdfile);
			MALLOC(out_rrdfile, strlen(rrdfile)+5, 3);
			strcpy(out_rrdfile, "out_");
			strcat(out_rrdfile, rrdfile);
		}
		else
		{
			MALLOC(in_rrdfile, strlen(rrdfile)+1, 3);
			strcpy(in_rrdfile, rrdfile);
		}
		
		if (create_rrd_files(verbose) ||
			pthread_create(&tid, NULL, thread_update_rrd, (void*)&rrd_args))
		{
			fprintf(stderr, "Unable to manage rrd. Stats won't be available\n");
			rrdtool = FALSE;
		} else
			pthread_detach(tid);
	}
	
	/* Flow probe */
	if (flow)
	{
		int i = 0;
		pthread_t tid[QUEUE_NO];
		
		/* Create hash table for flow*/
		table_element_t *t = create_flow_table();
		if (!t)
			flow = FALSE;
		else
		{
			pthread_t id_collector;
			/* Create consumer threads */
			for (; i<QUEUE_NO; i++)
			{
				/*pthread_attr_t attr;
				int sched = SCHED_RR;
				pthread_attr_init(&attr);
				pthread_attr_setschedpolicy(&attr, sched);*/
				init_queue(&q[i]);
				flow_args[i].q = &q[i];
				flow_args[i].table = t;
				if (pthread_create(&tid[i], NULL, flow_processor, (void*)&flow_args[i]))
				{
					flow = FALSE;
					break;
				}
				pthread_detach(tid[i]);
			}
			/* Create flow-cleaner thread */
			if (pthread_create(&id_collector, NULL, flow_collector, (void*)t))
				flow = FALSE;
			else
				pthread_detach(id_collector);
		}
		if (!flow)
		{
			/* Recovery on failure */
			for (i--; i>=0; i--)
				pthread_cancel(tid[i]);
			if (t)
				free(t);
			fprintf(stderr, "Unable to manage flow. Flow probe won't be available\n");
		}
	}
	
	/* Packet capture loop */
	pcap_loop(handle, LOOPCOUNT, process, NULL);
	
	dispose(handle);
	
	return 0;
}
