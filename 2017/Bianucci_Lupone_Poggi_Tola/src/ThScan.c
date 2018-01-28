/* *******************************************
Module : Thread Scan
********************************************* */
#include "ThScan.h"
#include <pcap/pcap.h>

pthread_t tscan;

static int *tcp_ports;
static int *udp_ports;

int portScanIsUpdate;

/* ******************************************************
 * Local func
 * */
void *ThreadScan(void *arg);
static void TScleanup_handler(void *arg);
void update_ports();

/*----------------------------------------------------------------*/
static void TScleanup_handler(void *arg)
{
	if (!fp)
	{
		pclose(fp);
		fp = NULL;
	}
}
/*----------------------------------------------------------------
  * todo..
  * */
void *ThreadScan(void *arg)
{
	pthread_cleanup_push(TScleanup_handler, NULL);
	do
	{
		sleep(1);
		update_ports();
		portScanIsUpdate = (portScanIsUpdate + 1) % 2;

#ifdef DEBUG_BLOCK_ON
		int i;
		printf("Porte TCP\n");
		for (i = 0; i < MAX_PORTS; i++)
		{
			if (tcp_ports[i])
				printf("\t%d\t%d\n", i, tcp_ports[i]);
		}
		printf("Porte UDP\n");
		for (i = 0; i < MAX_PORTS; i++)
		{
			if (udp_ports[i])
				printf("\t%d\t%d\n", i, udp_ports[i]);
		}
#endif
	} while (request_terminate_process == 0);

	pthread_cleanup_pop(false);

	return ((void *)0);
}

void update_ports()
{
	int *tcp_table, *udp_table, len = 512;
	char s[len], proto[10];
	ec_null(tcp_table = (int *)calloc(MAX_PORTS, sizeof(int)), "calloc fail")
		ec_null(udp_table = (int *)calloc(MAX_PORTS, sizeof(int)), "calloc fail")
			ec_null(fp = popen("netstat -atunp", "r"), "popen fail") while (fgets(s, len, fp))
	{
		if (strstr(s, myIp))
		{
			int i = 0, total_n = 0, n, m, is_tcp, is_udp, port = -1;
			sscanf(s, "%s", proto);
			is_tcp = !strcmp(proto, "tcp") || !strcmp(proto, "tcp6");
			is_udp = !strcmp(proto, "udp") || !strcmp(proto, "udp6");
			while (1 == sscanf(s + total_n, "%*[^0123456789]%d%n", &m, &n))
			{
				if (i == 6)
					port = m;
				else if (i == 12 && port >= 0)
				{
					if (is_tcp)
						tcp_table[port] = m;
					else if (is_udp)
						udp_table[port] = m;
				}
				total_n += n;
				i++;
			}
			if (i <= 12 && port >= 0)
			{
				if (is_tcp)
					tcp_table[port] = -1;
				else if (is_udp)
					udp_table[port] = -1;
			}
		}
	}
	ec_meno1(pclose(fp), "pclose fail")
	fp = NULL;
	int *tmp_ports = tcp_ports;
	tcp_ports = tcp_table;
	if (tmp_ports)
		free(tmp_ports);
	tmp_ports = udp_ports;
	udp_ports = udp_table;
	if (tmp_ports)
		free(tmp_ports);
}

int getPid(int port, u_char proto)
{
   /*
   * result = 0 -> miss
   * result = -1 -> pid morto
   * result = pid -> caso buono
   */
	int result = 0;
	if (proto == IPPROTO_TCP)
	{
		result = tcp_ports[port];
	}
	else
	{
		result = udp_ports[port];
	}
	return result;
}

void delete_ports()
{
	if (tcp_ports)
		free(tcp_ports);
	if (udp_ports)
		free(udp_ports);
}
