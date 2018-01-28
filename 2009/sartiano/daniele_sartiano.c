#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <getopt.h>
#include <evutil.h>
#include <time.h>
#include <event.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <GeoIP.h>
#include <GeoIPCity.h>

#include "daniele_sartiano.h"
#include "manage_rrd.h"
#include "flow.h"
#include "hashtable.h"
#include "flow_queue.h"
#include "flow_export.h"
#include "mongoose.h"

#define N_THREAD 5

const char
		page_no_map[] =
				"HTTP/1.1 200 OK\r\n"
					"content-Type: text/html\r\n\r\n"
					"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
					"<html xmlns=\"http://www.w3.org/1999/xhtml\">"
					"<head>"
					"</head>"
					"<body>"
					"<div>"
					"<h3 align='center'>SGR</h3>"
					"<table cellpadding='20' align='center' style=\"font-family : 'Courier New';\">"
					"<tr>"
					"<td><a href=\"/\">View Flows</a></td>"
					"<td><a href=\"/map\">View Map</a></td>"
					"<td><a href=\"/graph\">View Graph</a></td>"
					"</tr>"
					"</table>"
					"</div>"
					"<div align='center'>You must install GeoLiteCity from <a href='http://www.maxmind.com/app/geolitecity'>http://www.maxmind.com/app/geolitecity</a>"
					"<br/>to view the map.</div>";

const char
		page_no_graph[] =
				"HTTP/1.1 200 OK\r\n"
					"content-Type: text/html\r\n\r\n"
					"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
					"<html xmlns=\"http://www.w3.org/1999/xhtml\">"
					"<head>"
					"</head>"
					"<body>"
					"<div>"
					"<h3 align='center'>SGR</h3>"
					"<table cellpadding='20' align='center' style=\"font-family : 'Courier New';\">"
					"<tr>"
					"<td><a href=\"/\">View Flows</a></td>"
					"<td><a href=\"/map\">View Map</a></td>"
					"<td><a href=\"/graph\">View Graph</a></td>"
					"</tr>"
					"</table>"
					"</div>"
					"<div align='center'>RRD Tool is not enable!</div>";

const char
		page_map[] =
				"HTTP/1.1 200 OK\r\n"
					"content-Type: text/html\r\n\r\n"
					"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
					"<html xmlns=\"http://www.w3.org/1999/xhtml\">"
					"<head>"
					"<meta content=\"text/html; charset=utf-8\" http-equiv=\"Content-Type\" />"
					"<title>SGR Map</title>"
					"<script src=\"http://maps.google.com/maps?file=api&amp;v=2.x&amp;key=ABQIAAAA71rQIgo_yy6XLKTXCyX1ZRSgIx7NcM2Lyi0_av4-0a0oKguBhBRKpg_ZRsC4aj7dRzWA3KwvN6ZMOQ\" type=\"text/javascript\"></script> "
					"<script type=\"text/javascript\">"
					"var map = null;"
					"var markers = new Array();"

					"function initialize() {"
					"if (GBrowserIsCompatible()) {"
					"map = new GMap2(document.getElementById(\"map_canvas\"));"
					"map.setCenter(new GLatLng(37.4419, -122.1419), 2);"
					"var customUI = map.getDefaultUI();"
					"map.setUI(customUI);"
					"}}\n"

					"function showAddress(address) {\n"
					"var lan_lon = address.split(',');\n"
					"var end = 0;"
					"var i = 0;\n"
					"while(end != 1) {\n"
					"if(lan_lon[i+2] != undefined && lan_lon[i] != '-' ) {\n"
					"var marker = createMarker(new GLatLng(parseFloat(lan_lon[i]), parseFloat(lan_lon[i+1])), lan_lon[i+2]);\n"
					"if(!contains(marker)) {\n"
					"markers.push(marker);\n"
					"map.addOverlay(marker);\n"
					"}\n"
					"document.getElementById('info_marker').innerHTML = marker.getLatLng().toString() + ' ' + marker.getTitle();\n"
					"i+=3;}\n else  {end = 1;\n}\n"
					"}"
					"}"
					"function contains(element){"
					"for(var index=0;index < markers.length;index++) {"
					"if(markers[index].getLatLng().equals(element.getLatLng()) ) {\n"
					"return true;"
					"}\n"
					"}"
					"return false;"
					"}"

					"function createMarker(point, ip_address) {\n"
					"var marker = new GMarker(point, {title: ip_address});\n"
					"marker.value = ip_address;\n"
					"GEvent.addListener(marker, \"click\", function() {\n"
					"var myHtml = \"<b>\" + ip_address + \"</b>\" ;\n"
					"map.openInfoWindowHtml(point, myHtml);\n"
					"});\n"
					"return marker;\n"
					"}\n"
					"</script>"
					"<script type=\"text/javascript\" language=\"javascript\">"

					"setTimeout('makeGeoRequest()', 5000);"
					"var http_geo_request = false;"
					"function makeGeoRequest() {"
					" http_geo_request = false;"
					"if (window.XMLHttpRequest) { "
					"http_geo_request = new XMLHttpRequest();"
					"if (http_geo_request.overrideMimeType) {http_geo_request.overrideMimeType('text/html');}"
					"} else if (window.ActiveXObject) { "
					"try {http_geo_request = new ActiveXObject(\"Msxml2.XMLHTTP\");} "
					"catch (e) { try {"
					"http_geo_request = new ActiveXObject(\"Microsoft.XMLHTTP\");"
					"} catch (e) {}}}"
					"if (!http_geo_request) {"
					"alert('Cannot create XMLHTTP instance');"
					"return false;"
					"}"
					"http_geo_request.onreadystatechange = reloadMap;"
					"http_geo_request.open('GET', 'get_geo_data', true);"
					"http_geo_request.send(null);setTimeout('makeGeoRequest()', 5000);"
					"}"
					"function reloadMap() {"
					"if (http_geo_request.readyState == 4) {"
					"if (http_geo_request.status == 200) {"
					"result = http_geo_request.responseText;\n"
					"if(result != \"\") {"
					"document.getElementById('address_span').innerHTML = result;"
					"showAddress(result);}"
					"} else {"
					"alert('There was a problem with the request.');}}}"
					"</script>"
					"</head>"
					"<body onload=\"initialize()\" onunload=\"GUnload()\">"
					"<div>"
					"<h3 align='center'>SGR</h3>"
					"<table cellpadding='20' align='center' style=\"font-family : 'Courier New';\">"
					"<tr>"
					"<td><a href=\"/\">View Flows</a></td>"
					"<td><a href=\"/map\">View Map</a></td>"
					"<td><a href=\"/graph\">View Graph</a></td>"
					"</tr>"
					"</table>"
					"</div>"

					"<div align='center' id=\"map_canvas\" style=\"width: 100%; height: 450px\"></div>"
					"<p>address: <span id='address_span'></span> <p>"
					"<p>marker: <span id='info_marker'></span></p>"
					"</body>"
					"</html>";

const char
		page[] =
				"HTTP/1.1 200 OK\r\n"
					"content-Type: text/html\r\n\r\n"
					"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
					"<html xmlns=\"http://www.w3.org/1999/xhtml\">"
					"<head>"
					"<meta content=\"text/html; charset=utf-8\" http-equiv=\"Content-Type\" />"
					"<title>SGR</title>"
					"<script type=\"text/javascript\" language=\"javascript\">"
					"setTimeout(\"makeRequest()\", 3000);\n"

					"var http_request = false;\n"
					"function makeRequest() {\n"
					"http_request = false;\n"
					"if (window.XMLHttpRequest) { \n"
					"http_request = new XMLHttpRequest();\n"
					"if (http_request.overrideMimeType) {"
					"http_request.overrideMimeType('text/html');\n"
					"}\n"
					"} else if (window.ActiveXObject) { \n"
					"try {\n"
					"http_request = new ActiveXObject(\"Msxml2.XMLHTTP\");\n"
					"} catch (e) { \n"
					"try {\n"
					"http_request = new ActiveXObject(\"Microsoft.XMLHTTP\");\n"
					"} catch (e) {\n"
					"}\n"
					"}\n"
					"}\n"
					"if (!http_request) {\n"
					"alert('Cannot create XMLHTTP instance');\n"
					"return false;\n"
					"}\n"
					"http_request.onreadystatechange = alertContents;\n"
					"http_request.open('GET', 'get_data', true);\n"
					"http_request.send(null);\n"
					"setTimeout(\"makeRequest()\", 3000);\n"
					"}\n"
					"function alertContents() {\n"
					"if (http_request.readyState == 4) {\n"
					"if (http_request.status == 200) {\n"
					"result = http_request.responseText;\n"
					"document.getElementById('textarea_ajax').value += result;\n"
					"document.getElementById('textarea_ajax').scrollTop = document.getElementById('textarea_ajax').scrollHeight; \n"
					"} else {\n"
					"alert('There was a problem with the request.');\n}\n}\n}\n"
					"</script>"

					"</head>"
					"<body onload=\"initialize()\" onunload=\"GUnload()\">"
					"<div>"
					"<h3 align='center'>SGR</h3>"
					"<table cellpadding='20' align='center' style=\"font-family : 'Courier New';\">"
					"<tr>"
					"<td><a href=\"/\">View Flows</a></td>"
					"<td><a href=\"/map\">View Map</a></td>"
					"<td><a href=\"/graph\">View Graph</a></td>"
					"</tr>"
					"</table>"
					"</div>"
					"<div align='center'>"
					"<textarea id='textarea_ajax'  readonly  cols='100' rows='30'>"
					"ip_src:ip_port\t\t\tip_dst:port_dst\t\t\ttotal_bytes\tpackets_number\n"
					"</textarea>"
					"</div>"
					"</body>"
					"</html>";

char
		page_graph[] =
				"HTTP/1.1 200 OK\r\n"
					"content-Type: text/html\r\n\r\n"
					"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
					"<html xmlns=\"http://www.w3.org/1999/xhtml\">"
					"<head>"
					"<meta content=\"text/html; charset=utf-8\" http-equiv=\"Content-Type\" />"
					"<title>SGR Graph</title>"
					"<script type='text/javascript' language='JavaScript'>"
					"var image;var c = 0;var first = 0;"
					"function count(nameFile)"
					"{"
					"if(first == 0)"
					"{"
					"first = 1;"
					"document.getElementById('refresh').style.display = '';"
					"}"
					"image.src=nameFile+(++c);"
					"} "
					"function init(nameFile) { "
					"image = document.getElementById('refresh'); "
					"if( image ) { "
					"var fun = \"count('\" + nameFile + \"')\";"
					"setInterval(fun,5000); "
					"}"
					"}"
					"</script></head>"
					"<body onload=\"init('";

char
		page_graph_last[] =
				"?')\">"
					"<div>"
					"<h3 align='center'>SGR</h3>"
					"<table cellpadding='20' align='center' style=\"font-family : 'Courier New';\">"
					"<tr>"
					"<td><a href=\"/\">View Flows</a></td>"
					"<td><a href=\"/map\">View Map</a></td>"
					"<td><a href=\"/graph\">View Graph</a></td>"
					"</tr>"
					"</table>"
					"</div>"
					"<div align='center'>"
					"<form>"
					"<img border='1' id='refresh' style='display:none'>"
					"</form>"
					"</div>"
					"</body></html>";

//Buffer with the flows exported to send to web client
char* flow_buffer = NULL;
//mutex associato al buffer
pthread_mutex_t mutex_flow_buffer;
//var to synchronize flow_buffer
int view = 0;
//total packets counter
int total_pkt = 0;
//tcp packets counter
int tcp_pkt = 0;
//udp packets counter
int udp_pkt = 0;
//icmp packets counter
int icmp_pkt = 0;
//var to manage timer to manage rrd
unsigned int sec;

int datalink;
//rrd name file
char* rvalue;
//if rrdtool == 0 --> no manage rrd, else manage rrd
int rrdtool = 0;
//var to manage geolocalization
GeoIP *gi;

//Todo eliminare
struct sockaddr_in **my_address;
int my_address_number = 0;

//Hashtable to insert flows
struct hashtable *h = NULL;

//thread to capture packets
pthread_t thread_pcap;
//thread to manage timer to update rrd
pthread_t thread_event;
//thread to export flow
pthread_t thread_export;

//Thread che prelevano pacchetti dalle rispettive code e le inseriscono nell'hash table
pthread_t array_t[N_THREAD];
//Code in cui il processo che effettua la pcap_loop inserisce i pacchetti catturati
queue* array_q[N_THREAD];
//Array di mutex per mettere in wait e svegliare i relativi thread
pthread_mutex_t array_m[N_THREAD];
//Array di variabili condizione per svegliare e mettere in wait i relativi thread
pthread_cond_t array_c[N_THREAD];

pthread_mutex_t mutex_hashtable;

/*
 * Funzione statica richiamata ogni 3 secondi, per effettuare l'aggiornamento del rrd
 * */
static void timeout_cb(int fd, short event, void *arg) {
	struct event_base *base = arg;
	struct event *timeout;
	struct timeval seconds = { 3, 0 };

	update_rrd(rvalue, total_pkt, tcp_pkt, udp_pkt, icmp_pkt);
	timeout = evtimer_new(base, timeout_cb, base);
	event_add(timeout, &seconds);
}

/*
 * Funzione che mette in coda i pacchetti catturati,
 * la coda in cui verrà inserito il pacchetto, viene scelta in
 * base al risultato della chiave hash, per il modulo del numero di thread.
 * */
void enqueue_flow(in_addr_t s, int src_port, in_addr_t d, int dst_port,
		u_int32_t len, struct timeval time) {
	flow_key *k;
	element* e = (element*) malloc(sizeof(element));
	int i;
	//assign the key
	k = flow_key_create(s, d, src_port, dst_port);
	//assign the flow
	e->f = flow_create(k, len, 1, time, time);
	//assign hash key
	e->hash_key = hashtable_hash(k);
	//choose the queue where insert the packet
	i = e->hash_key % N_THREAD;
	flow_queue_insert(array_q[i], &e);
	//send a signal to thread that dequeue paskets, from the queue 'i'
	pthread_cond_signal(&array_c[i]);
}

/*
 * Function to export flows.
 */
void* export_flow(void* arg) {
	int i;
	while (0 == 0) {
		i = flow_export(h, &mutex_hashtable, gi);
		sleep(1);
	}
}

/*
 * Funzione per esportare i flussi dalle code.
 * Il flusso viene rimosso dalla coda e viene inserito/aggiornato
 * nella hash table.
 */
void* dequeue_flow(void* arg) {
	int i = *((int*) arg);
	element *e;
	while (0 == 0) {
		while (array_q[i]->size == 0) {
			pthread_mutex_lock(&array_m[i]);
			pthread_cond_wait(&array_c[i], &array_m[i]);
			pthread_mutex_unlock(&array_m[i]);
		}
		e = flow_queue_remove(array_q[i]);
		hashtable_insert(h, e->f, &mutex_hashtable);
		free(e);
	}
	return ((void *) 0);
}

void processPacket(u_char *_deviceId, const struct pcap_pkthdr *h,
		const u_char *p) {
	struct ether_header *eptr;
	struct ip *ipptre;
	struct tcphdr *tcpptre;
	struct udphdr *udpptre;
	struct icmphdr *icmpptre;
	u_int length = h->len;

	struct protoent *prototype;

	eptr = (struct ether_header*) p;
	int offset;

	if (113 == datalink)
		offset = 2;
	else
		offset = 0;

	if (datalink == 113 || ntohs(eptr->ether_type) == ETHERTYPE_IP) {
		ipptre = (struct ip*) (p + sizeof(struct ether_header) + offset);
		if (length < sizeof(struct ip)) {
			printf("short packet");
			return;
		}
		prototype = getprotobynumber(ipptre->ip_p);
		total_pkt++;
		switch (ipptre->ip_p) {
		case IPPROTO_TCP:
			tcp_pkt++;

			tcpptre = (struct tcphdr*) (p + sizeof(struct iphdr)
					+ sizeof(struct ether_header) + offset);
			fprintf(stdout, "%d -- ", total_pkt);
			fprintf(stdout, "%ld:%ld/", h->ts.tv_sec, h->ts.tv_usec);
			fprintf(stdout, "%s/", prototype->p_name);
			fprintf(stdout, "%s:", inet_ntoa(ipptre->ip_src));
			fprintf(stdout, "%u/", ntohs(tcpptre->source));
			fprintf(stdout, "%s:", inet_ntoa(ipptre->ip_dst));
			fprintf(stdout, "%u\n", ntohs(tcpptre->dest));
			enqueue_flow(ipptre->ip_src.s_addr, tcpptre->source,
					ipptre->ip_dst.s_addr, tcpptre->dest, h->len, h->ts);
			break;
		case IPPROTO_UDP:
			udp_pkt++;
			udpptre = (struct udphdr*) (p + sizeof(struct iphdr)
					+ sizeof(struct ether_header) + offset);
			fprintf(stdout, "%d -- ", total_pkt);
			fprintf(stdout, "%ld:%ld/", h->ts.tv_sec, h->ts.tv_usec);
			fprintf(stdout, "%s/", prototype->p_name);
			fprintf(stdout, "%s:", inet_ntoa(ipptre->ip_src));
			fprintf(stdout, "%u/", ntohs(udpptre->source));
			fprintf(stdout, "%s:", inet_ntoa(ipptre->ip_dst));
			fprintf(stdout, "%u\n", ntohs(udpptre->dest));
			enqueue_flow(ipptre->ip_src.s_addr, udpptre->source,
					ipptre->ip_dst.s_addr, udpptre->dest, h->len, h->ts);
			break;
		case IPPROTO_ICMP:
			icmp_pkt++;
			fprintf(stdout, "%d --", total_pkt);
			icmpptre = (struct icmphdr*) (p + sizeof(struct iphdr)
					+ sizeof(struct ether_header) + offset);
			fprintf(stdout, "%ld:%ld/", h->ts.tv_sec, h->ts.tv_usec);
			fprintf(stdout, "%s\n", prototype->p_name);
			enqueue_flow(ipptre->ip_src.s_addr, 0, ipptre->ip_dst.s_addr, 0,
					h->len, h->ts);

		}
	}
	fflush(stdout);
}

void help() {
	printf("daniele_sartiano -i -r <file>.rrd -f <file>.pcap \n");
	printf("         -i             | pcap_open_live\n");
	printf("         -r             | rrd filename\n");
	printf("         -f <file>.pcap | pcap_open_offline\n");
	printf("Example: daniele_sartiano  -f bob2diego.pcap\n");
	printf("Example: daniele_sartiano  -i -r ffd_filename.rrd\n");
	printf("\n");
	printf(
			"This tool that reads packets from a pcap file or from a selected interface\n");
	exit(0);
}

void* loop_pcap(void* arg) {
	pcap_t *descr = (pcap_t*) arg;
	pcap_loop(descr, -1, processPacket, NULL);
	return ((void *) 0);
}

void* loop_event(void *arg) {
	struct event *timeout;
	struct event_base *base = event_base_new();
	struct timeval seconds = { 3, 0 };

	timeout = evtimer_new(base, timeout_cb, base);
	event_add(timeout, &seconds);
	event_base_dispatch(base);
	return ((void*) 0);
}

void signalHandler(int signum) {

	switch (signum) {

	case SIGALRM:
		create_graph(rvalue);
		sec = alarm(5);
		break;

	case SIGINT:
		signal(SIGQUIT, &signalHandler);
		if (rrdtool)
			create_graph(rvalue);
		hashtable_delete(h);
		GeoIP_delete(gi);

		printf("\nExiting........\n");

		exit(0);
	}
}

void page_insert_flow(char* string_flow) {
	pthread_mutex_lock(&mutex_flow_buffer);
	if (1 == view) {
		free(flow_buffer);
		flow_buffer = (char*) malloc((strlen(string_flow) + 1) * sizeof(char));
		view = 0;
		strcpy(flow_buffer, string_flow);

	} else {
		if (flow_buffer == NULL) {
			flow_buffer = (char*) realloc(flow_buffer,
					(strlen(string_flow) + 1) * sizeof(char));
			strcpy(flow_buffer, string_flow);
		} else {
			flow_buffer = (char*) realloc(flow_buffer, ((strlen(flow_buffer)
					+ strlen(string_flow) + 1) * sizeof(char)));
			strcat(flow_buffer, string_flow);
		}
	}

	free(string_flow);
	pthread_mutex_unlock(&mutex_flow_buffer);
}

static void get_http_geo_info(struct mg_connection *conn,
		const struct mg_request_info *ri, void *data) {
	char* s = NULL;
	int i;
	char* tmp;
	char* sep = ",";
	char* end = ",-.-.-";

	pthread_mutex_lock(&mutex_queue_geo);
	if ((&q_city_info)->size > 0) {
		s = (char*) calloc(50 * ((&q_city_info)->size + 1), sizeof(char));
		for (i = 0; i < (&q_city_info)->size; i++) {
			tmp = queue_remove(&q_city_info);
			if (tmp != NULL) {
				if (i != 0)
					strcat(s, sep);
				strcat(s, tmp);

			}

		}
	}
	pthread_mutex_unlock(&mutex_queue_geo);
	if (s != NULL) {
		strcat(s, end);
		mg_printf(conn, s);
		free(s);
	} else {
		mg_printf(conn, "");
	}

}

static void get_http_data(struct mg_connection *conn,
		const struct mg_request_info *ri, void *data) {
	if (1 == view)
		mg_printf(conn, "");
	else {
		if (flow_buffer != NULL)
			mg_printf(conn, flow_buffer);
		else
			mg_printf(conn, "");
		view = 1;
	}
}

static void home_page(struct mg_connection *conn,
		const struct mg_request_info *ri, void *data) {
	mg_printf(conn, page);
}

static void get_http_map(struct mg_connection *conn,
		const struct mg_request_info *ri, void *data) {
	if (gi != NULL)
		mg_printf(conn, page_map);
	else
		mg_printf(conn, page_no_map);
}

static void get_http_graph(struct mg_connection *conn,
		const struct mg_request_info *ri, void *data) {
	if (rrdtool) {
		char* page_graph_all = (char*) malloc((strlen(page_graph) + strlen(
				page_graph_last) + strlen(manage_rrd_name_image) + 1)
				* sizeof(char));
		sprintf(page_graph_all, "%s%s%s", page_graph, manage_rrd_name_image,
				page_graph_last);

		mg_printf(conn, page_graph_all);

		free(page_graph_all);
	} else {
		mg_printf(conn, page_no_graph);
	}
}

int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr;
	struct pcap_addr *addr_tmp;
	pcap_if_t *alldevs, *d;
	u_int i = 0;
	int i_create_thread;
	int i_init_mutex_cond;
	int id_th[N_THREAD];
	int i_q;
	struct mg_context *ctx;
	struct sockaddr_in *addr;

	int c;
	char* fvalue = NULL; //name file to open
	rvalue = NULL; //name rdd file to create

	int dev;

	if (1 == argc)
		help();

	while ((c = getopt(argc, argv, "hif: r:")) != -1)
		switch (c) {
		case 'f':
			fvalue = optarg;
			descr = pcap_open_offline(fvalue, errbuf);
			break;
		case 'r':
			rvalue = optarg;
			rrdtool = 1;
			break;
		case 'i':
			//find all devs
			if (pcap_findalldevs(&alldevs, errbuf) == -1) {
				fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
				return -1;
			}
			//print devs list
			for (d = alldevs; d; d = d->next) {
				printf("%d. %s", ++i, d->name);

				if (d->description)
					printf(" (%s)\n", d->description);
				else
					printf(" (No description available)\n");
				addr_tmp = d->addresses;
				if (addr_tmp) {
					printf("Address: ");
					while (addr_tmp) {
						addr = (struct sockaddr_in*) addr_tmp->addr;
						printf("%s  ", inet_ntoa(
								(struct in_addr) {addr->sin_addr.s_addr}));
					addr_tmp = addr_tmp->next;
				}
				printf("\n");
				}
			}
			//if 0 interfaces found
			if (0 == i) {
				printf("\nNo interfaces found!\n");
				return -1;
			}
			printf("Select interface:\n");
			scanf("%d", &dev);

			if (dev < 1 || dev > i) {
				printf("No interface number %d\n", dev);
				pcap_freealldevs(alldevs);
				return -1;
			}

			for (d = alldevs, i = 0; i < dev - 1; d = d->next, i++)
				;
			addr_tmp = d->addresses;
			descr = pcap_open_live(d->name, BUFSIZ, 1, 0, errbuf);

			while(addr_tmp) {
				my_address_number++;
				addr_tmp = addr_tmp->next;
			}
			addr_tmp = d->addresses;
			my_address = (struct sockaddr_in**)malloc(my_address_number* sizeof(struct sockaddr_in*));
			i=0;
			while(addr_tmp) {
				*(my_address+i) = (struct sockaddr_in*) addr_tmp->addr;
				i++;
				addr_tmp = addr_tmp->next;
			}

			for(i=0;i<my_address_number;i++) {
				printf("%s\n",inet_ntoa(
						(struct in_addr) {my_address[i]->sin_addr.s_addr}));
			}

			break;
		case 'h':
			help();
			break;
		default:
			abort();
		}

	gi = GeoIP_open("./GeoIPCity.dat",  GEOIP_INDEX_CACHE);

	if(gi == NULL) {
		gi = GeoIP_open("./usr/local/share/GeoIP/GeoIPCity.dat", GEOIP_INDEX_CACHE);
	}

	pthread_mutex_init(&mutex_queue_geo, NULL);
	queue_init(&q_city_info);

	//start http server
	ctx = mg_start();
	mg_set_option(ctx, "ports", "8000");
	mg_set_uri_callback(ctx, "/", &home_page, NULL);
	mg_set_uri_callback(ctx, "/graph", &get_http_graph, NULL);
	mg_set_uri_callback(ctx, "/map", &get_http_map, NULL);
	mg_set_uri_callback(ctx, "/get_data", &get_http_data, NULL);
	mg_set_uri_callback(ctx, "/get_geo_data", &get_http_geo_info, NULL);

	pthread_mutex_init(&mutex_flow_buffer, NULL);

	h = create_hashtable();
	pthread_mutex_init(&mutex_hashtable, NULL);

	for (i_q = 0; i_q < N_THREAD; i_q++)
		array_q[i_q] = (queue*) malloc(sizeof(queue));
	for (i_q = 0; i_q < N_THREAD; i_q++)
		flow_queue_init(array_q[i_q]);

	//intercept CONTROL-C
	signal(SIGINT, &signalHandler);

	if (rrdtool) {
		create_rrd(rvalue);
		signal(SIGALRM, &signalHandler);

		sec = alarm(5);

		printf("Immagine file: %s\n\n",manage_rrd_name_image);
	}

	datalink = pcap_datalink(descr);

	for (i_init_mutex_cond = 0; i_init_mutex_cond < N_THREAD; i_init_mutex_cond++) {
		pthread_mutex_init(&(array_m[i_init_mutex_cond]), NULL);
		pthread_cond_init(&(array_c[i_init_mutex_cond]), NULL);
	}

	for (i_create_thread = 0; i_create_thread < N_THREAD; i_create_thread++) {
		id_th[i_create_thread] = i_create_thread;
		pthread_create(&array_t[i_create_thread], NULL, dequeue_flow,
				(void*) &id_th[i_create_thread]);
		if (pthread_detach(array_t[i_create_thread]))
			printf("Error!\n");
	}

	pthread_create(&thread_export, NULL, export_flow, NULL);

	pthread_create(&thread_pcap, NULL, loop_pcap, (void*) descr);
	if (rrdtool)
		pthread_create(&thread_event, NULL, loop_event, NULL);

	pthread_join(thread_pcap, NULL);
	if (rrdtool) {
		pthread_join(thread_event, NULL);
	}

	pthread_join(thread_export, NULL);
	pcap_close(descr);
	return 0;
}
