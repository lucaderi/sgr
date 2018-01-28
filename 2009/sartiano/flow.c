#include "flow.h"
#include <GeoIP.h>
#include <GeoIPCity.h>

flow_key* flow_key_create(in_addr_t ip_src, in_addr_t ip_dst,
		u_int16_t port_src, u_int16_t port_dst) {
	flow_key *k = (flow_key*) malloc(sizeof(flow_key));
	k->ip_src = ip_src;
	k->ip_dst = ip_dst;
	k->port_src = port_src;
	k->port_dst = port_dst;
	return k;
}

flow* flow_create(flow_key *k, u_int length, u_int pkts, struct timeval first,
		struct timeval last) {
	flow *f = (flow*) malloc(sizeof(flow));
	f->key = k;
	f->length = length;
	f->pkts = pkts;
	f->first = first;
	f->last = last;
	return f;
}

void flow_print_export(flow *f) {
	printf("----------------------------------------\n");
	printf("src %s:%u -", inet_ntoa((struct in_addr) {f->key->ip_src}), ntohs(f->key->port_src));
	printf(" dst %s:%u\n", inet_ntoa((struct in_addr) {f->key->ip_dst}), ntohs(f->key->port_dst));
	printf("first: %ld:%ld ", f->first.tv_sec, f->first.tv_usec);
	printf(" last: %ld:%ld\n", f->last.tv_sec, f->last.tv_usec);
	printf("lenght: %d - pkts: %d\n", f->length, f->pkts);
	printf("----------------------------------------\n");
}

char* flow_create_string(flow *f) {
	char* string = (char*) malloc(sizeof(char) * 200);
	char* src = (char*) malloc(sizeof(char) * 32);
	char* dst = (char*) malloc(sizeof(char) * 32);
	char* ip_src = (char*) malloc(sizeof(char) * 17);
	char* port_src = (char*) malloc(sizeof(char) * 6); //max 2^16
	char* ip_dst = (char*) malloc(sizeof(char) * 17);
	char* port_dst = (char*) malloc(sizeof(char) * 6);
	sprintf(ip_src, "%s", inet_ntoa((struct in_addr) {f->key->ip_src}));
	sprintf(port_src, "%u", ntohs(f->key->port_src));
	sprintf(ip_dst, "%s", inet_ntoa( (struct in_addr) {f->key->ip_dst}));
	sprintf(port_dst, "%u", ntohs(f->key->port_dst));
	if(strlen(ip_src) + strlen(port_src) < 15)
	sprintf(src, "%s:%s\t\t\t", ip_src, port_src);
	else
	sprintf(src, "%s:%s\t\t", ip_src, port_src);
	if(strlen(ip_dst) + strlen(port_dst) < 15)
	sprintf(dst, "%s:%s\t\t\t", ip_dst, port_dst);
	else
	sprintf(dst, "%s:%s\t\t", ip_dst, port_dst);
	sprintf(string, "%s%s%d\t\t%d\n",src,dst, f->length, f->pkts);
	free(ip_src);
	free(port_src);
	free(ip_dst);
	free(port_dst);
	free(src);
	free(dst);
	return string;
}

char* flow_get_geo_info(flow* f, GeoIP* gi) {
	char* s = (char*) calloc(50, sizeof(char));
	GeoIPRecord *gir;
	char* ip_src;

	ip_src = inet_ntoa((struct in_addr) {f->key->ip_src});
	gir = GeoIP_record_by_name(gi, ip_src);

	if(gir != NULL)
	snprintf(s, 50,"%f,%f,%s", gir->latitude, gir->longitude, ip_src);
	else {
		free(s);
		free(gir);
		return NULL;
	}
	free(gir);
	return s;
}

int flow_cmp(flow *a, flow *b) {
	if (a->key->ip_src == b->key->ip_src && a->key->ip_dst == b->key->ip_dst
			&& a->key->port_src == b->key->port_src && a->key->port_dst
			== b->key->port_dst) {
		return 1;
	}
	return 0;
}
