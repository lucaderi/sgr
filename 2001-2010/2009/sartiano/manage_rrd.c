#include "manage_rrd.h"

int create_rrd(char* name_file) {
	char cmd_rrdtool[1000];
	strcpy(cmd_rrdtool, "rrdtool create ");
	strcat(cmd_rrdtool, name_file); //concat name file
	strcat(cmd_rrdtool, " --step 3");
	strcat(cmd_rrdtool, " DS:total_pkt:COUNTER:5:0:1000000");
	strcat(cmd_rrdtool, " RRA:AVERAGE:0.5:1:3600");
	strcat(cmd_rrdtool, " DS:tcp_pkt:COUNTER:5:0:1000000");
	strcat(cmd_rrdtool, " RRA:AVERAGE:0.5:1:3600");
	strcat(cmd_rrdtool, " DS:udp_pkt:COUNTER:5:0:1000000");
	strcat(cmd_rrdtool, " RRA:AVERAGE:0.5:1:3600");
	strcat(cmd_rrdtool, " DS:icmp_pkt:COUNTER:5:0:1000000");
	strcat(cmd_rrdtool, " RRA:AVERAGE:0.5:1:3600");
	printf("%s\n", cmd_rrdtool);
	assign_name_image(name_file);

	return system(cmd_rrdtool);
}

void assign_name_image(char* name_file) {
	int i;
	int lenght_file = strlen(name_file);
	manage_rrd_name_image = (char*) calloc(lenght_file, sizeof(char));
	//copia il nome del file escludendo l'estensione
	for (i = 0; i < strlen(name_file) - 3; i++) {
		manage_rrd_name_image[i] = name_file[i];
	}

	//assegna l'estensione png alla stringa che sarà il nome dell'imagine da creare
	manage_rrd_name_image[lenght_file - 1] = 'g';
	manage_rrd_name_image[lenght_file - 2] = 'n';
	manage_rrd_name_image[lenght_file - 3] = 'p';
	manage_rrd_name_image[lenght_file] = '\0';
}

int create_graph(char* name_file) {
	char cmd_graph[1000];

	strcpy(cmd_graph, "rrdtool graph --width 800 --height 350 ");
	strcat(cmd_graph, manage_rrd_name_image);
	strcat(cmd_graph, " --start end-30m");
	strcat(cmd_graph, " DEF:n0=");
	strcat(cmd_graph, name_file);
	strcat(cmd_graph, ":total_pkt:AVERAGE LINE:n0#0000FF:'Total Pkts'");
	strcat(cmd_graph, " DEF:n1=");
	strcat(cmd_graph, name_file);
	strcat(cmd_graph, ":tcp_pkt:AVERAGE LINE:n1#FF0000:'tcp Pkts'");
	strcat(cmd_graph, " DEF:n2=");
	strcat(cmd_graph, name_file);
	strcat(cmd_graph, ":udp_pkt:AVERAGE LINE:n2#00FF00:'upd Pkts'");
	strcat(cmd_graph, " DEF:n3=");
	strcat(cmd_graph, name_file);
	strcat(cmd_graph, ":icmp_pkt:AVERAGE LINE:n3#FF00FF:'icmp Pkts'");

	return system(cmd_graph);

}

int update_rrd(char* file_name, int total_pkt, int tcp_pkt, int udp_pkt,
		int icmp_pkt) {
	char cmd_rrdtool_update[1000];
	char total_tmp[30];
	char tcp_tmp[30];
	char udp_tmp[30];
	char icmp_tmp[30];
	int ret;

	strcpy(cmd_rrdtool_update, "rrdtool update ");
	strcat(cmd_rrdtool_update, file_name);
	strcat(cmd_rrdtool_update, " --template=total_pkt:tcp_pkt:udp_pkt:icmp_pkt");
	strcat(cmd_rrdtool_update, " N:");
	sprintf(total_tmp, "%d", total_pkt);
	strcat(cmd_rrdtool_update, total_tmp);

	strcat(cmd_rrdtool_update, ":");
	sprintf(tcp_tmp, "%d", tcp_pkt);
	strcat(cmd_rrdtool_update, tcp_tmp);

	strcat(cmd_rrdtool_update, ":");
	sprintf(udp_tmp, "%d", udp_pkt);
	strcat(cmd_rrdtool_update, udp_tmp);

	strcat(cmd_rrdtool_update, ":");
	sprintf(icmp_tmp, "%d", icmp_pkt);
	strcat(cmd_rrdtool_update, icmp_tmp);

	ret = system(cmd_rrdtool_update);
	return ret;
}
