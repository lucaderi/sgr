/*
 * rrd.c
 *
 *  Created on: 18-mag-2009
 *      Author: mattevigo
 */

#include "rrd.h"

/*** ********************************************************************************************* ***/

int rrdcreate()
{
	char ds[250] = "";
	char rrdcreate[750] = "";
	char chmod[50] = "";

	sprintf(ds, "rrdtool create %s --step=%d ", RRD_DS_FILENAME, STEP);
	strcat(rrdcreate, ds);

	sprintf(ds, " DS:udpcount:COUNTER:2:0:9999999");
	strcat(rrdcreate, ds);
	sprintf(ds, " RRA:AVERAGE:0.5:10:720");
	strcat(rrdcreate, ds);

	sprintf(ds, " DS:tcpcount:COUNTER:2:0:9999999");
	strcat(rrdcreate, ds);
	sprintf(ds, " RRA:AVERAGE:0.5:10:720");
	strcat(rrdcreate, ds);

	sprintf(ds, " DS:tcpsize:COUNTER:2:0:999999999");
	strcat(rrdcreate, ds);
	sprintf(ds, " RRA:AVERAGE:0.5:10:720");
	strcat(rrdcreate, ds);

	sprintf(ds, " DS:udpsize:COUNTER:2:0:999999999");
	strcat(rrdcreate, ds);
	sprintf(ds, " RRA:AVERAGE:0.5:10:720");
	strcat(rrdcreate, ds);

	/*printf(rrdcreate, "\n");*/

	sprintf(chmod, "chmod 666 %s", RRD_DS_FILENAME);

	system(rrdcreate);
	system(chmod);
	return 1;
}

/*** ********************************************************************************************* ***/

int rrdupdate(u_int tcp_size, u_int udp_size, u_int tcp_count, u_int udp_count)
{
	char update[100];

	sprintf(update, "rrdupdate %s N:%u:%u:%u:%u", RRD_DS_FILENAME, udp_count, tcp_count, tcp_size, udp_size);
	system(update);
	/*printf(update, "\n");*/
	return 0;
}

/*** ********************************************************************************************* ***/

int rrdsave()
{
	char save[1000];
	char temp[100];

	sprintf(save, "rrdtool graph %s -w 640 -h 243 ", RRD_GRAPH_COUNTER_FILENAME);

	sprintf(temp, "DEF:totudp=%s:udpcount:AVERAGE ", RRD_DS_FILENAME);
	strcat(save, temp);
	sprintf(temp, "DEF:tottcp=%s:tcpcount:AVERAGE ", RRD_DS_FILENAME);
	strcat(save, temp);
	sprintf(temp, "LINE:totudp#ff0000:'UDP packets' --start -30m ");
	strcat(save, temp);
	sprintf(temp, "LINE:tottcp#0000ff:'TCP packets' --start -30m ");
	strcat(save, temp);

	/*printf(save, "\n");*/
	system(save);

	sprintf(save, "rrdtool graph %s -w 640 -h 243 ", RRD_GRAPH_TRAFFIC_FILENAME);

	sprintf(temp, "DEF:tcptraffic=%s:tcpsize:AVERAGE ", RRD_DS_FILENAME);
	strcat(save, temp);
	sprintf(temp, "DEF:udptraffic=%s:udpsize:AVERAGE ", RRD_DS_FILENAME);
	strcat(save, temp);
	sprintf(temp, "LINE:tcptraffic#6CE800:'TCP Traffic' --start -30m ");
	strcat(save, temp);
	sprintf(temp, "LINE:udptraffic#e914ff:'UDP Traffic' --start -30m ");
	strcat(save, temp);

	/*printf(save, "\n");*/
	system(save);

	return 1;
}

/*** ********************************************************************************************* ***/
