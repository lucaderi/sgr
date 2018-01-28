#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <wait.h>
#include "rrd.h"

/* dimensione massima di un comando shell */
#define CMD_BUF_SIZE 1024

/* file rrd */
char mypcap_rrd_file[ PATH_MAX + 1 ] = { 0 };

/* informazioni rrd */
struct mypcap_rrd_info mypcap_rrd_info = { 0 };

int mypcap_rrd_create()
{
    int e_status;
    char cmd_buf[ CMD_BUF_SIZE + 1 ] = { 0 };

    /* costruisce il comando shell */
    snprintf( cmd_buf , CMD_BUF_SIZE ,
              "rrdtool create %s --step %i "
              "DS:tcp_pkts:COUNTER:%u:0:U "
              "DS:udp_pkts:COUNTER:%u:0:U "
              "RRA:AVERAGE:0.5:1:%u "
              "RRA:MAX:0.5:%u:%u " ,
              mypcap_rrd_file , MYPCAP_RRD_STEP ,
              ( unsigned )( MYPCAP_RRD_STEP * MYPCAP_RRD_HEARTBEAT_RATIO ) ,
              ( unsigned )( MYPCAP_RRD_STEP * MYPCAP_RRD_HEARTBEAT_RATIO ) ,
              MYPCAP_RRD_FULL_AVG_STEPS ,
              MYPCAP_RRD_MAX_STEPS ,
              MYPCAP_RRD_MAX_SAMPLES );

    /* esegue il comando */
    e_status = system( cmd_buf );

    return WEXITSTATUS( e_status );
}

int mypcap_rrd_update()
{
    int e_status;
    char cmd_buf[ CMD_BUF_SIZE + 1 ] = { 0 };

    /* costruisce il comando shell */
    snprintf( cmd_buf , CMD_BUF_SIZE ,
              "rrdtool update %s N:%lu:%lu" ,
              mypcap_rrd_file ,
              mypcap_rrd_info.tcp_packets ,
              mypcap_rrd_info.udp_packets );

    /* esegue il comando */
    e_status = system( cmd_buf );

    return WEXITSTATUS( e_status );
}

int mypcap_rrd_graph( char *path )
{
    int e_status;
    char cmd_buf[ CMD_BUF_SIZE + 1 ] = { 0 };

    /* costruisce il comando shell */
    snprintf( cmd_buf , CMD_BUF_SIZE ,
              "rrdtool graph %s.png --start=end-%useconds "
              "-t 'TCP & UDP packets' -v 'packets/sec' "
              "DEF:tcp_pkts=%s:tcp_pkts:AVERAGE "
              "DEF:udp_pkts=%s:udp_pkts:AVERAGE "
              "DEF:tcp_pkts_max=%s:tcp_pkts:MAX "
              "DEF:udp_pkts_max=%s:udp_pkts:MAX "
              "AREA:tcp_pkts_max#ff000030:'TCP max' "
              "AREA:udp_pkts_max#00ff0030:'UDP max' "
              "LINE:tcp_pkts#ff0000:'TCP' "
              "LINE:udp_pkts#00ff00:'UDP' "
              "> /dev/null" ,
              ( path ? path : mypcap_rrd_file ) ,
              MYPCAP_RRD_STEP * MYPCAP_RRD_FULL_AVG_STEPS ,
              mypcap_rrd_file ,
              mypcap_rrd_file ,
              mypcap_rrd_file ,
              mypcap_rrd_file );

    /* esegue il comando */
    e_status = system( cmd_buf );

    return WEXITSTATUS( e_status );
}
