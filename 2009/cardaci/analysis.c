#include <string.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "rrd.h"
#include "analysis.h"
#include "flow.h"

/* dimensione del buffer per il timestamp */
#define TIMESTAMP_SIZE 256

/* informazioni da passare a rrd */
extern struct mypcap_rrd_info mypcap_rrd_info;

int mypcap_datalink_header_lengths( int datalynk_type , int *offset )
{
    switch ( datalynk_type )
    {
    case DLT_LINUX_SLL:
        *offset= 16;
        break;

    case DLT_EN10MB:
        *offset = sizeof( struct ether_header );
        break;

    case DLT_IEEE802_11:
        *offset = 12;
        break;

    default:
        return 1;
    }

    return 0;
}

void mypcap_pkt_handler( u_char *user ,
                         const struct pcap_pkthdr *pkt_header ,
                         const u_char *pkt )
{
    struct tm *tm;
    struct mypcap_pkt_handler_params *params;
    size_t trnsp_off;
    char tm_buf[ TIMESTAMP_SIZE + 1 ] = { 0 };
    char ip_src_buf[ INET_ADDRSTRLEN + 1 ] = { 0 };
    char ip_dst_buf[ INET_ADDRSTRLEN + 1 ] = { 0 };
    struct ip *ip;
    uint16_t src_port , dst_port;

    /* prende la struttura contenente i parametri */
    params = ( struct mypcap_pkt_handler_params * )user;

    /* controlla lo spazio disponibile */
    if ( params->dl_hdr_len + sizeof( struct ip ) > pkt_header->caplen )
    {
        fprintf( stderr , "capture too short; dropped\n" );
        return;
    }

    /* legge l'header IP */
    ip = ( struct ip * )( pkt + params->dl_hdr_len );

    /* offset dell'header di trasporto */
    trnsp_off = params->dl_hdr_len + ip->ip_hl * 4;

    /* legge l'header di trasporto */
    if ( ip->ip_p == 6 )                     /* TCP */
    {
        struct tcphdr *tcp_hdr;

        /* controlla lo spazio disponibile */
        if ( trnsp_off + sizeof( struct tcphdr ) > pkt_header->caplen )
        {
            fprintf( stderr , "capture too short; dropped\n" );
            return;
        }

        /* legge l'header TCP */
        tcp_hdr = ( struct tcphdr * )( pkt + trnsp_off );

        /* salva le porte */
        src_port = ntohs( tcp_hdr->source );
        dst_port = ntohs( tcp_hdr->dest );

        /* aggiorna le informazioni rrd */
        mypcap_rrd_info.tcp_packets++;
    }
    else if ( ip->ip_p == 17 )               /* UDP */
    {
        struct udphdr *udp_hdr;

        /* controlla lo spazio disponibile */
        if ( trnsp_off + sizeof( struct udphdr ) > pkt_header->caplen )
        {
            fprintf( stderr , "capture too short; dropped\n" );
            return;
        }

        /* legge l'header UDP */
        udp_hdr = ( struct udphdr * )( pkt + trnsp_off );

        /* salva le porte */
        src_port = ntohs( udp_hdr->source );
        dst_port = ntohs( udp_hdr->dest );

        /* aggiorna le informazioni rrd */
        mypcap_rrd_info.udp_packets++;
    }
    else                                     /* (controllo necessario?) */
    {
        fprintf( stderr , "packet corrupted; dropped\n" );
        return;
    }

    /* se il dump dei flussi e' abilitato */
    if ( params->net_flow_dump )
    {
        struct mypcap_flow_update_info update_info;
        memset( &update_info , 0 , sizeof( struct mypcap_flow_update_info ) );

        /* costruisce la chiave */
        update_info.key.src.ip = ip->ip_src;
        update_info.key.src.port = src_port;
        update_info.key.dst.ip = ip->ip_dst;
        update_info.key.dst.port = dst_port;

        /* costruisce le informazioni */
        update_info.bytes = pkt_header->len;
        update_info.lst = pkt_header->ts.tv_sec;

        /* aggiorna i flussi */
        mypcap_flow_add( &update_info );
    }

    /* se il dump dei pacchetti e' abilitato */
    if ( params->simple_info_dump )     /* TODO: Un thread dedicato alla stampa? */
    {
        /* formatta il timestamp */
        tm = localtime( &pkt_header->ts.tv_sec );
        strftime( tm_buf , TIMESTAMP_SIZE , "%d-%m-%Y %H:%M:%S" , tm );

        /* converte gli indirizzi IP */
        inet_ntop( AF_INET , &ip->ip_src , ip_src_buf , INET_ADDRSTRLEN );
        inet_ntop( AF_INET , &ip->ip_dst , ip_dst_buf , INET_ADDRSTRLEN );

        /* stampa il resoconto del pacchetto */
        printf( "O %s + %ldus ( %s ) %s:%u -> %s:%u\n" ,
                tm_buf , pkt_header->ts.tv_usec ,               /* timestamp */
                ( ip->ip_p == 6 ? "TCP" : "UDP" ) ,             /* protocollo di trasporto */
                ip_src_buf , src_port ,                         /* sorgente */
                ip_dst_buf , dst_port );                        /* destinazione */
    }
}
