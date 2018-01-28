#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <microhttpd.h>
#include "httpd.h"
#include "rrd.h"

/* dimensione del buffer per il timestamp */
#define TIMESTAMP_SIZE 10

/* descrittore del server http */
static struct MHD_Daemon *mypcap_httpd = NULL;

/* coda circolare degli ultimi flussi da mostrare nella pagina */
static struct mypcap_httpd_flow mypcap_httpd_flows[ MYPCAP_HTTPD_MAX_FLOWS ];

/* se le statistiche rrd sono abilitate */
static int mypcap_rrd_enabled = 0;

/* se la registrazione dei flussi e' abilitata */
static int mypcap_flow_enabled = 0;

/* legge l'immagine generata da rrd per mostrarla nella pagina */
static int mypcap_read_rrd_image( void *cls , size_t pos , char *buf , int max )
{
    size_t read;
    FILE *fs;

    /* apre l'immagine in sola lettura */
    fs = fopen( MYPCAP_HTTPD_TEMP_FILE ".png" , "r" );
    assert( fs != NULL );

    /* va alla posizione */
    fseek( fs , pos , SEEK_SET );

    /* legge il contenuto */
    read = fread( buf , 1 , max , fs );

    /* chiude il file */
    fclose( fs );
    return ( read == 0 ? -1 : read );
}

/* callback per le richieste http */
/* TODO: Inguardabile? */
static int mypcap_httpd_callback( void *cls ,
                                  struct MHD_Connection *connection ,
                                  const char *url ,
                                  const char *method ,
                                  const char *version ,
                                  const char *upload_data ,
                                  unsigned int *upload_data_size , /* TODO: Cambia in size_t * nella nuova versione. */
                                  void **con_cls )
{
    struct MHD_Response *response;
    int ret;

    /* grafico rrd */
    if ( strcmp( url , "/rrd.png" ) == 0 )
    {
        /* genera l'immagine */
        assert( mypcap_rrd_graph( MYPCAP_HTTPD_TEMP_FILE ) == EXIT_SUCCESS );

        /* crea la risposta */
        response = MHD_create_response_from_callback( -1 , 1024 , &mypcap_read_rrd_image , NULL , NULL );
        MHD_add_response_header( response , "Content-Type" , "image/png" );
    }
    /* pagina */
    else
    {
        char buf[ MYPCAP_HTTPD_PAGE_BUFFER_SIZE + 1 ];
        size_t i , pos = 0;

        pos += snprintf( buf + pos , MYPCAP_HTTPD_PAGE_BUFFER_SIZE - pos ,
                         "<html>"
                         "<head>"
                         "<title>my-pcap</title>"
                         "<meta http-equiv=\"Refresh\" content=\"5\">"
                         "</head>"
                         "<style>"
                         "body { font-family: arial , sans-serif , sans; font-size: 10pt; background: #112233; color: #000000; text-align: center; }"
                         "h1 , h2 , th { color: #aa0000; }"
                         "td , th { padding: 0.5em; background: #f3f3f3; }"
                         "table { margin: 0 auto; }"
                         "</style>"
                         "</head>"
                         "<body>"
                         "<h1>my-pcap</h1>" );

        /* se abilitato, mostra il grafico rrd */
        if ( mypcap_rrd_enabled )
        {
            pos += snprintf( buf + pos , MYPCAP_HTTPD_PAGE_BUFFER_SIZE - pos ,
                             "<h2>RRD stats</h2>"
                             "<p><img src=\"/rrd.png\"></p>" );
        }

        /* se abilitati, mostra i flussi */
        if ( mypcap_flow_enabled )
        {
            pos += snprintf( buf + pos , MYPCAP_HTTPD_PAGE_BUFFER_SIZE - pos ,
                             "<h2>Flows</h2>"
                             "<table><tr><th>First</th><th>Last</th><th>Source IP</th><th>Source Port</th>"
                             "<th>Destination IP</th><th>Destination Port</th><th>Packets</th><th>Bytes</th></tr>\n" );

            /* scorre i flussi */
            for ( i = 0 ; i < MYPCAP_HTTPD_MAX_FLOWS ; i++ )
            {
                /* se valido */
                if ( mypcap_httpd_flows[ i ].data.pkts )
                {
                    struct tm *tm;
                    char ip_src_buf[ INET_ADDRSTRLEN + 1 ] = { 0 };
                    char ip_dst_buf[ INET_ADDRSTRLEN + 1 ] = { 0 };
                    char fst_tm_buf[ TIMESTAMP_SIZE ];
                    char lst_tm_buf[ TIMESTAMP_SIZE ];

                    /* formatta i timestamp */
                    tm = localtime( &mypcap_httpd_flows[ i ].data.fst );
                    strftime( fst_tm_buf , TIMESTAMP_SIZE , "%H:%M:%S" , tm );
                    tm = localtime( &mypcap_httpd_flows[ i ].data.lst );
                    strftime( lst_tm_buf , TIMESTAMP_SIZE , "%H:%M:%S" , tm );

                    /* converte gli indirizzi IP */
                    inet_ntop( AF_INET , &mypcap_httpd_flows[ i ].key.src.ip , ip_src_buf , INET_ADDRSTRLEN );
                    inet_ntop( AF_INET , &mypcap_httpd_flows[ i ].key.dst.ip , ip_dst_buf , INET_ADDRSTRLEN );

                    /* scrive la riga */
                    pos += snprintf( buf + pos , MYPCAP_HTTPD_PAGE_BUFFER_SIZE - pos ,
                                     "<tr>"
                                     "<td>%s</td><td>%s</td>"    /* inizio e fine */
                                     "<td>%s</td><td>%u</td>"    /* sorgente */
                                     "<td>%s</td><td>%u</td>"    /* destinazione */
                                     "<td>%u</td><td>%u</td>"    /* pacchetti e bytes */
                                     "</tr>\n" ,
                                     fst_tm_buf , lst_tm_buf ,
                                     ip_src_buf , mypcap_httpd_flows[ i ].key.src.port ,
                                     ip_dst_buf , mypcap_httpd_flows[ i ].key.dst.port ,
                                     mypcap_httpd_flows[ i ].data.pkts ,
                                     mypcap_httpd_flows[ i ].data.bytes );
                }
                /* riga vuota */
                else
                {
                    pos += snprintf( buf + pos , MYPCAP_HTTPD_PAGE_BUFFER_SIZE - pos ,
                                     "<tr><td>-</td><td>-</td><td>-</td><td>-</td>"
                                     "<td>-</td><td>-</td><td>-</td><td>-</td></tr>\n" );
                }
            }

            pos += snprintf( buf + pos , MYPCAP_HTTPD_PAGE_BUFFER_SIZE - pos , "</table>" );
        }

        pos += snprintf( buf + pos , MYPCAP_HTTPD_PAGE_BUFFER_SIZE - pos , "</body></html>" );

        /* crea la risposta */
        response = MHD_create_response_from_data( pos , buf , MHD_NO , MHD_NO );
        MHD_add_response_header( response , "Content-Type" , "text/html" );
    }

    if ( !response ) return MHD_NO;

    /* invia la risposta */
    ret = MHD_queue_response( connection , 200 , response );
    if ( ret == MHD_NO ) return MHD_NO;

    /* libera la risposta */
    MHD_destroy_response( response );
    return ret;
}

void mypcap_httpd_init( int port , int rrd , int flow )
{
    /* inizializza le strutture dati */
    mypcap_rrd_enabled = rrd;
    mypcap_flow_enabled = flow;
    memset( mypcap_httpd_flows , 0 , MYPCAP_HTTPD_MAX_FLOWS * sizeof( struct mypcap_httpd_flow ) );

    /* avvia il server */                    /* TODO: Bind su un indirizzo specificato. */
    mypcap_httpd = MHD_start_daemon( MHD_USE_SELECT_INTERNALLY , port , NULL , NULL ,
                                     &mypcap_httpd_callback , NULL , MHD_OPTION_END );
    if ( !mypcap_httpd )
    {
        perror( "MHD_Start_daemon" );
        exit( errno );
    }
}

void mypcap_httpd_push_flow( struct mypcap_flow_key *key ,
                             struct mypcap_flow_data *data )
{
    static size_t index = 0;

    /* inserisce il flusso */
    mypcap_httpd_flows[ index ].key = *key;
    mypcap_httpd_flows[ index ].data = *data;

    /* 'riavvolge'  */
    if ( ++index >= MYPCAP_HTTPD_MAX_FLOWS ) index = 0;
}

void mypcap_httpd_free()
{
    /* MHD_stop_daemon( mypcap_httpd );*/    /* TODO: Alle volte si blocca indefinitivamente. */
}
