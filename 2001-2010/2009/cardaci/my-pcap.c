#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <pthread.h>
#include "rrd.h"
#include "capture.h"
#include "analysis.h"
#include "flow.h"
#include "httpd.h"

/* porzione di pacchetto da catturare (byte) */
#define MYPCAP_SNAPLEN 80

/* filtro bpf per i pacchetti */
#define BPF_FILTER "ip and ( tcp or udp )"

/* error buffer */
extern char mypcap_err_buf[];

/* file pcap */
extern char mypcap_rrd_file[];

/* flag di terminazione */
int mypcap_stop = 0;

/* mostra informazioni sull'utilizzo */
static void usage()
{
    fprintf( stderr , "usage:\n" );
    fprintf( stderr , "    my-pcap -h\n" );
    fprintf( stderr , "    my-pcap -c <rrd>\n" );
    fprintf( stderr , "    my-pcap -g <rrd>\n" );
    fprintf( stderr , "    my-pcap [-i <int>] [-p] [-n <max>] [-d i | o]\n" );
    fprintf( stderr , "            [-r <rrd>] [-o] [-f] [-w <port>]\n" );
    fprintf( stderr , "\n" );
    fprintf( stderr , " -h        : print these infos.\n" );
    fprintf( stderr , " -l        : list compatible devices.\n" );
    fprintf( stderr , " -c <out>  : create a rrd database in <out>.\n" );
    fprintf( stderr , " -g <rrd>  : create a sample graph of <rrd>.\n" );
    fprintf( stderr , " -i <int>  : read packets from <int>; 'any' by default.\n" );
    fprintf( stderr , " -p        : promiscuous mode.\n" );
    fprintf( stderr , " -n <max>  : read <max> packets and exit.\n" );
    fprintf( stderr , " -d i|o    : capture direction, input(I) or output(O);\n" );
    fprintf( stderr , "             input and output by default.\n" );
    fprintf( stderr , " -r <out>  : fill a rrd database in <out>.\n" );
    fprintf( stderr , " -o        : dump some info on stdout.\n" );
    fprintf( stderr , " -f        : dump some net flow info on stdout or http.\n" );
    fprintf( stderr , " -w <port> : enable http server on port <port>.\n" );
    fprintf( stderr , "\n" );
    fprintf( stderr , "Analyze TCP and UDP over IPv4 packages only.\n" );
    fprintf( stderr , "Use SIGTERM or SIGINT to break the process.\n" );

    exit( EXIT_FAILURE );
}

/* stampa le devices disponibili */
static void list_devices()
{
    pcap_if_t *devs , *dev_ptr;

    /* elenca i dispositivi compatibili */
    if ( pcap_findalldevs( &devs , mypcap_err_buf ) )
    {
        fprintf( stderr , "%s\n" , mypcap_err_buf );
        exit( EXIT_FAILURE );
    }

    /* stampa i disposiztivi */
    for ( dev_ptr = devs ; dev_ptr ; dev_ptr = dev_ptr->next )
    {
        printf( "%s\n" , dev_ptr->name );
    }

    /* dealloca le strutture dati */
    pcap_freealldevs( devs );

    exit( EXIT_SUCCESS );
}

/* thread che gestisce i segnali */
static void * sig_handler( void *args )
{
    sigset_t sig_block_set;

    /* set dei segnali da gestire */
    sigemptyset( &sig_block_set );
    sigaddset( &sig_block_set , SIGALRM );
    sigaddset( &sig_block_set , SIGINT );
    sigaddset( &sig_block_set , SIGTERM );

    /* loop dei segnali */
    while ( 1 )
    {
        int sig = -1;

        /* attende un segnale */
        if ( sigwait( &sig_block_set , &sig ) )
        {
            perror( "sigwait" );
            exit( errno );
        }

        /* gestisce il segnale */
        switch ( sig )
        {
            /* interruzione */
        case SIGINT:
        case SIGTERM:
            mypcap_break_capture();     /* interrompe la cattura */
            mypcap_stop = 1;            /* informa la terminazione */
            exit( EXIT_SUCCESS );

            /* allarme: aggiorna il database rrd */
        case SIGALRM:
            /* aggiorna il database rrd */
            if ( mypcap_rrd_update() != EXIT_SUCCESS )
            {
                exit( EXIT_FAILURE );
            }
            break;
        }
    }

    return NULL;
}

/* in caso di terminazione spontanea */
static void cleanup()
{
    mypcap_stop = 1;
}

int main( int argc , char *argv[] )
{
    char c;

    /* parametri */
    char dev_name[ PATH_MAX + 1 ] = { 0 }; /* (!) */
    int pkt_cnt = -1;
    int promisc = 0;
    pcap_direction_t pcap_dir = PCAP_D_INOUT;
    int simple_info_dump = 0;
    int net_flow_dump = 0;
    int httpd = 0;
    int httpd_port;

    /* per default ascolta da tutte i dispositivi */
    strcpy( dev_name , "any" );

    /* disabilita la notifica degli errori per getopt() */
    opterr = 0;

    /* parsing della command line */
    while ( c = getopt( argc , argv , "hlc:g:i:pn:d:r:ofw:" ) , c != -1 )
    {
        switch ( c )
        {
        case 'h': usage();         /* stampa informazioni */

        case 'l': list_devices();  /* elenca i dispositivi compatibili */

        case 'g':                  /* genera il grafico */
            strncpy( mypcap_rrd_file , optarg , PATH_MAX );
            exit( mypcap_rrd_graph( NULL ) );

        case 'c':                  /* crea il file rrd */
            strncpy( mypcap_rrd_file , optarg , PATH_MAX );
            exit( mypcap_rrd_create() );

        case 'i':                  /* nome del dispositivo da interrogare */
            strncpy( dev_name , optarg , PATH_MAX );
            break;

        case 'p':                  /* modalita' promiscua */
            promisc = 1;
            break;

        case 'n':                  /* limite al numero di pacchetti catturati */
            {
                char *chk;

                pkt_cnt = strtol( optarg , &chk , 10 );
                if ( *chk || pkt_cnt <= 0 ) usage();
                break;
            }

        case 'd':                  /* direzione dei pacchetti */
            if ( *( optarg + 1 ) ) usage();  /* argomento non valido */

            switch ( *optarg )
            {
            case 'i': pcap_dir = PCAP_D_IN;  break;
            case 'o': pcap_dir = PCAP_D_OUT; break;

            default: usage();                /* argomento non valido */
            }
            break;

        case 'r':                  /* usa un database rrd */
            strncpy( mypcap_rrd_file , optarg , PATH_MAX );
            break;

        case 'o':                  /* informazioni base su stdout */
            simple_info_dump = 1;
            break;

        case 'f':                  /* scrive i flussi su stdout */
            net_flow_dump = 1;
            break;

        case 'w':                  /* abilita il server http */
            {
                char *chk;

                httpd_port = strtol( optarg , &chk , 10 );
                if ( *chk || httpd_port <= 0 ) usage();

                httpd = 1;
                break;
            }
            break;

        case '?':                  /* opzione non valida */
            usage();
        }
    }

    /* troppe opzioni */
    if ( optind != argc ) usage();

    /* notifica se nessuna opzione */
    if ( argc == 1 )
    {
        fprintf( stderr ,
                 "No option selected, noting will be shown. "
                 "Run `my-pcap -h` for help.\n" );
    }

    /* FINE DEL PARSING */

    /* cleanup handler */
    atexit( &mypcap_capture_cleanup );

    /* gestione dei segnali */
    {
        struct sigaction sa;
        sigset_t sig_block_set;
        pthread_t sig_handler_id;

        /* prepara sigaction */
        memset( &sa , 0 , sizeof( struct sigaction ) );
        sa.sa_handler = SIG_IGN;

        /* ignora SIGALRM, SIGINT e SIGTERM */
        if ( sigaction( SIGALRM , &sa , NULL ) ||
             sigaction( SIGINT , &sa , NULL ) ||
             sigaction( SIGTERM , &sa , NULL ) )
        {
            perror( "sigaction" );
            exit( errno );
        }

        /* crea il thread gestore dei segnali */
        if ( pthread_create( &sig_handler_id , NULL , &sig_handler , NULL ) )
        {
            perror( "pthread_create" );
            exit( errno );
        }

        /* set dei segnali da mascherare */
        sigemptyset( &sig_block_set );
        sigaddset( &sig_block_set , SIGALRM );
        sigaddset( &sig_block_set , SIGINT );
        sigaddset( &sig_block_set , SIGTERM );

        /* permette la terminazione del gestore */
        atexit( &cleanup );

        /* maschera i segnali per farli arrivare al gestore */
        if ( pthread_sigmask( SIG_BLOCK , &sig_block_set , NULL ) )
        {
            perror( "pthread_sigmask" );
            exit( errno );
        }
    }

    /* server http abilitato */
    if ( httpd )
    {
        /* avvia il server http */
        mypcap_httpd_init( httpd_port , *mypcap_rrd_file , net_flow_dump );

        /* registra il cleanup handler */
        atexit( &mypcap_httpd_free );
    }

    /* abilita le statistiche rrd */
    if ( *mypcap_rrd_file )
    {
        struct itimerval itv;
        struct timeval interval , value;

        /* prepara il timer */
        interval.tv_sec = value.tv_sec = MYPCAP_RRD_STEP;
        interval.tv_usec = value.tv_usec = 0;
        itv.it_interval = interval;
        itv.it_value = value;

        /* imposta il timer */
        if ( setitimer( ITIMER_REAL , &itv , NULL ) != 0 )
        {
            perror( "setitimer" );
            exit( errno );
        }
    }

    /* registrazione dei flussi abilitata */
    if ( net_flow_dump )
    {
        /* inizializza le strutture dati */
        mypcap_flow_init( httpd );

        /* registra il cleanup handler */
        atexit( &mypcap_flow_free );
    }

    /* in caso di terminazione spontanea */
    atexit( &cleanup );

    /* cattura */
    {
        struct mypcap_pkt_handler_params params = { 0 };

        /* prepara i parametri */
        params.simple_info_dump = simple_info_dump;
        params.net_flow_dump = net_flow_dump;

        /* inizia la cattura */
        if ( mypcap_start_capture( dev_name , MYPCAP_SNAPLEN , pkt_cnt ,
                                   promisc , BPF_FILTER , pcap_dir ,
                                   &mypcap_pkt_handler ,
                                   &mypcap_datalink_header_lengths ,
                                   &params ) )
        {
            fprintf( stderr , "%s\n" , mypcap_err_buf );
            exit( EXIT_FAILURE );
        }
    }

    exit( EXIT_SUCCESS );
}
