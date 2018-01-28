#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include "analysis.h"
#include "capture.h"

/* error buffer */
char mypcap_err_buf[ PCAP_ERRBUF_SIZE + 1 ] = { 0 };

/* descrittore pcap */
static pcap_t *mypcap_pcap_d = NULL;

/* programma bpf  */
static struct bpf_program bpf_program = { 0 };

/* imposta un messaggio di errore */
static void set_error( const char *tag , const char *message )
{
    snprintf( mypcap_err_buf , PCAP_ERRBUF_SIZE , "%s : %s" , tag , message );
}

/* imposta un messaggio di errore in base a errno */
static void set_errno_error( const char *tag )
{
    set_error( tag , strerror( errno ) );
}

void mypcap_break_capture()
{
    /* interrompe la cattura  */
    if ( mypcap_pcap_d ) pcap_breakloop( mypcap_pcap_d );
}

int mypcap_start_capture( const char *dev_name ,
                          int snaplen ,
                          int pkt_cnt ,
                          int promisc ,
                          const char *bpf_filter ,
                          pcap_direction_t pcap_dir ,
                          pcap_handler pkt_handler ,
                          mypcap_dl_hdr_len_handler dl_hdr_len_fun ,
                          struct mypcap_pkt_handler_params *params )
{
    /* richiede il descrittore */
    mypcap_pcap_d = pcap_open_live( dev_name , snaplen , promisc , 0 , mypcap_err_buf );

    /* cambia utente se eseguito tramite sudo */
    if ( mypcap_change_user() ) return EXIT_FAILURE;

    /* ritorna in caso di errore (ignora i warning) */
    if ( !mypcap_pcap_d ) return EXIT_FAILURE;

    /* compila il filtro bpf */
    if ( pcap_compile( mypcap_pcap_d , &bpf_program , bpf_filter , 1 , 0 ) )
    {
        set_error( "pcap_compile" , pcap_geterr( mypcap_pcap_d ) );
        return EXIT_FAILURE;
    }

    /* imposta un filtro ai pacchetti */
    if ( pcap_setfilter( mypcap_pcap_d , &bpf_program ) )
    {
        set_error( "pcap_setfilter" , pcap_geterr( mypcap_pcap_d ) );
        return EXIT_FAILURE;
    }

    /* imposta la direzione dei pacchetti catturati */
    if ( pcap_setdirection( mypcap_pcap_d , pcap_dir ) )
    {
        set_error( "pcap_setdirection" , pcap_geterr( mypcap_pcap_d ) );
        return EXIT_FAILURE;
    }

    /* salva il protocollo per il livello datalink */
    if ( dl_hdr_len_fun( pcap_datalink( mypcap_pcap_d ) , &params->dl_hdr_len ) )
    {
        set_error( "pcap" , "unknown datalink protocol" );
        return EXIT_FAILURE;
    }

    /* inizia il loop  */
    switch ( pcap_loop( mypcap_pcap_d , pkt_cnt , pkt_handler , ( u_char * )( params ) ) )
    {
    case -1:   /* errore */
        set_error( "pcap_loop" , pcap_geterr( mypcap_pcap_d ) );
        return EXIT_FAILURE;

    case 0:    /* limite ai pacchetti letti */
    case -2:   /* interrotto */
        return 0;
    }

    return 0;
}

void mypcap_capture_cleanup()
{
    /* rilascia il filtro bpf compilato */
    pcap_freecode( &bpf_program );

    /* rilascia il descrittore */
    if ( mypcap_pcap_d ) pcap_close( mypcap_pcap_d );
}

int mypcap_change_user()
{
    char *sudo_user;

    /* prende l'utente che ha eseguito sudo */
    sudo_user = getenv( "SUDO_USER" );

    /* se e' stato eseguito stramite sudo, altrimenti resta root */
    if ( sudo_user )
    {
        struct passwd *pw;

        /* prende le informazioni su l'utente nobody */
        if ( pw = getpwnam( sudo_user ) , !pw )   /* TODO: Memory leak! */
        {
            set_errno_error( "getpwnam" );
            return errno;
        }

        /* cambia UID e GID effettivi */
        if ( setgid( pw->pw_gid ) || setuid( pw->pw_uid ) )
        {
            set_errno_error( "getpwnam" );
            return errno;
        }
    }

    return 0;
}
