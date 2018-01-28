/* *******************************************
Module : Thread Interface

********************************************* */
#include "ThInterface.h"

#define clear() printf("\033[H\033[J") //cancella la shell
#define pos_0_0() printf("\033[0;0H")  //mette il cursore in posizione 0,0 (angolo in alto a sx)

pthread_mutex_t mtx_intrf = PTHREAD_MUTEX_INITIALIZER;
pthread_t tintrf;

/* ******************************************************
 * Local func
 * */
void *ThreadInterf(void *arg);
static void TIcleanup_handler(void *arg);

/*----------------------------------------------------------------*/
static void TIcleanup_handler(void *arg)
{
  Pthread_mutex_unlock(&mtx_intrf);
}
/*----------------------------------------------------------------
  * */
void *ThreadInterf(void *arg)
{

  int i, tmpU, tmpT;
  pthread_cleanup_push(TIcleanup_handler, NULL);
  process_t elem;
  unsigned int sommaBytes;
  unsigned int sommaPks;

  do
  {
#ifdef DEBUG_BLOCK_ON
    printf("-------------- THREAD INTERFACE RUN ---------------------------\n");
#endif

#ifdef INTERFACE_TH_ENABLE_PRINT
    clear();
    //pos_0_0();
    Pthread_mutex_lock(&mtx_intrf);
    tmpU = contUnricognizable;
    tmpT = contPktRx;
    Pthread_mutex_unlock(&mtx_intrf);
    printf("Pacchetti non Riconosciuti: %d\tPacchetti Totali: %d\n", tmpU, tmpT);
    printf("--------------------------------------------------------------------------------------------------------------------\n");
    printf("PID\t\tKbyteS\t\tKbyteR\t\tpktS\t\tpktR\t\tUSER\t\tNAME\n");
    printf("--------------------------------------------------------------------------------------------------------------------\n");

    sommaPks = tmpU;
    sommaBytes = 0;

    for (i = 0; i < pid_max; i++)
    {
      elem = getProc(i);
      if (i == 0)
        printf("%s\t\t%d\t\t%d\t\t%d\t\t%d\t\t%-.7s\t\t%-.20s\n", "-", elem.info.byteS / 1024, elem.info.byteR / 1024, elem.info.pktS, elem.info.pktR, "-", "data-pkt unassigned!");
      else if (elem.active && (elem.info.pktS != 0 || elem.info.pktR != 0))
        printf("%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%-.7s\t\t%-.20s\n", elem.PID, elem.info.byteS / 1024, elem.info.byteR / 1024, elem.info.pktS, elem.info.pktR, elem.user, elem.name);
      sommaBytes += (elem.info.byteS / 1024 + elem.info.byteR / 1024);
      sommaPks += elem.info.pktS + elem.info.pktR;
    }
    printf("--------------------------------------------------------------------------------------------------------------------\n");

//decommentare per vedere la differenza dei conteggi tra pcap e le strutture dati
//printf("\n\nsommaBytes = %d\tsommaPks=%d\n", sommaBytes, sommaPks);

#endif
    sleep(1);
  } while (request_terminate_process == 0);

  pthread_cleanup_pop(false);

  return ((void *)0);
}
