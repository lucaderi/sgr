/* *******************************************
   Module : Thread Demon header
   ********************************************* */
#include "ThDemon.h"
#include <proc/readproc.h>

#define clear() printf("\033[H\033[J") // cancella la shell
#define pos_0_0() printf("\033[0;0H")  // mette il cursore in posizione 0,0 (angolo in alto a sx)

pthread_t tdem;

static int_list used_pids;
static int_list new_pids;

int deadProcIsUpdate;

/* ******************************************************
 * Local func
 * */
void *ThreadDemon(void *arg);
static void TDcleanup_handler(void *arg);

/*----------------------------------------------------------------*/
static void TDcleanup_handler(void *arg)
{
}

void addInPkts(int pid, int bytes)
{
  process_list[pid].info.byteR += bytes;
  process_list[pid].info.pktR++;
}

void addOutPkts(int pid, int bytes)
{
  process_list[pid].info.byteS += bytes;
  process_list[pid].info.pktS++;
}

/* Elimina dalla lista i processi non più attivi */
void removeDeleted(int_list *l)
{
  int n;
  while (*l != NULL)
  {
    n = (*l)->value;
    process_list[n].active = false;
    // NOTA: anche se altamente improbabile, la put potrebbe fallire in caso di coda piena
    putInt(&queueDead, n);
    *l = (*l)->next;
  }
}

void *ThreadDemon(void *arg)
{
  int i;
  process_t elem;
  unsigned int sommaBytes;
  unsigned int sommaPks;

  pthread_cleanup_push(TDcleanup_handler, NULL);
  used_pids = newList();

  do
  {
    static proc_t pinfo;
    static proc_t *t;
    new_pids = newList();

#ifdef DEBUG_BLOCK_ON
    printf("-------------- THREAD DEMON RUN ---------------------------\n");
#endif
    PROCTAB *proc = openproc(PROC_FILLSTAT | PROC_FILLUSR);
    memset(&pinfo, 0, sizeof(pinfo));

    while ((t = readproc(proc, NULL)) != NULL)
    {
      pinfo = *t;

      // Aggiorno la lista dei pid
      new_pids = insertList(new_pids, pinfo.tid);
      used_pids = removeFromList(used_pids, pinfo.tid);

      // Aggiorno le info del processo
      process_list[pinfo.tid].active = true;
      process_list[pinfo.tid].PID = pinfo.tid;
      strncpy(process_list[pinfo.tid].name, pinfo.cmd, 512);
      strncpy(process_list[pinfo.tid].user, pinfo.euser, 512);

      freeproc(t);
    }

    closeproc(proc);

    removeDeleted(&used_pids);
    deadProcIsUpdate = (deadProcIsUpdate + 1) % 2;
    if (used_pids != NULL)
      freeList(&used_pids);
    used_pids = new_pids;
    free(t);

//interface print block
#ifdef INTERFACE_TH_ENABLE_PRINT
    clear();
    printf("Pacchetti non Riconosciuti: %d\tPacchetti Totali: %d\n", contUnricognizable, contPktRx);
    printf("--------------------------------------------------------------------------------------------------------------------\n");
    printf("PID\t\tKbyteS\t\tKbyteR\t\tpktS\t\tpktR\t\tUSER\t\tNAME\n");
    printf("--------------------------------------------------------------------------------------------------------------------\n");

    sommaPks = contUnricognizable;
    sommaBytes = 0;

    for (i = 0; i < pid_max; i++)
    {
      elem = process_list[i];
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
