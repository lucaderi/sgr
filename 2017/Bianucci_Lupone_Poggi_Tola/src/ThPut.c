/* *******************************************
Module : Thread Put
********************************************* */
#include "ThPut.h"
#include <pcap/pcap.h>

pthread_t tput;

/* **************************************************** */
void *ThreadPut(void *arg);
static void TPcleanup_handler(void *arg);
int worker(void);
int Mworker(void);

/* ************************************************** */
int myPortScanIsUpdate;
int myDeadProcIsUpdate;

/*----------------------------------------------------------------*/
static void TPcleanup_handler(void *arg)
{
}

//***********************************
//return 0 if no elements else return 1
int worker(void)
{
  arrQueueElem_t elem;
  int PID;
  if (getArrQueueElem(&queuePkt, &elem)) //==1 get ok
  {
    PID = getPid(elem.Port, elem.Protocol);
    //printf("PID %d protocol %d porta %d\n",PID,elem.Protocol,elem.Port);

    if (elem.direction == 1) //out
    {
      if (PID > 0)
      {
        addOutPkts(PID, elem.byteLen);
      }
      else if (PID == 0)
      {
        putArrQueueElem(&queueMiss, &elem);
      }
      else if (PID == -1)
        addOutPkts(0, elem.byteLen);
    }
    else //in
    {
      if (PID > 0)
      {
        addInPkts(PID, elem.byteLen);
      }
      else if (PID == 0)
      {
        putArrQueueElem(&queueMiss, &elem);
      }
      else if (PID == -1)
        addInPkts(0, elem.byteLen);
    }
    return 1;
  }
  return 0;
}

//***********************************
//return 0 if no elements else return 1
int Mworker(void)
{
  arrQueueElem_t elem;
  int PID;
  if (getArrQueueElem(&queueMiss, &elem)) //==1 get ok
  {
    PID = getPid(elem.Port, elem.Protocol);
    //printf("PID %d protocol %d porta %d\n",PID,elem.Protocol,elem.Port);

    if (elem.direction == 1) //out
    {
      if (PID > 0)
      {
        addOutPkts(PID, elem.byteLen);
      }
      else
        addOutPkts(0, elem.byteLen);
    }
    else //in
    {
      if (PID > 0)
      {
        addInPkts(PID, elem.byteLen);
      }
      else
        addInPkts(0, elem.byteLen);
    }
    return 1;
  }
  return 0;
}

void removeDeadProc()
{
  int PID;
  while ((PID = getInt(&queueDead)))
  {
    process_list[PID].info.byteS = 0;
    process_list[PID].info.byteR = 0;
    process_list[PID].info.pktS = 0;
    process_list[PID].info.pktR = 0;
  }
}

/*---------------------------------------------------------------- */
void *ThreadPut(void *arg)
{
  pthread_cleanup_push(TPcleanup_handler, NULL);
  sleep(1); //wait update port externally
  do
  {
    if (!worker())
    {
      sleep(0.1);
    }
    if (portScanIsUpdate == myPortScanIsUpdate)
    {
      while (Mworker())
      {
        ;
      }
      myPortScanIsUpdate = (myPortScanIsUpdate + 1) % 2;
    }
    if (deadProcIsUpdate == myDeadProcIsUpdate)
    {
      removeDeadProc();
      myDeadProcIsUpdate = (myDeadProcIsUpdate + 1) % 2;
    }
  } while (request_terminate_process == 0);

  pthread_cleanup_pop(false);

  return ((void *)0);
}
