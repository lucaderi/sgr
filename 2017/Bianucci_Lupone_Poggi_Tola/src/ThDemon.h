/*
Module : Thread Demon header
*/

/**************************************************************************/
/*                          HEADER                                        */
/**************************************************************************/

#ifndef __THDEMON_H__
#define __THDEMON_H__ 001
/**************************************************************************/

#include "Global.h"

extern pthread_t tdem;
extern int deadProcIsUpdate; // flag checked externaly

extern void *ThreadDemon(void *arg);

void addInPkts(int pid, int bytes);
void addOutPkts(int pid, int bytes);

/**************************************************************************/
#endif
/**************************************************************************/
/*                          end  HEADER                                   */
/**************************************************************************/
