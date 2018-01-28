/*
Module : Thread Scan header
*/

/**************************************************************************/
/*                          HEADER                                        */
/**************************************************************************/

#ifndef __TH_SCAN_H__
#define __TH_SCAN_H__ 001
/**************************************************************************/

#include "Global.h"

extern pthread_t tscan;
extern int portScanIsUpdate; // flag checked externaly

int getPid(int port, u_char proto);

extern void *ThreadScan(void *arg);
extern void update_ports();
extern void delete_ports();
/**************************************************************************/
#endif
/**************************************************************************/
/*                          end  HEADER                                   */
/**************************************************************************/
