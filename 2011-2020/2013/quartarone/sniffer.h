#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include "flow.h"
#include "data.h"
#include "pcap.h"
#define TIMEOUT 1500
#define CAPSIZE 65535
#define ERR_BUF_SIZE 128
#define PROISC 1

#define SLEEP_TIME 10000
#define DEAD_LINE 120

typedef struct flow_worker_args{
  flow_table_t *f_tab;
  flow_buffer_t *f_buf;
  int wbase; /* indice di finestra */
  int wsize; /* dimensione finestra */
}worker_args_t;

typedef struct dispatcher_args{
  int datalink;
  u_char *mac_addr;
  pcap_t *handle;
}dispatcher_args_t;

data_t *data;
//volatile int stop =0;

#endif
