#include "data.h"

#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

#define RRD_UPDATE_STEP 10

/* Creates rrd files */
int create_rrd(char* file);
//int create_rrd_files(char *fin, char *fout);

typedef struct rrd_update_args
{
	int inout_traffic;
  char *in_rrdfile;
  char *out_rrdfile;
} rrd_update_args_t;

/* create a thread for periodic update of rrd file(s)
   args must be a rrd_update_args_t pointer */
void* thread_update_rrd(void* args);
