#include "stats.h"

#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

#define RRD_UPDATE_STEP 10

/* File names for rrd (in and out) statistics*/
extern char *in_rrdfile;
extern char *out_rrdfile;

/* Creates rrd files named in_rrdfile and out_rrdfile (if not NULL) */
int create_rrd_files(int verbose);

typedef struct rrd_update_args
{
	int inout_traffic;
	int verbose;
} rrd_update_args_t;

/* create a thread for periodic update of rrd file(s)
   args must be a rrd_update_args_t pointer */
void* thread_update_rrd(void* args);
