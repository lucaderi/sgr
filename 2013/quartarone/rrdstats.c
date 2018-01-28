#include "rrdstats.h"
#include <rrd.h>
#include <strings.h>
#include <sys/stat.h>
#include <errno.h>


#define CREATE_ARGS 14
static char* create_args[] =
{
	"create",
	"--step",
	STR(RRD_UPDATE_STEP),
	NULL,
	"DS:Bytes:ABSOLUTE:15:0:125000000",
	"DS:Ip:ABSOLUTE:15:0:125000000",
	"DS:NotIp:ABSOLUTE:15:0:125000000",
	"DS:Tcp:ABSOLUTE:15:0:125000000",
	"DS:Udp:ABSOLUTE:15:0:125000000",
	"DS:Oth:ABSOLUTE:15:0:125000000",
	"RRA:AVERAGE:0.5:1:1200",
	"RRA:AVERAGE:0.5:1:1200",
	"RRA:MAX:0.5:30:1200",
	"RRA:MAX:0.5:360:1200"
};

static char* update_params[] = 
{
	"update",
	NULL,
	NULL
};

int update_rrd(char* file, long int last_up, data_t* dt)
{
	if ( dt )
	{
		char data[256];
		update_params[1] = file;
		sprintf(data, "%ld:%u:%u:%u:%u:%u:%u",
				last_up,
				dt->bytes,
				dt->ip_v4_bytes,
				dt->not_ip_bytes,
				dt->tcp_bytes,
				dt->udp_bytes,
				dt->other_bytes);
		update_params[2] = data;
		if (rrd_update(3, update_params))
		{
			fprintf(stderr, "rrd update failed: %s\n", rrd_get_error());
			rrd_clear_error();
		}
		else
				printf("%s updated!\n", file);
		bzero(dt, sizeof(data_t));
	}
	else
	    fprintf(stderr, "\nerror\n");
	return 0;
}

void* thread_update_rrd(void* args)
{
	data_collector_t *datac;
	rrd_update_args_t arg = *(rrd_update_args_t*)args;
	for(;;)
	{
		sleep(RRD_UPDATE_STEP-1);
		datac = swap_data();
		sleep(1);
		update_rrd(arg.in_rrdfile, datac->last_up, &datac->data_in);
//    fprintf(stderr,"updata\n");
	//	if (arg.inout_traffic)
	//		update_rrd(arg.out_rrdfile, datac->last_up, &datac->data_out);
	}
	return NULL;
}

int create_rrd(char* file)
{
	struct stat st;
	if (file)
	{
		
		if (stat(file, &st))
		{   /* stats fails*/
			if (errno != ENOENT)
			{ /* error occurred */
				perror(file);
				return -1;
			}
		}
    /*  file exists  */
		create_args[3] = file;
		if (rrd_create(CREATE_ARGS, create_args))
		{
			fprintf(stderr, "unable to create file: %s\n", file);
			fprintf(stderr, "%s\n", rrd_get_error());
			rrd_clear_error();
			return -1;
		}
		printf("file %s created\n", file);
	}
	return 0;
}
/*
int create_rrd_files(char *fin, char *fout)
{
	return create_rrd(fin, 1) || create_rrd(fout, 1);
}
*/
