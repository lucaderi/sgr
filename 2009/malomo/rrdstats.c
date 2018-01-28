#include "rrdstats.h"
#include <rrd.h>
#include <strings.h>
#include <sys/stat.h>
#include <errno.h>

char *in_rrdfile = NULL;
char *out_rrdfile = NULL;

#define CREATE_ARGS 15
static char* create_args[] =
{
	"create",
	"--step",
	STR(RRD_UPDATE_STEP),
	NULL,
	"DS:Bytes:ABSOLUTE:15:0:125000000",
	"DS:Ip:ABSOLUTE:15:0:125000000",
	"DS:Ip6:ABSOLUTE:15:0:125000000",
	"DS:NotIp:ABSOLUTE:15:0:125000000",
	"DS:Tcp:ABSOLUTE:15:0:125000000",
	"DS:Udp:ABSOLUTE:15:0:125000000",
	"DS:Oth:ABSOLUTE:15:0:125000000",
	"RRA:AVERAGE:0.5:1:1200",
	"RRA:AVERAGE:0.5:12:2400",
	"RRA:MAX:0.5:30:1200",
	"RRA:MAX:0.5:360:2400"
};

static char* update_params[] = 
{
	"update",
	NULL,
	NULL
};

int update_rrd(char* file, long int last_up, stats_t* st, int verbose)
{
	if (st && last_up != 0l)
	{
		char data[256];
		update_params[1] = file;
		sprintf(data, "%ld:%u:%u:%u:%u:%u:%u:%u",
				last_up,
				st->bytes,
				st->ip_bytes,
				st->ip6_bytes,
				st->not_ip_bytes,
				st->tcp_bytes,
				st->udp_bytes,
				st->other_bytes);
		update_params[2] = data;
		if (rrd_update(3, update_params))
		{
			fprintf(stderr, "rrd update failed: %s\n", rrd_get_error());
			rrd_clear_error();
		}
		else
			if (verbose)
				printf("%s updated!\n", file);
		bzero(st, sizeof(stats_t));
	}
	else
	{
	    fprintf(stderr, "\nerror\n");
	}
	return 0;
}

void* thread_update_rrd(void* args)
{
	stats_cont_t* stats;
	rrd_update_args_t arg = *(rrd_update_args_t*)args;
	for(;;)
	{
		sleep(RRD_UPDATE_STEP-1);
		stats = swap_stats_buffers();
		sleep(1);
		update_rrd(in_rrdfile, stats->last_up, &stats->stats_in, arg.verbose);
		if (arg.inout_traffic)
			update_rrd(out_rrdfile, stats->last_up, &stats->stats_out, arg.verbose);
	}
	return NULL;
}

int create_rrd(char* file, int verbose)
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
		else /* file exists */
		{
			char select = 0;
			do
			{
				printf("file %s still exists: would you like to overwrite it? [y|n]: ", file);
				fflush(stdout);
				scanf("%*[\n]");
				scanf("%c", &select);
				scanf("%*[^\n]");
			}
			while ( select != 'y' && select != 'n' );
			if (select == 'n')
			{
				if (verbose)
					printf("continuing happily with previous %s\n", file);
				return 0;
			}
		}
		create_args[3] = file;
		if (rrd_create(CREATE_ARGS, create_args))
		{
			fprintf(stderr, "unable to create file: %s\n", file);
			fprintf(stderr, "%s\n", rrd_get_error());
			rrd_clear_error();
			return -1;
		}
		if (verbose)
			printf("file %s created\n", file);
	}
	return 0;
}

int create_rrd_files(int verbose)
{
	return create_rrd(in_rrdfile, verbose) || create_rrd(out_rrdfile, verbose);
}