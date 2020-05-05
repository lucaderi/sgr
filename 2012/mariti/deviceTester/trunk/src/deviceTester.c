#define __USE_BSD
#include <sys/types.h>

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <limits.h>

#include <getopt.h>

#include "utils.h"
#include "timeUtils.h"
#include "types.h"

#include "deviceTester.h"

/*------------------------------------------------------------------------
  Declaration of Local Functions
  --------------------------------------------------------------------------*/

/**
 * 
 */
static int doTest(int resend_timeout, int resend_max_attemps);

/**
 * 
 */
static void printResults(void);

/*------------------------------------------------------------------------
  Global Variables
  --------------------------------------------------------------------------*/

pcap_t		*offline;		/* pcap offline session */
pcap_t		*live[2];		/* pcap online sessions */
struct list	list;			/* packets list */

struct timeval		start_time;
unsigned int		num_pkt;
unsigned int		pckts_good;
u_int64_t		bytes_good;
u_int64_t		bytes_lost;
unsigned int		pckts_discarded;
u_int64_t		bytes_discarded;
/* 0 current, 1 max, 2 min, 3 sum, 4 square_sum */
usec_t			latency[5] = { 0, 0, USEC_T_MAX, 0, 0 };
usec_t			jitter[5] = { 0, 0, USEC_T_MAX, 0, 0 };
unsigned char		verboseIntervall = 1;

char			outputmode = 0;

FILE		*trial_output;
#define		trial_output_filename "/tmp/dt-trialoutput"
unsigned int	trial_sleep = 2;	/* seconds */
unsigned char	trial_num = 0;
unsigned int	trial_limit = 10;

int (*dt_send)(pcap_t *, const void *, size_t) = pcap_inject;
const u_char *(*dt_receive)(pcap_t *p, struct pcap_pkthdr *h) = pcap_next;

/*------------------------------------------------------------------------
  Main
  --------------------------------------------------------------------------*/

static void alarmHandler(int sig) {
  printResults();
  fflush(stdout);
  alarm(verboseIntervall);
}

static void sigint_handle(int sig) {
  if (live[0]) pcap_close(live[0]);
  if (live[1]) pcap_close(live[1]);
  exit(EXIT_SUCCESS);
}

#define DEFAULT_RESEND_TIMEOUT 1000
#define DEFAULT_RESEND_MAX_ATTEMPS 0
#define DEFAULT_FIXED_DELTAS 0
#define DEFAULT_VERBOSE 0

#define FLAGS_VERBOSE 1
#define FLAGS_VERBOSE_C 254
#define FLAGS_SIMULATE 2
#define FLAGS_TRIAL 4
unsigned char flags = 0 | DEFAULT_VERBOSE;

static void printHelp(void) {
  printf("Usage: deviceTester -f pcapfile -A dev -B dev [options] \n");
  printf("Options: -f file                  \t pcap file \n"
	 "         -A dev, -B dev           \t device A and device B \n"
	 "         -h|--help                \t print this help \n"
	 "         -t|--timeout msec        \t receive timeout \n"
	 "         -r|--resend-attemps num  \t num of resend attemps when to occurs \n"
	 "         -F|--fixed-deltas msec   \t interpacket elapsed time \n"
	 "         -p|--partition-rule str  \t str in {none,ip,mac,random,evenAndOdd}\n"
	 "         -s|--simulate a:b:c      \t simulate mode: simulate network delay \n"
	 "                                  \t and sut packet filtering/lost \n"
	 "                                  \t a=lost%% b=sutMaxDelay c=sutMinDelay \n"
	 "         -T|--trial num:sec       \t execute trial test: num=tests, \n"
	 "                                  \t sec=sleep time \n"
	 "         -v|--verbose             \t verbose mode \n"
	 "         -o|--output-mode str     \t str in {human,script} \n"
	 );
  printf("Default values: timeout=1000, resend-attemps=0, fixed-deltas=0, \n"
	 "                partition-rule=\"none\" \n"
	 );
}

int main(int argc, char **argv) {
  char	errbuf[PCAP_ERRBUF_SIZE];
  static int longopt =0;
  int opt;
  static const struct option options[] = {
    { "pcap-file",	required_argument,	&longopt,	'f' },
    { "devA",		required_argument,	&longopt,	'A' },
    { "devB",		required_argument,	&longopt,	'B' },
    { "timeout",	required_argument,	&longopt,	't' },
    { "resend-attemps", required_argument,	&longopt,	'r' },
    { "fixed-deltas",	required_argument,	&longopt,	'F' },
    { "verbose",	no_argument,		&longopt,	'v' },
    { "help",		no_argument,		&longopt,	'h' },
    { "simulate",	no_argument,		&longopt,	's' },
    { "partition-rule", required_argument,	&longopt,	'p' },
    { "trial",		required_argument,	&longopt,	'T' },
    { "output-mode",	required_argument,	&longopt,	'o' },
    { NULL,		0,			NULL,		0 }
  };

  char  *pcapfile = NULL, *iA = NULL, *iB = NULL;
  int	resend_timeout = DEFAULT_RESEND_TIMEOUT; /* don't resend, or milliseconds */
  int	resend_max_attemps = DEFAULT_RESEND_MAX_ATTEMPS;
  int   fixed_deltas = DEFAULT_FIXED_DELTAS;
  char  *partrule = "none";
  
  while (longopt ||
	 -1 != (opt = getopt_long(argc, argv, "f:A:B:t:r:F:vhs:p:T:o:", options, NULL))) {
    switch (opt) {
    case 'f': pcapfile = optarg; break;
    case 'A': iA = optarg; break;
    case 'B': iB = optarg; break;
    case 't': resend_timeout = atoi(optarg); break;
    case 'r': resend_max_attemps = atoi(optarg); break;
    case 'F': fixed_deltas = atoi(optarg); break;
    case 'v': flags |= FLAGS_VERBOSE; break;
    case 'h': printHelp(); exit(0);
    case 's': flags |= FLAGS_SIMULATE;
      simulate_lostperc = atoi(strtok(optarg, ":"));
      simulate_sutmaxdelay = atoi(strtok(NULL, ":"));
      simulate_sutmindelay = atoi(strtok(NULL, ":"));
      break;
    case 'p': partrule = optarg; break;
    case 'T': flags |= FLAGS_TRIAL;
      trial_limit = atoi(strtok(optarg, ":"));
      trial_sleep = atoi(strtok(NULL, ":"));
      break;
    case 'o': outputmode = !strcmp("script", optarg);
      break;
    case 0: opt=longopt; continue;
    }
    longopt =0;
  }    

  /* required arguments */
  if (!pcapfile || !iA || !iB) {
    printHelp();
    return EXIT_FAILURE;
  }
  signal(SIGINT, sigint_handle);
  ERRHAND_PC_EB(NULL, offline = pcap_open_offline(pcapfile, errbuf));
  ERRHAND_PC_EB(NULL, live[0] = pcap_open_live(iA, 65536, 1, resend_timeout, errbuf));
  ERRHAND_PC_EB(NULL, live[1] = pcap_open_live(iB, 65536, 1, resend_timeout, errbuf));
  if (pcap_datalink(live[0]) != pcap_datalink(live[1]) ||
      pcap_datalink(offline) != pcap_datalink(live[0])) {
    fprintf(stderr, "errore: devices con data link di tipo diverso.\n");
    exit(EXIT_FAILURE);
  }

  if (flags & FLAGS_SIMULATE) {
    //dt_simulate_init();
    dt_send = dt_simulate_send;
    dt_receive = dt_simulate_receive;
  }

  if (flags & FLAGS_VERBOSE) {
    signal(SIGALRM, alarmHandler);
    alarm(1);
  }

  if (flags & FLAGS_TRIAL) {
    time_t now = time(NULL);
    struct tm *tsr;
    char ts[13]; /* ddmmyyyy-hhmm */
    char filename[128] = trial_output_filename"-";
    ERRHAND(NULL, tsr=localtime(&now));
    sprintf(ts, "%02d%02d%d-%02d%02d", tsr->tm_mday, 1+tsr->tm_mon, 
	    1900+tsr->tm_year, tsr->tm_hour, tsr->tm_min);
    strcat(filename, ts);
    ERRHAND(NULL, trial_output = fopen(filename, "a"));
    flags &= FLAGS_VERBOSE_C; 	/* la modalita` trial non e` mai prolissa */
  }
  
#ifdef DEBUG
#   ifdef DEBUG_LOG_STDOUT 
  dbg_logfile=stdout;
#   else
  ERRHAND(NULL, dbg_logfile = fopen(dbg_logfilename, "w"));
#   endif
#endif
  
  //printf("interface A=%s, interface B=%s, datalink=%s, timeout=%d, resend max attemps=%d  \n", iA, iB, pcap_datalink_val_to_name(pcap_datalink(live[0])), resend_timeout, resend_max_attemps);
  
  ERRHAND_PC_PE(-1,
		parsePcapFile(&list, offline, parsePartRule(partrule), fixed_deltas),
		offline);
  do {
    (void)gettimeofday(&start_time, NULL);
    (void)doTest(resend_timeout, resend_max_attemps);
    printResults();
    if (flags & FLAGS_TRIAL) {
      fflush(stdout);
      /* reset global variables */
      num_pkt = 0; pckts_good = 0; bytes_good = 0; bytes_lost = 0; pckts_discarded = 0;
      bytes_discarded = 0; latency[1] = 0; latency[2] = USEC_T_MAX; latency[3] = 0;
      latency[4] = 0; jitter[1] = 0; jitter[2] = USEC_T_MAX; jitter[3] = 0;
      jitter[4] = 0;
      /* reset static variables */
      printResults(); 		

      trial_num ++;
      sleep(trial_sleep);
    }
  } while (flags & FLAGS_TRIAL && trial_num < trial_limit);

  if (flags & FLAGS_TRIAL)
    fclose(trial_output);
  
  return 0;
}

/*------------------------------------------------------------------------
  Definition of functions
  --------------------------------------------------------------------------*/ 


/*------------------------------------------------------------------------
  Definition of Local Functions
  --------------------------------------------------------------------------*/


#define dt_max(x, y)				\
  if ((x) > (y)) y = x;
#define dt_min(x, y)				\
  if ((x) < (y)) y = x;
#define dt_all(x)							\
  dt_max(x[0], x[1]); dt_min(x[0], x[2]); x[3] += x[0]; x[4] += x[0]*x[0];

static int doTest(int resend_timeout, int resend_max_attemps) {
  struct packet		*itr = list.head;
  struct packet		*last_correct[2] = { NULL /*intf A*/, NULL /*intf B*/ };
  struct timeval	send_ts = {0, 0};
  usec_t		latency_prev =0;
  const int		linkType = pcap_datalink(live[0]);
  unsigned char		dont_send = 0; /* se e' ricevuto un pacchetto
					* 1diverso da quello atteso */

  while (NULL != itr) {
    struct pcap_pkthdr	h;
    const u_char	*bytes;
    unsigned char 	resend_attemps = 0;
    unsigned char	out_intf = itr->interface;
    unsigned char	in_intf  = (out_intf+1)%2;

    if (!dont_send) {
      gettimeofday(&send_ts, NULL); 	/* forward timestamp */
      ERRHAND(-1, dt_send(live[out_intf], itr->data, itr->len));
      itr->test_send_ts = send_ts;
    } else {
      dont_send = 0;
    }
    while (NULL == (bytes = dt_receive(live[in_intf], &h)) &&
	   resend_attemps < resend_max_attemps) {
      ERRHAND_PC_GETERR(live[in_intf], "pcap_next");
      /* read timeout */
      resend_attemps ++;
    }
    ERRHAND_PC_GETERR(live[in_intf], "pcap_next");

    if (NULL == bytes) {
      /* lost */
      bytes_lost += itr->len + 8 + 4;
      itr = itr->next;
    } else if (!packetData_cmp(linkType, itr->data, itr->len, bytes, h.caplen)) {
      /* good */
      pckts_good ++;
      bytes_good += itr->len + 8 + 4;
      latency[0] = usec_timevalsub(&h.ts, &send_ts);
      dt_all(latency);
      if (latency_prev &&
	  ( (NULL != last_correct[0] && last_correct[0]->next == itr) ||
	    (NULL != last_correct[1] && last_correct[1]->next == itr) )) {
	jitter[0] = abs(latency[0] - latency_prev);
	dt_all(jitter);
      }
      latency_prev = latency[0];
      last_correct[out_intf] = itr;
      itr = itr->next;
    } else {
      /* really bad ?  */
      struct packet *pkt = last_correct[out_intf];
      while (NULL != pkt && pkt != itr && 
	     (out_intf != pkt->interface || 
	      packetData_cmp(linkType, pkt->data, pkt->len, bytes, h.caplen))) {
	pkt = pkt->next;
      }
      if (pkt == itr) {
	/* not bad, previous packet given for lost */
	bytes_lost -= itr->len - 8 - 4;
	latency[0] = usec_timevalsub(&h.ts, &pkt->test_send_ts);
	dt_all(latency);
	if (0 != latency_prev &&
	    ((NULL != last_correct[0] && last_correct[0]->next == pkt) ||
	     (NULL != last_correct[1] && last_correct[1]->next == pkt))) {
	  jitter[0] = abs(latency[0] - latency_prev);
	  dt_all(jitter);
	}
	latency_prev = latency[0];
	last_correct[out_intf] = pkt;
	pckts_good ++;
	bytes_good += pkt->len + 8 + 4;
	dont_send = 1;
      } else {
	/* bad */
	pckts_discarded ++;
	bytes_discarded += pkt->len + 8 + 4;
	itr = itr->next;
      }
    }

    if (NULL != itr && !dont_send) {
      struct timeval	now;
      struct timespec	tosleep, remain;
      int		diff;
      gettimeofday(&now, NULL);
      diff = itr->delta - usec_timevalsub(&now, &send_ts);
      usec2timespec(diff, &tosleep);
      while (diff > 0 && -1 == nanosleep(&tosleep, &remain)) {
	tosleep.tv_sec = remain.tv_sec;
	tosleep.tv_nsec = remain.tv_nsec;
      }
    }
    num_pkt ++;
  } /* end while itr */

  num_pkt --;
  return 0;
}

static void printResults(void) {
  static unsigned int		last_pckts_good;
  static u_int64_t		last_bytes_good;
  static struct timeval		last_print_time;
  static usec_t			last_latency_sum;
  static double			last_jitter_sum;
  
  usec_t		delta_micro;
  double		throughput_cur, throughput_bytes_cur;
  double		throughput_avg, throughput_bytes_avg;
  double		latency_cur, latency_avg, latency_sdev;
  double		jitter_cur, jitter_avg, jitter_sdev;
  struct timeval	print_time;
  unsigned int		cur_pckts_good;
  unsigned int		cur_bytes_good;

  if (0 == pckts_good && last_pckts_good > 0) {
    /* trial mode, new test started */
    last_pckts_good = 0; last_bytes_good = 0; last_print_time.tv_sec = 0;
    last_print_time.tv_usec = 0; last_latency_sum = 0; last_jitter_sum = 0;
    if (0 == outputmode) printf("====\n");
    return;
  }
  
  cur_pckts_good = pckts_good - last_pckts_good;
  cur_bytes_good = bytes_good - last_bytes_good;

  /* Avoid crash */
  if((cur_pckts_good == 0) || (pckts_good == 0)) {
    //printf("No data received yet\n");
    return;
  }

  gettimeofday(&print_time, NULL);

  if (!last_print_time.tv_sec) last_print_time = start_time;
  else printf("----\n");

  latency_cur = (double)(latency[3] - last_latency_sum) / cur_pckts_good;
  latency_avg = (double)latency[3] / pckts_good;
  latency_sdev = sqrt(latency[4] - pckts_good * latency_avg * latency_avg);
  jitter_cur = (double)(jitter[3] - last_jitter_sum) / cur_pckts_good;
  jitter_avg = (double)jitter[3] / pckts_good;
  jitter_sdev = sqrt(jitter[4] - pckts_good * jitter_avg * jitter_avg);

  delta_micro		= usec_timevalsub(&print_time, &last_print_time);
  throughput_cur	= (double)cur_pckts_good / delta_micro * 1000000;
  throughput_bytes_cur	= (double)cur_bytes_good / delta_micro * 1000000;

  delta_micro		= usec_timevalsub(&print_time, &start_time);
  throughput_avg	= (double)pckts_good / delta_micro * 1000000;
  throughput_bytes_avg  = (double)bytes_good / delta_micro * 1000000;

  if (0 == outputmode) {
    /* human output mode */
    printf("elapsed time: "PRI_USEC" usec\n"
	   "packet: %u received %u discarded %u lost \n"
	   "bytes: "PRI_UI64" received "PRI_UI64" discarded "PRI_UI64" lost \n"
	   "throughput cur: %f pps %f bps\n"
	   "throughput avg: %f pps %f bps\n"
	   "latency (usec): %f cur %f avg %f sdev "PRI_UI64" max "PRI_UI64" min \n"
	   "jitter (usec): %f cur %f avg %f sdev "PRI_UI64" max "PRI_UI64" min \n",
	   usec_timevalsub(&print_time, &start_time),
	   pckts_good+pckts_discarded, pckts_discarded, num_pkt+1 - pckts_good,
	   bytes_good+bytes_discarded, bytes_discarded, bytes_lost,
	   throughput_cur, throughput_bytes_cur,
	   throughput_avg, throughput_bytes_avg,
	   latency_cur, latency_avg, latency_sdev, latency[1], latency[2],
	   jitter_cur, jitter_avg, jitter_sdev, jitter[1], jitter[2]
	   );
  } else {
    /* script output mode */
    printf("%f %f "
	   "%f %f "PRI_UI64" "PRI_UI64" "
	   "%f %f "PRI_UI64" "PRI_UI64"\n",
	   throughput_avg, throughput_bytes_avg,
	   latency_avg, latency_sdev, latency[1], latency[2],
	   jitter_avg, jitter_sdev, jitter[1], jitter[2]
	   );
  }
	  
  if (flags & FLAGS_TRIAL) {
    fprintf(trial_output, "%f %f "
	    "%f %f "PRI_UI64" "PRI_UI64" "
	    "%f %f "PRI_UI64" "PRI_UI64"\n",
	    throughput_avg, throughput_bytes_avg,
	    latency_avg, latency_sdev, latency[1], latency[2],
	    jitter_avg, jitter_sdev, jitter[1], jitter[2]
	    );
  }

  last_pckts_good = pckts_good;
  last_bytes_good = bytes_good;
  last_print_time = print_time;
  last_latency_sum = latency[3];
  last_jitter_sum = jitter[3];
}
