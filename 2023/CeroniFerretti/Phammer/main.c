#include "dependencies.h"

static volatile sig_atomic_t keep_running = 1;

void sig_handler(int sig) {
	keep_running = 0;
}

int drop_privileges(const char *username) {
  struct passwd *pw = NULL;

  if (getgid() && getuid()) {
    fprintf(stderr, "privileges are not dropped as we're not superuser\n");
    return -1;
  }

  pw = getpwnam(username);

  if(pw == NULL) {
    username = "nobody";
    pw = getpwnam(username);
  }

  if(pw != NULL) {
    if(setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
      fprintf(stderr, "unable to drop privileges [%s]\n", strerror(errno));
      return -1;
    } else {
      fprintf(stderr, "user changed to %s\n", username);
    }
  } else {
    fprintf(stderr, "unable to locate user %s\n", username);
    return -1;
  }

  umask(0);
  return 0;
}

void printHelp(void) {

  printf("Usage: phammer [-h] -d <destination> [-a <source>] [-n <num>]\n");
  printf("-h              	   [Print help]\n");
  printf("-d <destination>     [Address of receiver]\n");
  printf("-a <source>     	   [Source address]\n");
  printf("-n <num>        	   [Number of packets to send]\n");

}

int main (int argc, char *argv[]) {

	int opt, packets_num;
	char* s_addr = NULL;
	char * d_addr;

	if(argc < 2) {
		printHelp();
		exit(0);
	}

	// Parsing of command-line arguments
	while( (opt = getopt(argc, argv, "hd:a:n:")) != -1) {
		switch (opt) {
		case 'h':
			printHelp();
			exit(0);
			break;
		case 'd':
			d_addr = optarg;
			break;
		case 'a':
			s_addr = optarg;
			break;
		case 'n':
			packets_num = atoi(optarg);
			break;
		}
	}

	// For handling ctrl + c, used to stop the program from sending packets
    struct sigaction action;
    action.sa_handler = sig_handler;
    sigaction(SIGINT, &action, NULL);
	//srand(time(NULL));

	char ipbase[14];
	//Si crea il socket in RAW
	int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	
	if(s == -1)
	{
		perror("Errore, privilegi insufficienti");
		exit(1);
	}

	if(drop_privileges("nobody") < 0)
    	return(-1);

	int tot_packets = 0;

	if (s_addr != NULL) {
		psender_udp(s, s_addr, d_addr);
		tot_packets++;
		keep_running = 0;
	}

	while (keep_running && packets_num) {
		int r1 = rand() % 255;
		int r2 = rand() % 255;
		int r3 = rand() % 255;
		int r4 = rand() % 255;
		snprintf(ipbase, 14, "%d.%d.%d.%d", r1,r2,r3,r4);
		//printf("%s,\n",ipbase); 
		psender_udp(s,ipbase, d_addr);
		packets_num--;
		tot_packets++;
	}

	printf("Program ended without fails and sent %d packets\n", (tot_packets);
	
	return 0;
}
