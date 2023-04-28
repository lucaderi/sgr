#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<errno.h> 	//For errno - the error number
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<time.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdbool.h>
#include<signal.h>
#include <pwd.h>

#include "senderUDP.h"