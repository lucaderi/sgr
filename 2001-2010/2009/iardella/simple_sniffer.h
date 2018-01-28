/* Ethernet header size */
#define ETHERNET_SIZE 14
#define RRD_STEP 60

int becomeNobody();
int becomeRoot();
void printReport();

void end_handler(int signum);
void alarm_handler(int signum);
