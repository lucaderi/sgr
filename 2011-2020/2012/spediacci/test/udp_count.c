#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

u_int64_t count = 1;
int int_count = 0;
time_t start;

int skt = 0;

void handler(int sig) {
  printf("count: %llu speed: %llu KB/s signal: %i\n", count, count / (time(NULL) - start) / 1000, sig);
  if (++int_count == 3) {
    if (skt)
      close(skt);
    exit(0);
  }
}

int main(int argc, char *args[]) {
  struct sigaction sa;
  struct sockaddr_in dest_addr;
  u_int16_t len;
  sigaction(SIGINT, NULL, &sa);
  sa.sa_handler = &handler;
  sigaction(SIGINT, &sa, NULL);
  if (argc != 4) {
    printf("usage: ip_dest port_dest message\n");
    return -1;
  }
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(atoi(args[2]));
  inet_pton(AF_INET, args[1], &dest_addr.sin_addr);
  skt = socket(AF_INET, SOCK_DGRAM, 0);
  if (skt < 0) {
    perror("socket");
    return -2;
  }
  start = time(NULL);
  for (len = strlen(args[3]);
       sendto(skt, args[3], len, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) > 0;
       count++)
    ;
  close(skt);
  return 0;
}
