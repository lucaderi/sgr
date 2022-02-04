#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *args[]) {
  struct sockaddr_in dest_addr;
  ssize_t ret = 0;
  int skt;
  if (argc != 3) {
    printf("usage: ip_dest port_dest\n");
    return -1;
  }
  dest_addr.sin_family = AF_INET;
  inet_pton(AF_INET, args[1], &dest_addr.sin_addr);
  dest_addr.sin_port = htons(atoi(args[2]));
  skt = socket(AF_INET, SOCK_DGRAM, 0);
  if (skt < 0) {
    printf("ERROR: unable to open socket\n");
    return -2;
  }
  printf("skt %i\n", skt);
  while (!feof(stdin) && ret >= 0) {
    char buffer[1024 * 1024];
    fgets(buffer, sizeof(buffer), stdin);
    ret = sendto(skt, buffer, strlen(buffer) + 1, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
  }
  if (ret < 0)
    perror("sendto");
  close(skt);
  return ret;
}
