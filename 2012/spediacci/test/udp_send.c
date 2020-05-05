#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *args[]) {
  int skt;
  struct sockaddr_in dest_addr;
  int ret;
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
  ret = sendto(skt, args[3], strlen(args[3]), 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
  if (ret < 0)
    perror("send");
  close(skt);
  return ret;
}
