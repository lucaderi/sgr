#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

int skt = 0;
int closing = 0;

pthread_mutex_t m;
pthread_t closer_t;

void handler(int sig) {
  sig = sig;
  if (!closing) {
    closing = 1;
    puts("closing..");
    pthread_mutex_unlock(&m);
  }
}

void *closer(void *arg) {
  arg = arg;
  pthread_mutex_lock(&m);
  pthread_mutex_unlock(&m);
  if (skt)
    close(skt);
  pthread_exit(NULL);
}

int main(int argc, char *args[]) {
  int ret;
  struct sockaddr_in addr, addr_dest;
  struct sigaction sa;
  sigaction(SIGINT, NULL, &sa);
  sa.sa_handler = &handler;
  sigaction(SIGINT, &sa, NULL);
  if (argc != 5) {
    printf("usage: port_bind ip_dest port_dest message\n");
    return -1;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons(atoi(args[1]));
  addr.sin_addr.s_addr = INADDR_ANY;
  skt = socket(AF_INET, SOCK_DGRAM, 0);
  if (skt < 0) {
    perror("socket");
    return -2;
  }
  if (bind(skt, (struct sockaddr *) &addr, sizeof(addr))) {
    perror("bind");
    return -3;
  }
  addr_dest.sin_family = AF_INET;
  addr_dest.sin_port = htons(atoi(args[3]));
  inet_pton(AF_INET, args[2], &addr_dest.sin_addr);
  if (sendto(skt, args[4], strlen(args[4]), 0, (struct sockaddr *) &addr_dest, sizeof(addr_dest)) < 0) {
    perror("sendto iniziale");
    return -7;
  }
  puts("first message sent");
  ret = 0;
  pthread_mutex_init(&m, NULL);
  pthread_mutex_lock(&m);
  pthread_create(&closer_t, NULL, closer, NULL);
  while (!closing) {
    char buffer[1024];
    struct sockaddr_in addr_recv;
    socklen_t addr_recv_len = sizeof(addr_recv);
    ssize_t len = recvfrom(skt, buffer, sizeof(buffer), 0, (struct sockaddr *) &addr_recv, &addr_recv_len);
    if (len < 0) {
      perror("recvfrom");
      ret = -4;
      break;
    }
    //puts("received");
    buffer[len] = '\0';
    if (strcmp(buffer, args[4])) {
      printf("message differ\noriginal: %s\nactual: %s\n", args[4], buffer);
      ret = -5;
      break;
    }
    if (sendto(skt, buffer, len, 0, (struct sockaddr *) &addr_recv, sizeof(addr_recv)) < 0) {
      perror("sendto");
      ret = -6;
      break;
    }
    //puts("sended");
  }
  pthread_join(closer_t, NULL);
  return ret;
}
