#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <inttypes.h>

struct sockaddr_in addr_send;
int skt_s = 0;
int *skt_r = NULL;
int closing = 0;
u_int32_t msg_len = 0;

int port_bind_start, port_bind_end, port_dest_start, port_dest_end;

pthread_mutex_t in_count_m;
u_int64_t out_count = 0, in_count = 0;
u_int64_t in_ok_count = 0;
u_int64_t in_bytes = 0;

time_t start, end;

#define MBIT 8 / (1000 * 1000)
void print_stats() {
  time_t elapsed = end - start;
  printf("message len: %u bytes\n", msg_len);
  printf("seconds elapsed: %lli\n", (long long int) elapsed);
  msg_len += 14 + 20 + 8; // headers
  printf("out_count: %" PRIu64 " pkt, %" PRIu64 " Mbit\n", out_count, out_count * msg_len * MBIT);
  printf("in_count: %" PRIu64 " pkt, %" PRIu64 " Mbit\n", in_count, in_bytes * MBIT);
  printf("in_ok_count: %" PRIu64 " pkt\n", in_ok_count);
  printf("***************\n");
  printf("speed sendto: %"  PRIu64 " pkt/s, %" PRIu64 " Mbit/s\n", out_count / elapsed, (out_count / elapsed) * msg_len * MBIT);
  printf("speed recvfrom: %"  PRIu64 " pkt/s, %" PRIu64 " Mbit/s\n", in_count / elapsed, (in_bytes / elapsed) * MBIT);
}

void shut() {
  if(!closing) {
    closing = 1;
    end = time(NULL);
  }
}

void *sighandler(void *arg) {
  sigset_t set; int sig;
  arg = arg;
  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGSEGV);
  sigaddset(&set, SIGFPE);
  sigaddset(&set, SIGILL);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGKILL);
  sigaddset(&set, SIGALRM);
  sigwait(&set, &sig);
  if (sig == SIGINT || sig == SIGALRM)
    shut();
  else {
    exit(sig);
  }
  return NULL;
}

void *reader(void *arg) {
  int first = 1;
  char b1[1024] = {0}, b2[1024] = {0};
  int skt = *(int *) arg;
  u_int64_t count = 0;
  u_int64_t ok = 0;
  u_int64_t bytes = 0;
  while (!closing) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    ssize_t len = recvfrom(skt, first ? b1 : b2, sizeof(b1), 0, (struct sockaddr *) &addr, &addr_len);
    if (len < 0)
      break;
    bytes += len;
    count++;
    if (first || memcmp(b1, b2, len) == 0)
      ok++;
    first = 0;
  }
  in_bytes += count * (14 + 20 + 8); //headers
  pthread_mutex_lock(&in_count_m);
  in_count += count;
  in_ok_count += ok;
  in_bytes += bytes;
  pthread_mutex_unlock(&in_count_m);
  close(skt);
  //  printf("receiver exit %llu pkt\n", count);
  pthread_exit(NULL);  
}

void *sender(void *arg) {
  char *message = (char *) arg;
  ssize_t len = strlen(message);
  ssize_t ret = -1;
  while (!closing) {
    int i;
    for (i=port_dest_start; i < port_dest_end; i++) {
      addr_send.sin_port = htons(i);
      message[len - 1] = i;
      if ((ret=sendto(skt_s, message, len, 0, (struct sockaddr *) &addr_send, sizeof(addr_send))) == len)
	out_count++;
    }
  }
  printf("sender exit %i\n", (int) ret);
  close(skt_s);
  pthread_exit(NULL);
}

int main(int argc, char *args[]) {
  int i;
  pthread_t s, signal;
  pthread_t *r;
  sigset_t set;
  int send_or_recv;
  char *ip_dest;
  char *message;
  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGSEGV);
  sigaddset(&set, SIGFPE);
  sigaddset(&set, SIGILL);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGKILL);
  sigaddset(&set, SIGALRM);
  pthread_sigmask(SIG_SETMASK, &set, NULL);
  if (argc != 8) {
    printf("usage: port_bind_start port_bind_end ip_dest port_dest_start port_dest_end message send_or_recv\n");
    return -1;
  }
  port_bind_start = atoi(args[1]);
  port_bind_end = atoi(args[2]);
  port_dest_start = atoi(args[4]);
  port_dest_end = atoi(args[5]);
  ip_dest = args[3];
  send_or_recv = atoi(args[7]);
  message = args[6];
  msg_len = strlen(message);

  skt_r = malloc(sizeof(int) * (port_bind_end - port_bind_start));
  r = malloc(sizeof(pthread_t) * (port_bind_end - port_bind_start));

  pthread_mutex_init(&in_count_m, NULL);

  addr_send.sin_family = AF_INET;
  if (inet_pton(AF_INET, ip_dest, &addr_send.sin_addr) != 1) {
    perror("fail to convert ip address");
    return -2;
  }

  if (send_or_recv == 0 || send_or_recv == 2) {
    struct sockaddr_in addr_recv;
    addr_recv.sin_family = AF_INET;
    addr_recv.sin_addr.s_addr = INADDR_ANY;  
    for (i=0; i < port_bind_end - port_bind_start; i++) {
      skt_r[i] = socket(AF_INET, SOCK_DGRAM, 0);
      if (skt_r[i] <= 0) {
	perror("socket recv");
	shut();
	return -8;
      }
      addr_recv.sin_port = htons(i + port_bind_start);
      if (bind(skt_r[i], (struct sockaddr *) &addr_recv, sizeof(addr_recv))) {
	perror("bind");
	shut();
	return -3;
      }
    }
  }


  if (send_or_recv == 0 || send_or_recv == 1) {
    skt_s = socket(AF_INET, SOCK_DGRAM, 0);
    if (skt_s <= 0) {
      perror("socket send");
      shut();
      return -9;
    }
  }
 
  pthread_create(&signal, NULL, &sighandler, NULL);

  start = time(NULL);
  if (send_or_recv == 0 || send_or_recv == 2) {
    alarm(30);
    for (i=0; i < port_bind_end - port_bind_start; i++) {
      pthread_create(&r[i], NULL, &reader, &skt_r[i]);
    }
  }
  if (send_or_recv == 0 || send_or_recv == 1) {
    pthread_create(&s, NULL, &sender, message);
  }

  if (send_or_recv == 0 || send_or_recv == 2) {
    for (i=0; i < port_bind_end - port_bind_start; i++) {
      pthread_join(r[i], NULL);
    }
  }
  if (send_or_recv == 0 || send_or_recv == 1) {
    pthread_join(s, NULL);
  }
  pthread_join(signal, NULL);
  print_stats();

  free(r);
  free(skt_r);
  return 0;
}
