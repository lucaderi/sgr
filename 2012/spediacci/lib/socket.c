#include <limits.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>

#include "dnastack.h"

#define MAX_NUM_SOCKETS    32

pthread_mutex_t sockets_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t dlsym_mutex   = PTHREAD_MUTEX_INITIALIZER;
DnaSocket *sockets[MAX_NUM_SOCKETS] = { NULL };
u_int n_sockets = 0;

int (*real_socket)(int domain, int type, int protocol) = NULL;
ssize_t (*real_sendto)(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen) = NULL;
ssize_t (*real_recvfrom)(int sockfd, void *buf, size_t len, int flags,
			 struct sockaddr *src_addr, socklen_t *addrlen) = NULL;
int (*real_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
int (*real_close)(int fd) = NULL;

void get_dlsym(void **handle, const char *name) {
  pthread_mutex_lock(&dlsym_mutex);
  if (!(*handle))
    *handle = dlsym(RTLD_NEXT, name);
  pthread_mutex_unlock(&dlsym_mutex);
}

int socket(int domain, int type, int protocol) {
  if((domain == AF_INET)  &&
     (type == SOCK_DGRAM) &&
     (protocol == 0)) {
    int i, found = -1, fd = 0;
    pthread_mutex_lock(&sockets_mutex);
    if (n_sockets == 0) {
      if (dnastack_init())
	return -1;
    }
    for(i=0; i<MAX_NUM_SOCKETS; i++) {
      if(sockets[i] == NULL) {
	found = i;
	break;
      }
    }
    fd = -1;
    if (found >= 0) {
      if ((sockets[found] = dnasocket_open())) {
	fd = INT_MAX - found;
	n_sockets++;
      } else {
	errno = ENOMEM;
	if (n_sockets == 0)
	  dnastack_kill();
      }
    } else {
      errno = ENFILE;
    }
    pthread_mutex_unlock(&sockets_mutex);
    return fd;
  } else {
    if (!real_socket)
      get_dlsym((void **) &real_socket, "socket");
    return real_socket(domain, type, protocol);
  }
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen) {
  if (INT_MAX - MAX_NUM_SOCKETS >= sockfd) {
    if (!real_sendto)
      get_dlsym((void **) &real_sendto, "sendto");
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
  } else {
    DnaSocket *skt;
    if (addrlen != sizeof(struct sockaddr_in) || dest_addr->sa_family != AF_INET) {
      errno = EINVAL;
      return -1;
    }
    skt = sockets[INT_MAX - sockfd];
    if (skt)
      return dnasocket_sendto(buf, len, flags, (struct sockaddr_in *) dest_addr, skt);
    errno = EBADF;
    return -1;
  }
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen) {
  if (INT_MAX - MAX_NUM_SOCKETS >= sockfd) {
    if (!real_recvfrom)
      get_dlsym((void **) &real_recvfrom, "recvfrom");
    return real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
  } else {
    DnaSocket *skt;
    if (*addrlen != sizeof(struct sockaddr_in)) {
      errno = EINVAL;
      return -1;
    }
    skt = sockets[INT_MAX - sockfd];
    if (skt) {
      *addrlen = sizeof(struct sockaddr_in);
      return dnasocket_recvfrom(buf, len, flags, (struct sockaddr_in *) src_addr, skt);
    }
    errno = EBADF;
    return -1;
  }
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  if (INT_MAX - MAX_NUM_SOCKETS >= sockfd) {
    if (!real_bind)
      get_dlsym((void **) &real_bind, "bind");
    return real_bind(sockfd, addr, addrlen);
  } else {
    DnaSocket *skt;
    int ret = -1;
    pthread_mutex_lock(&sockets_mutex);
    if (addrlen < sizeof(struct sockaddr_in) || addr->sa_family != AF_INET) {
      errno = EINVAL;
    } else if (addrlen > sizeof(struct sockaddr_in)) {
      errno = ENAMETOOLONG;
    } else {
      skt = sockets[INT_MAX - sockfd];
      if (skt)
	ret = dnasocket_bind((struct sockaddr_in *) addr, skt);
      else
	errno = EBADF;
    }
    pthread_mutex_unlock(&sockets_mutex);
    return ret;
  }
}

int close(int fd) {
  if (INT_MAX - MAX_NUM_SOCKETS >= fd) {
    if (!real_close)
      get_dlsym((void **) &real_close, "close");
    return real_close(fd);
  } else {
    int retval = -1;
    DnaSocket *skt;
    pthread_mutex_lock(&sockets_mutex);
    skt = sockets[INT_MAX - fd];
    if (skt) {
      sockets[INT_MAX - fd] = NULL;
      retval = dnasocket_close(skt);
      if (--n_sockets == 0)
	dnastack_kill();
    } else
      errno = EBADF;
    pthread_mutex_unlock(&sockets_mutex);
    return retval;
  }
}
