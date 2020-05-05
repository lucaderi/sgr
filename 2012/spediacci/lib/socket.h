#pragma once

extern int socket(int domain, int type, int protocol);
extern ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen);
extern ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen);
extern int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int close(int fd);
