#ifndef WRAPPERS_H
#define WRAPPERS_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

void *xmalloc(size_t size);
int xfork(void);
void xexecvp(const char *file, char *const argv[]);

#endif