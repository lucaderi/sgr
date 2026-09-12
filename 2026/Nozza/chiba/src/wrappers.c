#include "wrappers.h"

void *xmalloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "malloc error: %s\n", strerror(errno));    
    }
    return ptr;
}

int xfork(void) {
    int pid = fork();
    if (pid == -1) {
        fprintf(stderr, "fork error: %s\n", strerror(errno));
    }
    return pid;
}

/* Implemented safe child process termination */
void xexecvp(const char *file, char *const argv[]) {
    if (execvp(file, argv) == -1) {
        fprintf(stderr, "execvp error: %s\n", strerror(errno));
        _exit(EXIT_FAILURE);
    }
}