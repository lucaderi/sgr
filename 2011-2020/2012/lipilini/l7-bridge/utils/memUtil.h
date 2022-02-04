#ifndef _MEMUTIL_H_
#define _MEMUTIL_H_

#include <cstdlib>

void * calloc_wrapper(unsigned long size);

void free_wrapper(void * freeable);

#endif // _MEMUTIL_H_
