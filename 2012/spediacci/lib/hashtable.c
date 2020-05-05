#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "hashtable.h"

typedef struct __list_t {
  const void **e;
  u_int n;
  u_int size;
} list_t;

struct __HashTable {
  u_int nelems;
  int (*cmp)(const void *, const void *);
  u_int (*hash)(const void *, u_int n);
  list_t *lists;
  u_int nlists;
};

Hashtable_t *hashtable_new(u_int nelems,
			   int (*cmp)(const void *, const void *),
			   u_int (*hash)(const void *, u_int)) {
  Hashtable_t *h = malloc(sizeof(Hashtable_t));
  if (h == NULL) return NULL;
  h->nlists = nelems;
  h->lists = calloc(h->nlists, sizeof(list_t));
  if (!h->lists) {
    free(h);
    return NULL;
  }
  memset(h->lists, 0, sizeof(list_t) * h->nlists);
  h->nelems = 0;
  h->cmp = cmp;
  h->hash = hash;
  return h;
}

void hashtable_free(Hashtable_t *h, void (*free_el)(void *)) {
  if (h->lists != NULL) {
    u_int a;
    list_t *l;
    for (a = 0, l = h->lists; a < h->nlists; a++, l++) {
      if (l->size == 0) {
	if (l->e)
	  free_el((void *) l->e);
      } else {
	u_int b;
	const void **e;
	for (b = 0, e = l->e; b < l->n; b++, e++) {
	  free_el((void *) *e);
	}
	free(l->e);
      }
    }
    free(h->lists);
  }
  free(h);
}

const void **list_get(Hashtable_t *h, list_t *l, const void *k) {
  u_int a;
  if (l->size == 0) {
    if(l->e &&
       h->cmp(k, (void *) l->e) == 0)
      return (const void **) &l->e;
  } else {
    const void **e;
    for (a = 0, e = l->e; a < l->n; a++, e++) {
      if (h->cmp(k, *e) == 0)
	return e;
    }					
  }
  return NULL;
}

const void *hashtable_get(Hashtable_t *h, const void *k) {
  list_t *l = &h->lists[h->hash(k, h->nlists)];
  const void **e = list_get(h, l, k);
  return e ? *e : NULL;
}

int hashtable_put(Hashtable_t *h,
		  const void *new,
		  const void **old) {
  list_t *l = &h->lists[h->hash(new, h->nlists)];
  const void **e = list_get(h, l, new);
  if (e) {
    *old = *e;
    *e = new;
    return 1;
  }
  if (l->size == 0 &&
      !l->e)
    l->e = (const void **) new;
  else {
    if (l->n == l->size) {
      if (l->size) {
	u_int nsize = l->size << 1;
	const void **r = realloc(l->e, nsize * sizeof(void *));
	if (!r) {
	  errno = ENOMEM;
	  return -1;
	}
	l->e = r;
	l->size = nsize;
      } else {
	u_int nsize = 2;
	void *p = (void *) l->e;
	l->e = calloc(nsize, sizeof(void *));
	if (!l->e) {
	  errno = ENOMEM;
	  return -1;
	}
	l->size = nsize;
	l->e[0] = p;
	l->n = 1;
      }
    }
    l->e[l->n++] = new;
  }
  h->nelems++;
  return 0;
}

void *hashtable_pop(Hashtable_t *h, const void *k) {
  list_t *l = &h->lists[h->hash(k, h->nlists)];
  const void **e = list_get(h, l, k);
  if (e) {
    const void *r = *e;
    if (l->size) {
      const void **e2 = l->e;
      u_int a;
      for (a=0; e != e2; a++, e2++)
	;
      l->n--;
      for (; a < l->n; a++)
	l->e[a] = l->e[a + 1];
    } else {
      l->e = NULL;
    }
    h->nelems--;
    return (void *) r;
  }
  return NULL;
}

u_int hashtable_remove(Hashtable_t *h, int (*match)(void *, void *), void *obj) {
  u_int remain = h->nelems;
  u_int a;
  list_t *l;
  u_int removed;
  for (a = 0, l = h->lists; a < h->nlists && remain > 0; a++, l++) {
    if (l->size == 0) {
      if (l->e) {
	if (match((void *) l->e, obj)) {
	  l->e = NULL;
	  remain--;
	}
      }
    } else if (l->n) {
      u_int b;
      for (b = l->n - 1; remain > 0; b--) {
	if (match((void *) l->e[b], obj)) {
	  u_int c;
	  l->n--;
	  remain--;
	  for (c = b; c < l->n; c++) {
	    l->e[c] = l->e[c + 1];
	  }
	}
	if (b == 0)
	  break;
      }
    }
  }
  removed = h->nelems - remain;
  h->nelems = remain;
  return removed;
}

void hashtable_map(Hashtable_t *h,
		   void (*map)(const void *, const void *),
		   const void *obj) {
  u_int a;
  list_t *l;
  u_int remain = h->nelems;
  for (a = 0, l = h->lists; a < h->nlists && remain > 0; a++, l++) {
    if (l->size == 0) {
      if (l->e) {
	map((void *) l->e, obj);
	remain--;
      }
    } else {
      u_int b;
      const void **e;
      for (b = 0, e = l->e; b < l->n; b++, e++)
	map(*e, obj);
      remain -= l->n;
    }
  }
}

u_int hashtable_count(Hashtable_t *h) {
  return h->nelems;
}
