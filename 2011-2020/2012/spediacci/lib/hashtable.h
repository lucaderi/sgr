#pragma once
struct __HashTable;
typedef struct __HashTable Hashtable_t;

extern Hashtable_t *hashtable_new(u_int nelems,
			   int (*cmp)(const void *, const void *),
			   u_int (*hash)(const void *, u_int));

extern void hashtable_free(Hashtable_t *h, void (*free_el)(void *));

extern const void *hashtable_get(Hashtable_t *h, const void *k);

extern int hashtable_put(Hashtable_t *h,
		  const void *new,
		  const void **old);

extern void *hashtable_pop(Hashtable_t *h, const void *k);

extern u_int hashtable_remove(Hashtable_t *h,
			      int (*match)(void *, void *),
			      void *obj);

extern void hashtable_map(Hashtable_t *h,
			  void (*map)(const void *, const void *),
			  const void *obj);

extern u_int hashtable_count(Hashtable_t *h);
