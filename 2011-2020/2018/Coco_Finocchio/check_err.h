/* File contenente macro utili per la gestione degli errori */

#define CHECK_ALLOC(var,foo,err) if((var=foo) == NULL) { fprintf(stderr,err); return -1; }
#define CHECK_T_ALLOC(var,foo,err) if((var=foo) == NULL) { fprintf(stderr,err); pthread_exit((void*)-1); }

#define CHECK_MENO1(var,foo,err) if((var=foo) == -1) { fprintf(stderr,err); return -1; }
#define CHECK_T_MENO1(var,foo,err) if((var=foo) == -1) { fprintf(stderr,err); pthread_exit((void*)-1); }

#define CHECK_NULL(var,foo,err) if((var=foo) == NULL) { fprintf(stderr,err); return -1; }

#define CHECK_OVER0(foo,err) if((foo) > 0) { fprintf(stderr,err); return -1; }

