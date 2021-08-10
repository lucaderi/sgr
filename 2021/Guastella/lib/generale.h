#if !defined(GENERALE_H)
#define GENERALE_H

#define BUF_FGETS 60

#define CHECK_EQ(x, val,str)\
    if((x) == val){\
          perror(str); \
         fprintf(stderr,"Error at line %d of file %s\n", __LINE__, __FILE__);\
         exit(EXIT_FAILURE);\
}


void hash_function(const char* key, unsigned int depth, unsigned int *a, unsigned int *b );





#endif
