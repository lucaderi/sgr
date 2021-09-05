#if !defined(GENERALE_H)
#define GENERALE_H

#define RIGHE 101
#define COLONNE 47
#define SMALLR 5
#define SMALLC 3
#define SMALLES1 "./Test/small_es_1.txt"
#define SMALLRIS1 "./Test/small_ris_1.txt"
#define SMALLES2 "./Test/small_es_2.txt"
#define ES1 "./Test/es_primo.txt"
#define RIS1 "./Test/ris_primo.txt"
#define ES2 "./Test/es_secondo.txt"
#define RIS2 "./Test/ris_secondo.txt"
#define BUF_FGETS 60

#define CHECK_EQ(x, val,str)\
    if((x) == val){\
          perror(str); \
         fprintf(stderr,"Error at line %d of file %s\n", __LINE__, __FILE__);\
         exit(EXIT_FAILURE);\
}



#endif
