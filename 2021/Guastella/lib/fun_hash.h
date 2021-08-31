#include <stdlib.h>
/*
    @brief : from k take the corresponding hash value (of two different hash function), applicate the modulo operation and put it in a and b
    @param : key = string from which extract the value
    @param : a = result of the value of first hash function
    @param : b = result of the second hash function
    @param : depth = value of modulo operation
    
    @effect: modify the value of a and b

*/
void hash_function(const char* key, u_int32_t depth, u_int32_t *a, u_int32_t *b );

/*
    @brief: hash function where the seed are *a, *b, i and the upper bound value is depth

 */
u_int32_t hash_increment(u_int32_t depth, u_int32_t *a, u_int32_t *b, int i);