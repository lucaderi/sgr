
typedef struct {
    u_int32_t c, r;        //c=columns, r= row
    u_int32_t **t;         //matrix
} cmsketch_t;

cmsketch_t* new_count_min_sketch(u_int32_t c, u_int32_t r);
void free_count_min_sketch(cmsketch_t* table);
void add_min_count_sketch(cmsketch_t* table, char *str);
u_int32_t read_count_min_sketch(cmsketch_t * table, char *str);
cmsketch_t* sum_count_min_sketch(cmsketch_t * table1, cmsketch_t * table2);
cmsketch_t* clone_count_min_sketch(cmsketch_t * table);
u_int32_t * riga_count_min_sketch(cmsketch_t* table, char* str);


void print_table(cmsketch_t* table);
