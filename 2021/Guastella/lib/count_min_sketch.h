   /*
    Implementation of a Count Min Sketch and a set of function to manage it
    */



/*Data Struct that implement a Count Min Sketch
  variable:
        -t represent the table with a matrix,
        -c are the columns of t
        -r row of t */
typedef struct {
    u_int32_t c, r;        
    u_int32_t **t;         
} cmsketch_t;


/*
  @brief   : create a new data struct with r row and c columns
  @param   : r  = row of the matrix of new cmsketch_t
  @param   : c  = columns of the matrix
  @return  : new cmsketch_t
  */
cmsketch_t* new_count_min_sketch(u_int32_t c, u_int32_t r);


/*
  @brief : free the memory pointed by a cmsketch_t
  @param : table = the cmsketch_t to free
  */
void free_count_min_sketch(cmsketch_t* table);


/*
  @brief : add a count of a string in a cmsketch_t
  @param : table = cmskestch_t to which the string is added
  @param : str = string to add
  */
void add_min_count_sketch(cmsketch_t* table, char *str);


/*
  @brief  : read the value in a cmsketch_t, associated with a string
  @param  : table = cmsketch_t to read
  @param  : str = string to search for
  @return : value associated with str in table
  */
u_int32_t read_count_min_sketch(cmsketch_t * table, char *str);


/*
  @brief : create a new cmsketch_t that is the sum of two cmsketch_t
  @param : table1 & table2 = cmsketch_t to sum
  @return: new cmsketch_t which is the sum of table1 and table2
  */
cmsketch_t* sum_count_min_sketch(cmsketch_t * table1, cmsketch_t * table2);


/*
  @brief : return a copy of the parameter
  */
cmsketch_t* clone_count_min_sketch(cmsketch_t * table);


/*
  @brief  :  return the value associated with a string for each columns
  @param  :  table = cmsketch_t to read
  @param  :  str = string to search in
  @return :  array of lenght table->c (number of columns),
               with the value of position i is the value associated with str in column i
  */
u_int32_t * riga_count_min_sketch(cmsketch_t* table, char* str);


/*
    @brief : print the matrix of cmsketch
    @param : table = the data struct to print
   */
void print_table(cmsketch_t* table);
