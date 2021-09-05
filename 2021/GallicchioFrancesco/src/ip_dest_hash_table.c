#include <stdlib.h>
#include <stdio.h>

#include <ip_dest_hash_table.h>

/**
 * \brief Funzione hash che, data una chiave key, restituisce l'indice all'interno
 *        della tabella di dimensione size.
 *
 * \return L'indice all'interno della tabella.
 */
static inline unsigned int hash_function(size_t size, u_int32_t key);

static inline unsigned int hash_function(size_t size, u_int32_t key) {
    return key%size;
}

struct ip_dest_hash_table* ip_dest_hash_table_new(size_t size) {
    struct ip_dest_hash_table* hash_table;
    if((hash_table = malloc(sizeof(struct ip_dest_hash_table))) != NULL) {
        hash_table->size = size;
        hash_table->elem = 0;
        if((hash_table->table = malloc(sizeof(struct ip_dest_hash_table_node*)*size)) != NULL) {
            for(int i = 0; i < size; i++) {
                (hash_table->table)[i] = NULL;
            }
            return hash_table;
        } else {
            free(hash_table);
            return NULL;
        }
    }
    return NULL;
}

void ip_dest_hash_table_free(struct ip_dest_hash_table* hash_table) {
    if(hash_table == NULL) return;
    
    ip_dest_hash_table_deleteAll(hash_table, NULL);
    
    free(hash_table->table);
    free(hash_table);
}

int ip_dest_hash_table_insert(struct ip_dest_hash_table* hash_table, u_int32_t src_ip, u_int32_t dest_ip) {
    if(hash_table == NULL) return -1;
    unsigned int index = hash_function(hash_table->size, src_ip);
    struct ip_dest_hash_table_node* prev = NULL;
    struct ip_dest_hash_table_node* node = (hash_table->table)[index];
    while(node != NULL) {
        if(node->src_ip == src_ip) break;
        prev = node;
        node = node->next;
    }
    if(node == NULL) {
        struct ip_dest_hash_table_node* new_node;
        if((new_node = malloc(sizeof(struct ip_dest_hash_table_node))) == NULL) return -2;
        new_node->src_ip = src_ip;
        new_node->destinations = roaring_bitmap_of(1, dest_ip);
        new_node->next = NULL;
        if(prev == NULL) {
            (hash_table->table)[index] = new_node;
        } else {
            prev->next = new_node;
        }
        hash_table->elem++;
    } else {
        roaring_bitmap_add(node->destinations, dest_ip);
    }
    
    return 0;
}

int ip_dest_hash_table_get_array(struct ip_dest_hash_table* hash_table, struct ip_dest_hash_table_node*** arr, size_t* arr_size) {
    if(hash_table == NULL || arr == NULL || arr_size == NULL) return -1;
    if((*arr = malloc(sizeof(struct ip_dest_hash_table_node*)*hash_table->elem)) == NULL) return -2;
    
    int arr_index = 0;
    int i = 0;
    while(arr_index != hash_table->elem) {
        struct ip_dest_hash_table_node* node = (hash_table->table)[i];
        while(node != NULL) {
            (*arr)[arr_index++] = node;
            node = node->next;
        }
        i++;
    }
    *arr_size = hash_table->elem;
    
    return 0;
}

void ip_dest_hash_table_deleteAll(struct ip_dest_hash_table* hash_table, void (*doBeforeCompletion) (struct ip_dest_hash_table_node* node)) {
    if(hash_table == NULL) return;
    int i = 0;
    while(hash_table->elem != 0) {
        struct ip_dest_hash_table_node* prev = NULL;
        struct ip_dest_hash_table_node* node = (hash_table->table)[i];
        while(node != NULL) {
            if(doBeforeCompletion != NULL) doBeforeCompletion(node);
            prev = node;
            node = node->next;
            roaring_bitmap_free(prev->destinations);
            free(prev);
            hash_table->elem--;
        }
        (hash_table->table)[i++] = NULL;
    }
}
