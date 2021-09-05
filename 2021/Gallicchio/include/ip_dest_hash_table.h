#ifndef IP_DEST_HASH_TABLE_H
#define IP_DEST_HASH_TABLE_H

#include <roaring.h>

// Ogni elemento/nodo all'interno della tabella hash è definito da una chiave src_ip
// e un insieme di valori destinations.
// I byte degli indirizzi IP sono ordinati secondo il Network Byte Order.
struct ip_dest_hash_table_node {
    u_int32_t src_ip;
    roaring_bitmap_t* destinations;
    struct ip_dest_hash_table_node* next;
};

// La tabella hash
struct ip_dest_hash_table {
    // Dimensione della tabella
    size_t size;
    // Numero degli elementi presenti nella tabella
    unsigned int elem;
    // La tabella (vettore)
    struct ip_dest_hash_table_node** table;
};

/**
 * \brief Restituisce una nuova tabella hash di dimensione size.
 *
 * \return Una nuova tabella hash di dimensione size,
 *         NULL se non è stato possibile allocare la memoria.
 */
struct ip_dest_hash_table* ip_dest_hash_table_new(size_t size);

/**
 * \brief Libera dalla memoria hash_table e tutti gli elementi contenuti in essa.
 */
void ip_dest_hash_table_free(struct ip_dest_hash_table* hash_table);

/**
 * \brief Se la chiave src_ip è già presente nella tabella hash_table, allora
 *        viene aggiunto il valore dest_ip alla bitmap compressa.
 *        Altrimenti, aggiunge un nuovo elemento nella tabella con chiave src_ip
 *        e univo valore dest_ip all'interno della bitmap compressa.
 *
 * \return 0 in caso di successo,
 *         -1 se hash_table == NULL,
 *         -2 se non è stato possibile allocare la memoria.
 */
int ip_dest_hash_table_insert(struct ip_dest_hash_table* hash_table, u_int32_t src_ip, u_int32_t dest_ip);

/**
 * \brief Salva in *arr un vettore di dimensione arr_size con tutti gli elementi di hash_table.
 *        Qualsiasi modifica agli elementi contenuti nel vettore può compromettere il corretto funzionamento di hash_table.
 *        Usare free su *arr per liberare la memoria.
 *
 * \return 0 in caso di successo,
 *         -1 se hash_table == NULL || arr == NULL || arr_size == NULL
 *         -2 se non è stato possibile allocare la memoria.
 */
int ip_dest_hash_table_get_array(struct ip_dest_hash_table* hash_table, struct ip_dest_hash_table_node*** arr, size_t* arr_size);

/**
 * \brief Rimuove tutti gli elementi presenti nella tabella hash_table.
 *        Se doBeforeCompletion != NULL, allora esegue questa funzione passandole come argomento
 *        ogni elemento presente nella tabella prima di rimuoverlo.
 */
void ip_dest_hash_table_deleteAll(struct ip_dest_hash_table* hash_table, void (*doBeforeCompletion) (struct ip_dest_hash_table_node* node));

#endif
