//
// Semplice implementazione di una lista usando reallocarray.
// Vengono allocati 8 puntatori a void e poi vengono raddoppiati ogni volta che non c'è più spazio
//

#include <stdlib.h>
#include <string.h>
#include "array_list.h"

void array_list_init(ArrayList *list) {
    list->data = calloc(8, sizeof(void *));
    list->allocated = 8;
    list->length = 0;
}

void array_list_add(ArrayList *list, void *element) {
    if (list->length >= list->allocated) {
        void *re = reallocarray(list->data, list->allocated * 2, sizeof(void *));
        if (re == NULL)
            return;
        list->data = re;
        // azzero i nuovi puntatori
        memset(&list->data[list->allocated], 0, sizeof(void *) * list->allocated);
        list->allocated *= 2;
    }
    list->data[list->length] = element;
    list->length++;
}

void array_list_copy_add(ArrayList *list, void *element, size_t size) {
    void *copy = malloc(size);
    memcpy(copy, element, size);
    array_list_add(list, copy);
}

void *array_list_get(ArrayList *list, unsigned int index) {
    if (index >= list->allocated)
        return NULL;
    return list->data[index];
}

void *array_list_get_last(ArrayList *list) {
    if (list->length == 0)
        return NULL;
    return list->data[list->length - 1];
}

void array_list_free(ArrayList *list) {
    for (int i = 0; i < list->length; i++)
        free(list->data[i]);
    free(list->data);
    list->allocated = 0;
}
