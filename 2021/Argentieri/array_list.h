//
// Created by elia on 2021/07/27.
//

#ifndef ANOMALYDETECT_ARRAY_LIST_H
#define ANOMALYDETECT_ARRAY_LIST_H

struct array_list {
    void **data;
    unsigned int allocated;
    unsigned int length;
};

typedef struct array_list ArrayList;

void array_list_init(ArrayList *list);

void array_list_add(ArrayList *list, void *element);

void array_list_copy_add(ArrayList *list, void *element, size_t size);

void* array_list_get(ArrayList *list, unsigned int index);

void* array_list_get_last(ArrayList *list);

void array_list_free(ArrayList *list);



#endif //ANOMALYDETECT_ARRAY_LIST_H
