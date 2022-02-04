#ifndef __LIST_H__
#define __LIST_H__

#define LIST_PREPEND(head, el, type, field) \
    do { \
        (el)->field = (head); \
        (head) = (el); \
    } while (0);

#define LIST_DELETE(head, el, type, field) \
    do { \
        if ((head) != NULL) { \
            type* prec = NULL; \
            type* curr = head; \
            while (curr != NULL) { \
                if (curr == el) { \
                    if (prec != NULL) { \
                        prec->field = curr->field; \
                    } else { \
                        (head) = curr->field; \
                    } \
                    curr->field = NULL; \
                    break; \
                } \
                prec = curr; \
                curr = curr->field; \
            } \
        } \
    } while (0);

#define LIST_ITERATE(head, el, type, field) \
    for ( \
        type *el = (head), *__next_el = ((head) ? (head)->field : NULL); \
        el != NULL; \
        el = __next_el, __next_el = el == NULL ? NULL : el->field \
    )

#endif