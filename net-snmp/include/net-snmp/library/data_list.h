/*
 * data_list.h
 *
 * $Id$
 *
 * External definitions for functions and variables in data_list.c.
 */

#ifndef DATA_LIST_H
#define DATA_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "snmp_impl.h"
#include "tools.h"


typedef void (Free_List_Data)(void *);

typedef struct data_list_s {
   struct data_list_s *next;
   char *name;
   void *data;                     /* The pointer to the data passed on. */
   Free_List_Data *free_func;     /* must know how to free data_list->data */
} data_list;


inline data_list *create_data_list(const char *, void *,
                                   Free_List_Data *);
void add_list_data(data_list **head, data_list *node);
void *get_list_data(data_list *head, const char *node);
void free_list_data(data_list *head);  /* single */
void free_all_list_data(data_list *head); /* multiple */
    

#ifdef __cplusplus
}
#endif


#endif
