#include <config.h>
#include <sys/types.h>
#include <stdlib.h>

#if HAVE_STRING_H
#include <string.h>
#endif

#include "data_list.h"

/***********************************************************************/
/* New Handler based API */
/***********************************************************************/
inline data_list *
create_data_list(const char *name, void *data,
                         Free_List_Data *beer)
{
    data_list *node = SNMP_MALLOC_TYPEDEF(data_list);
    if (!node)
        return NULL;
    node->name = strdup(name);
    node->data = data;
    node->free_func = beer;
    return node;
}
   
    
inline void
add_list_data(data_list **head, data_list *node) 
{
    data_list *ptr;
    if (!*head) {
        *head = node;
        return;
    }

    /* xxx-rks: check for duplicate names? */
    for(ptr = *head; ptr->next != NULL; ptr = ptr->next) {
        /* noop */
    }

    if (ptr) /* should always be true */
        ptr->next = node;
}

inline void *
get_list_data(data_list *head, const char *name)
{
  for(; head; head = head->next)
    if (head->name && strcmp(head->name, name) == 0)
      break;
  if (head)
    return head->data;
  return NULL;
}

inline void
free_list_data(data_list *node)
{
  Free_List_Data *beer;
  if (!node)
    return;

  beer = node->free_func;
  if (beer)
    (beer)(node->data);
  SNMP_FREE(node->name);
}

inline void
free_all_list_data(data_list *head) 
{
    data_list *tmpptr;
    for(; head; ) {
        free_list_data(head);
        tmpptr = head;
        head = head->next;
        SNMP_FREE(tmpptr);
    }
}

