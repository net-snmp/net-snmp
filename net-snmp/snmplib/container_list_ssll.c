/*
 * container_list_sl.c
 * $Id$
 *
 */

#include <net-snmp/net-snmp-config.h>

#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <sys/types.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/types.h>
#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/snmp_assert.h>

#include <net-snmp/library/container_list_ssll.h>

typedef struct sl_node {
   const void     *data;
   struct sl_node *next;
} sl_node;

typedef struct sl_container_s {
   netsnmp_container          c;
   
   size_t                     count;      /* Index of the next free entry */
   sl_node                   *head;       /* head of list */
} sl_container;


static void *
_get(netsnmp_container *c, const void *key, int exact)
{
    sl_container *sl = (sl_container*)c;
    sl_node  *curr = sl->head;
    
    if( (NULL != curr) && (NULL != key)) {
        while (curr) {
            if (sl->c.compare(curr->data, key) == 0)
                break;
            curr = curr->next;
        }
        
        if((curr) && (!exact)) {
            curr = curr->next;
        }
    }

    return curr ? (void *)curr->data : NULL;
}

/**********************************************************************
 *
 *
 *
 **********************************************************************/
static void
_ssll_free(netsnmp_container *c)
{
    if(c) {
        free(c);
    }
}

static void *
_ssll_find(netsnmp_container *c, const void *data)
{
    if((NULL == c) || (NULL == data))
        return NULL;

    return _get(c, data, 1);
}

static void *
_ssll_find_next(netsnmp_container *c, const void *data)
{
    if(NULL == c)
        return NULL;

    return _get(c, data, 0);
}

static int
_ssll_insert(netsnmp_container *c, const void *data)
{
    sl_container *sl = (sl_container*)c;
    sl_node  *new_node;
    
    if(NULL == c)
        return -1;

    new_node = SNMP_MALLOC_TYPEDEF(sl_node);
    if(NULL == new_node)
        return -1;
    new_node->data = data;
    
    if(NULL == sl->head) {
        sl->head = new_node;
    }
    else {
        sl_node *curr = sl->head, *last = NULL;
        for( ; curr; last = curr, curr = curr->next) {
            if(sl->c.compare(curr->data, data) > 0)
                break;
        }
        if(NULL == last) {
            new_node->next = sl->head;
            sl->head = new_node;
        }
        else {
            new_node->next = last->next;
            last->next = new_node;
        }
    }
    ++sl->count;
    return 0;
}

static int
_ssll_remove(netsnmp_container *c, const void *data)
{
    sl_container *sl = (sl_container*)c;
    sl_node  *curr = sl->head;
    
    if((NULL == c) || (NULL == curr))
        return -1;

    if(sl->c.compare(sl->head->data, data) == 0) {
        curr = sl->head;
        sl->head = sl->head->next;
    }
    else {
        sl_node *last = sl->head;
        for(curr = sl->head->next ; curr; last = curr, curr = curr->next)
            if(sl->c.compare(curr->data, data) == 0) {
                last->next = curr->next;
                break;
            }
    }

    if(NULL == curr)
        return -2;
    
    /*
     * free our node structure, but not the data
     */
    free(curr);
    --sl->count;
    
    return 0;
}

static size_t
_ssll_size(netsnmp_container *c)
{
    sl_container *sl = (sl_container*)c;
    
    if(NULL == c)
        return 0;

    return sl->count;
}

static void
_ssll_for_each(netsnmp_container *c, netsnmp_container_obj_func *f,
             void *context)
{
    sl_container *sl = (sl_container*)c;
    sl_node  *curr;
    
    if(NULL == c)
        return;
    
    for(curr = sl->head; curr; curr = curr->next)
        (*f) ((void *)curr->data, context);
}

/**********************************************************************
 *
 *
 *
 **********************************************************************/
netsnmp_container *
netsnmp_container_get_ssll(void)
{
    /*
     * allocate memory
     */
    sl_container *sl = SNMP_MALLOC_TYPEDEF(sl_container);
    if (NULL==sl) {
        snmp_log(LOG_ERR, "couldn't allocate memory\n");
        return NULL;
    }

    sl->c.cfree = (netsnmp_container_rc*)_ssll_free;
        
    sl->c.get_size = _ssll_size;
    sl->c.init = NULL;
    sl->c.insert = _ssll_insert;
    sl->c.remove = _ssll_remove;
    sl->c.find = _ssll_find;
    sl->c.find_next = _ssll_find_next;
    sl->c.get_subset = NULL;
    sl->c.get_iterator = NULL;
    sl->c.for_each = _ssll_for_each;

       
    return (netsnmp_container*)sl;
}

netsnmp_factory *
netsnmp_container_get_ssll_factory(void)
{
    static netsnmp_factory f = {"sorted_singly_linked_list",
                                (netsnmp_factory_produce_f*)
                                netsnmp_container_get_ssll };
    
    return &f;
}

void
netsnmp_container_ssll_init(void)
{
    netsnmp_container_register("sorted_singly_linked_list",
                               netsnmp_container_get_ssll_factory());
}
