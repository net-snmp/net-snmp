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
   void           *data;
   struct sl_node *next;
} sl_node;

typedef struct binary_array_table_s {
   size_t                     count;      /* Index of the next free entry */
   sl_node                   *head;       /* head of list */
} sl_table;


static sl_table *
_ssll_initialize(void)
{
    sl_table *t;

    t = SNMP_MALLOC_TYPEDEF(sl_table);
    if (t == NULL)
        return NULL;

    return t;
}

static void
_ssll_free(netsnmp_container *c)
{
    if(c) {
        if(c->private)
            free(c->private);
        free(c);
    }
}

static void *
_ssll_get(netsnmp_container *c, const void *key, int exact)
{
    sl_table *t = (sl_table*)c->private;
    sl_node  *curr;
    
    if (NULL == key) {
        if(exact || (NULL==t->head))
            return NULL;;

        return t->head->data;
    }
    
    if (NULL == (curr = t->head))
        return NULL;

    while (curr) {
        if (c->compare(curr->data, key) == 0)
            break;
        curr = curr->next;
    }

    if((curr) && (!exact)) {
        curr = curr->next;
    }

    return curr ? curr->data : NULL;
}

static void *
_ssll_find(netsnmp_container *c, const void *data)
{
    if((NULL == c) || (NULL == c->private))
        return NULL;

    return _ssll_get(c, data, data ? 1 : 0);
}

static void *
_ssll_find_next(netsnmp_container *c, const void *data)
{
    if((NULL == c) || (NULL == c->private))
        return NULL;

    return _ssll_get(c, data, 0);
}

static int
_ssll_insert(netsnmp_container *c, const void *data)
{
    sl_table *t;
    sl_node  *new_node;
    
    if((NULL == c) || (NULL == c->private))
        return -1;

    t = (sl_table*)c->private;
    new_node = SNMP_MALLOC_TYPEDEF(sl_node);
    if(NULL == new_node)
        return -1;
    new_node->data = (void*)data;
    
    if(NULL == t->head) {
        t->head = new_node;
    }
    else {
        sl_node *curr = t->head, *last = NULL;
        for( ; curr; last = curr, curr = curr->next) {
            if(c->compare(curr->data, data) > 0)
                break;
        }
        if(NULL == last) {
            new_node->next = t->head;
            t->head = new_node;
        }
        else {
            new_node->next = last->next;
            last->next = new_node;
        }
    }
    ++t->count;
    return 0;
}

static int
_ssll_remove(netsnmp_container *c, const void *data)
{
    sl_table *t;
    sl_node  *curr;
    
    if((NULL == c) || (NULL == c->private))
        return 0;

    t = (sl_table*)c->private;
    if(NULL == t->head)
        return -1;

    if(c->compare(t->head->data, data) == 0) {
        curr = t->head;
        t->head = t->head->next;
    }
    else {
        sl_node *last = t->head;
        for(curr = t->head->next ; curr; last = curr, curr = curr->next)
            if(c->compare(curr->data, data) == 0) {
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
    --t->count;
    
    return 0;
}

static size_t
_ssll_size(netsnmp_container *c)
{
    sl_table *t;
    
    if((NULL == c) || (NULL == c->private))
        return 0;

    t = (sl_table*)c->private;

    /*
     * return count
     */
    return t->count;
}

static void
_ssll_for_each(netsnmp_container *c, netsnmp_container_obj_func *f,
             void *context)
{
    sl_table *t;
    sl_node  *curr;
    
    if((NULL == c) || (NULL == c->private))
        return;

    t = (sl_table*)c->private;
    
    for(curr = t->head; curr; curr = curr->next)
        (*f) (curr->data, context);
}

int
netsnmp_container_get_ssll_noalloc(netsnmp_container *c)
{
    if (NULL==c)
        return -1;
    
    c->private = _ssll_initialize();
    c->cfree = (netsnmp_container_rc*)_ssll_free;
        
    c->get_size = _ssll_size;
    c->init = NULL;
    c->insert = _ssll_insert;
    c->remove = _ssll_remove;
    c->find = _ssll_find;
    c->find_next = _ssll_find_next;
    c->get_subset = NULL;
    c->get_iterator = NULL;
    c->for_each = _ssll_for_each;

    return 0;
}

netsnmp_container *
netsnmp_container_get_sorted_singly_linked_list(void)
{
    /*
     * allocate memory
     */
    netsnmp_container *c = SNMP_MALLOC_TYPEDEF(netsnmp_container);
    if (NULL==c) {
        snmp_log(LOG_ERR, "couldn't allocate memory\n");
        return NULL;
    }

    if (0 != netsnmp_container_get_ssll_noalloc(c)) {
        free(c);
        return NULL;
    }
        
    return c;
}

netsnmp_factory *
netsnmp_container_get_ssll_factory(void)
{
    static netsnmp_factory f = {"sorted_singly_linked_list",
                                (netsnmp_factory_produce_f*)
                                netsnmp_container_get_sorted_singly_linked_list,
                                (netsnmp_factory_produce_noalloc_f*)
                                netsnmp_container_get_ssll_noalloc };
    
    return &f;
}

void
netsnmp_container_ssll_init(void)
{
    netsnmp_container_register("sorted_singly_linked_list",
                               netsnmp_container_get_ssll_factory());
}
