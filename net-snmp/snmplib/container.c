#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/container_binary_array.h>
#include <net-snmp/library/container_list_ssll.h>
#include <net-snmp/library/container_null.h>

/*------------------------------------------------------------------
 */
static netsnmp_container *containers = NULL;

typedef struct container_type_s {
   const char                 *name;
   netsnmp_factory            *factory;
} container_type;

netsnmp_factory *
netsnmp_container_get_factory(const char *type);

/*------------------------------------------------------------------
 */
static void 
_factory_free(void *dat, void *context)
{
    container_type *data = (container_type *)dat;
    if (data == NULL)
	return;
    
    if (data->name != NULL) {
        DEBUGMSGTL(("container", "  _factory_free_list() called for %s\n",
                    data->name));
	free((const void*)data->name); /* SNMP_FREE wasted on object about to be freed */
    }
    free(data); /* SNMP_FREE wasted on param */
}

/*------------------------------------------------------------------
 */
void
netsnmp_container_init_list(void)
{
    if (NULL != containers)
        return;

    /*
     * create a binary arry container to hold container
     * factories
     */
    containers = netsnmp_container_get_binary_array();
    containers->compare = netsnmp_compare_cstring;

    /*
     * register containers
     */
    netsnmp_container_binary_array_init();
    netsnmp_container_ssll_init();
    netsnmp_container_null_init();

    /*
     * default aliases for some containers
     */
    netsnmp_container_register("table_container",
                               netsnmp_container_get_factory("binary_array"));
    netsnmp_container_register("linked_list",
                               netsnmp_container_get_factory("sorted_singly_linked_list"));
    netsnmp_container_register("ssll_container",
                               netsnmp_container_get_factory("sorted_singly_linked_list"));
}

void
netsnmp_container_free_list(void)
{
    DEBUGMSGTL(("container", "netsnmp_container_free_list() called\n"));
    if (containers == NULL)
	return;

    /*
     * free memory used by each factory entry
     */
    CONTAINER_FOR_EACH(containers, _factory_free, NULL);

    /*
     * free factory container
     */
    CONTAINER_FREE(containers);
    containers = NULL;
}

int
netsnmp_container_register(const char* name, netsnmp_factory *f)
{
    container_type *ct, tmp;

    tmp.name = name;
    ct = CONTAINER_FIND(containers, &tmp);
    if (NULL!=ct) {
        DEBUGMSGT(("container_registry",
                   "replacing previous container factory\n"));
        ct->factory = f;
    }
    else {
        ct = SNMP_MALLOC_TYPEDEF(container_type);
        if (NULL == ct)
            return -1;
        ct->name = strdup(name);
        ct->factory = f;
        CONTAINER_INSERT(containers, ct);
    }
    DEBUGMSGT(("container_registry", "registered container factory %s (%s)\n",
               ct->name, f->product));

    return 0;
}

/*------------------------------------------------------------------
 */
netsnmp_factory *
netsnmp_container_get_factory(const char *type)
{
    container_type ct, *found;
    
    ct.name = type;
    found = CONTAINER_FIND(containers, &ct);

    return found ? found->factory : NULL;
}

netsnmp_factory *
netsnmp_container_find_factory(const char *type_list)
{
    netsnmp_factory   *f = NULL;
    char              *list, *entry;
    char              *st;

    if (NULL==type_list)
        return NULL;

    list = strdup(type_list);
    entry = strtok_r(list, ":", &st);
    while(entry) {
        f = netsnmp_container_get_factory(entry);
        if (NULL != f)
            break;
        entry = strtok_r(NULL, ":", &st);
    }

    free(list);
    return f;
}

/*------------------------------------------------------------------
 */
netsnmp_container *
netsnmp_container_get(const char *type)
{
    netsnmp_factory *f = netsnmp_container_get_factory(type);
    if (f)
        return f->produce();

    return NULL;
}

/*------------------------------------------------------------------
 */
netsnmp_container *
netsnmp_container_find(const char *type)
{
    netsnmp_factory *f = netsnmp_container_find_factory(type);
    if (f)
        return f->produce();

    return NULL;
}

/*------------------------------------------------------------------
 */
void
netsnmp_container_add_index(netsnmp_container *primary,
                            netsnmp_container *new_index)
{
    netsnmp_container *curr = primary;

    if((NULL == new_index) || (NULL == primary)) {
        snmp_log(LOG_ERR, "add index called with null pointer\n");
        return;
    }

    while(curr->next)
        curr = curr->next;

    curr->next = new_index;
    new_index->prev = curr;
}

#ifndef NETSNMP_USE_INLINE /* default is to inline */

/*------------------------------------------------------------------
 * These functions should EXACTLY match the inline version in
 * container.h. If you chance one, change them both.
 */
int CONTAINER_INSERT(netsnmp_container *x, const void *k)
{ 
    int rc2, rc = 0;
    
    /** start at first container */
    while(x->prev)
        x = x->prev;
    while(x) {
        rc2 = x->insert(x,k);
        if (rc2) {
            snmp_log(LOG_ERR,"error on subcontainer insert (%d)\n", rc2);
            rc = rc2;
        }
        x = x->next;
    }
    return rc;
}

/*------------------------------------------------------------------
 * These functions should EXACTLY match the inline version in
 * container.h. If you chance one, change them both.
 */
int CONTAINER_REMOVE(netsnmp_container *x, const void *k)
{
    int rc2, rc = 0;
    
    /** start at last container */
    while(x->next)
        x = x->next;
    while(x) {
        rc2 = x->remove(x,k);
        if (rc2) {
            snmp_log(LOG_ERR,"error on subcontainer remove (%d)\n", rc2);
            rc = rc2;
        }
        x = x->prev;
        
    }
    return rc;
}

/*------------------------------------------------------------------
 * These functions should EXACTLY match the inline version in
 * container.h. If you chance one, change them both.
 */
int CONTAINER_FREE(netsnmp_container *x)
{
    int  rc2, rc = 0;
        
    /** start at last container */
    while(x->next)
        x = x->next;
    while(x) {
        netsnmp_container *tmp;
        tmp = x->prev;
        rc2 = x->cfree(x);
        if (rc2) {
            snmp_log(LOG_ERR,"error on subcontainer cfree (%d)\n", rc2);
            rc = rc2;
        }
        x = tmp;
    }
    return rc;
}
#endif


/*------------------------------------------------------------------
 */
void
netsnmp_init_container(netsnmp_container         *c,
                       netsnmp_container_rc      *init,
                       netsnmp_container_rc      *cfree,
                       netsnmp_container_size    *size,
                       netsnmp_container_compare *cmp,
                       netsnmp_container_op      *ins,
                       netsnmp_container_op      *rem,
                       netsnmp_container_rtn     *fnd)
{
    if (c == NULL)
        return;

    c->init = init;
    c->cfree = cfree;
    c->get_size = size;
    c->compare = cmp;
    c->insert = ins;
    c->remove = rem;
    c->find = fnd;
}

/*------------------------------------------------------------------
 *
 * simple comparison routines
 *
 */
int
netsnmp_compare_netsnmp_index(const void *lhs, const void *rhs)
{
    int rc;
    netsnmp_assert((NULL != lhs) && (NULL != rhs));
    DEBUGIF("compare:index") {
        DEBUGMSGT(("compare:index", "compare "));
        DEBUGMSGSUBOID(("compare:index", ((const netsnmp_index *) lhs)->oids,
                     ((const netsnmp_index *) lhs)->len));
        DEBUGMSG(("compare:index", " to "));
        DEBUGMSGSUBOID(("compare:index", ((const netsnmp_index *) rhs)->oids,
                     ((const netsnmp_index *) rhs)->len));
        DEBUGMSG(("compare:index", "\n"));
    }
    rc = snmp_oid_compare(((const netsnmp_index *) lhs)->oids,
                          ((const netsnmp_index *) lhs)->len,
                          ((const netsnmp_index *) rhs)->oids,
                          ((const netsnmp_index *) rhs)->len);
    DEBUGMSGT(("compare:index", "result was %d\n", rc));
    return rc;
}

int
netsnmp_ncompare_netsnmp_index(const void *lhs, const void *rhs)
{
    int rc;
    netsnmp_assert((NULL != lhs) && (NULL != rhs));
    DEBUGIF("compare:index") {
        DEBUGMSGT(("compare:index", "compare "));
        DEBUGMSGSUBOID(("compare:index", ((const netsnmp_index *) lhs)->oids,
                     ((const netsnmp_index *) lhs)->len));
        DEBUGMSG(("compare:index", " to "));
        DEBUGMSGSUBOID(("compare:index", ((const netsnmp_index *) rhs)->oids,
                     ((const netsnmp_index *) rhs)->len));
        DEBUGMSG(("compare:index", "\n"));
    }
    rc = snmp_oid_ncompare(((const netsnmp_index *) lhs)->oids,
                           ((const netsnmp_index *) lhs)->len,
                           ((const netsnmp_index *) rhs)->oids,
                           ((const netsnmp_index *) rhs)->len,
                           ((const netsnmp_index *) rhs)->len);
    DEBUGMSGT(("compare:index", "result was %d\n", rc));
    return rc;
}

int
netsnmp_compare_cstring(const void * lhs, const void * rhs)
{
    return strcmp(((const container_type*)lhs)->name,
                  ((const container_type*)rhs)->name);
}

int
netsnmp_ncompare_cstring(const void * lhs, const void * rhs)
{
    return strncmp(((const container_type*)lhs)->name,
                   ((const container_type*)rhs)->name,
                   strlen(((const container_type*)rhs)->name));
}

/*
 * compare two memory buffers
 *
 * since snmp strings aren't NULL terminated, we can't use strcmp. So
 * compare up to the length of the smaller, and then use length to
 * break any ties.
 */
int
netsnmp_compare_mem(const char * lhs, size_t lhs_len,
                    const char * rhs, size_t rhs_len)
{
    int rc, min = SNMP_MIN(lhs_len, rhs_len);

    rc = memcmp(lhs, rhs, min);
    if((rc==0) && (lhs_len != rhs_len)) {
        if(lhs_len < rhs_len)
            rc = -1;
        else
            rc = 1;
    }

    return rc;
}
