/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/interface.h>

/**---------------------------------------------------------------------*/
/*
 * local static prototypes
 */
static int _access_interface_entry_compare_name(const void *lhs,
                                                const void *rhs);
static void _access_interface_entry_release(netsnmp_interface_entry * entry,
                                            void *unused);
static void _access_interface_entry_set_index(netsnmp_interface_entry *entry,
                                              const char *name);

/**---------------------------------------------------------------------*/
/*
 * external per-architecture functions prototypes
 *
 * These shouldn't be called by the general public, so they aren't in
 * the header file.
 */
extern int
netsnmp_access_interface_container_arch_load(netsnmp_container* container,
                                             u_int load_flags);

/**---------------------------------------------------------------------*/
/*
 * container functions
 */
/**
 */
netsnmp_container *
netsnmp_access_interface_container_init(u_int flags)
{
    netsnmp_container *container1;

    DEBUGMSGTL(("access:interface:container", "init\n"));

    /*
     * create the containers. one indexed by ifIndex, the other
     * indexed by ifName.
     */
    container1 = netsnmp_container_find("access_interface:table_container");
    if (NULL == container1)
        return NULL;

    if (flags & NETSNMP_ACCESS_INTERFACE_INIT_ADDL_IDX_BY_NAME) {
        netsnmp_container *container2 =
            netsnmp_container_find("access_interface_by_name:access_interface:table_container");
        if (NULL == container2)
            return NULL;

        container2->compare = _access_interface_entry_compare_name;
        
        netsnmp_container_add_index(container1, container2);
    }

    return container1;
}

/**
 * load interface information in specified container
 *
 * @param container empty container, or NULL to have one created for you
 * @param load_flags flags to modify behaviour. Examples:
 *                   NETSNMP_ACCESS_INTERFACE_INIT_ADDL_IDX_BY_NAME
 *
 * @retval NULL  error
 * @retval !NULL pointer to container
 */
netsnmp_container*
netsnmp_access_interface_container_load(netsnmp_container* container, u_int load_flags)
{
    int rc;

    DEBUGMSGTL(("access:interface:container", "load\n"));

    if (NULL == container)
        container = netsnmp_access_interface_container_init(load_flags);
    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_interface\n");
        return NULL;
    }

    rc =  netsnmp_access_interface_container_arch_load(container, load_flags);
    if (0 != rc) {
        netsnmp_access_interface_container_free(container,
                                                NETSNMP_ACCESS_INTERFACE_FREE_NOFLAGS);
        container = NULL;
    }

    return container;
}

void
netsnmp_access_interface_container_free(netsnmp_container *container, u_int free_flags)
{
    DEBUGMSGTL(("access:interface:container", "free\n"));

    if (NULL == container) {
        snmp_log(LOG_ERR, "invalid container for netsnmp_access_interface_free\n");
        return;
    }

    if(! (free_flags & NETSNMP_ACCESS_INTERFACE_FREE_DONT_CLEAR)) {
        /*
         * free all items.
         */
        CONTAINER_CLEAR(container,
                        (netsnmp_container_obj_func*)_access_interface_entry_release,
                        NULL);
    }

    CONTAINER_FREE(container);
}

/**---------------------------------------------------------------------*/
/*
 * ifentry functions
 */
/**
 */
netsnmp_interface_entry *
netsnmp_access_interface_entry_get_by_index(netsnmp_container *container, oid index)
{
    netsnmp_index   tmp;

    if (NULL == container) {
        snmp_log(LOG_ERR,
                 "invalid container for netsnmp_access_interface_entry_get_by_index\n");
        return NULL;
    }

    tmp.len = 1;
    tmp.oids = &index;

    return (netsnmp_interface_entry *) CONTAINER_FIND(container, &tmp);
}

/**
 */
netsnmp_interface_entry *
netsnmp_access_interface_entry_get_by_name(netsnmp_container *container,
                                const char *name)
{
    netsnmp_interface_entry tmp;

    if (NULL == container) {
        snmp_log(LOG_ERR,
                 "invalid container for netsnmp_access_interface_entry_get_by_name\n");
        return NULL;
    }

    if (NULL == container->next) {
        snmp_log(LOG_ERR,
                 "secondary index missing for netsnmp_access_interface_entry_get_by_name\n");
        return NULL;
    }

    tmp.if_name = name;
    return CONTAINER_FIND(container->next, &tmp);
}

/**
 * @retval 0  interface not found
 */
oid
netsnmp_access_interface_index_find(const char *name)
{
    oid index = se_find_value_in_slist("interfaces", name);
    if (index == SE_DNE)
        return 0;

    return index;
}

/**
 */
netsnmp_interface_entry *
netsnmp_access_interface_entry_create(const char *name)
{
    netsnmp_interface_entry *entry =
        SNMP_MALLOC_TYPEDEF(netsnmp_interface_entry);

    if(NULL == entry)
        return NULL;

    if(NULL != name)
        entry->if_name = strdup(name);

    _access_interface_entry_set_index(entry, name);

    entry->if_descr = strdup("unknown");
    // xxx-rks: if_alias? supposed to be persistent

    /*
     * make some assumptions
     */
    entry->if_connector_present = 1;
    entry->if_oper_status = IFOPERSTATUS_UP;

    entry->oid_index.len = 1;
    entry->oid_index.oids = (oid *) & entry->index;

    // xxx-rks: do this stuff.. ifspeed, etc..
    /*
     * XXX - initialise the "static" information
     *  a) Using the configure overrides
     *  b) Via (architecture-specific) utility routines
     */
    snmp_log(LOG_ERR, "netsnmp_access_interface_entry_create(entry);\n");

    return entry;
}

/**
 */
void
netsnmp_access_interface_entry_free(netsnmp_interface_entry * entry)
{
    if (NULL == entry)
        return;

    if (NULL != entry->if_name)
        free(entry->if_name);

    if (NULL != entry->if_descr)
        free(entry->if_descr);

    if (NULL != entry->if_paddr)
        free(entry->if_paddr);

    free(entry);
}

/**---------------------------------------------------------------------*/
/*
 * Utility routines
 */

/**
 */
static int
_access_interface_entry_compare_name(const void *lhs, const void *rhs)
{
    return strcmp(((const netsnmp_interface_entry *) lhs)->if_name,
                  ((const netsnmp_interface_entry *) rhs)->if_name);
}

/**
 */
static void
_access_interface_entry_release(netsnmp_interface_entry * entry, void *context)
{
    netsnmp_access_interface_entry_free(entry);
}

/**
 */
static void
_access_interface_entry_set_index(netsnmp_interface_entry *entry, const char *name)
{
    if(NULL != name) {
        entry->index = netsnmp_access_interface_index_find(name);
        if (entry->index == 0) {
            entry->index = se_find_free_value_in_slist("interfaces");
            if (entry->index == SE_DNE)
                entry->index = 1;       /* Completely new list! */
            se_add_pair_to_slist("interfaces", strdup(name), entry->index);
            DEBUGMSGTL(("access:interface:ifIndex", "new ifIndex %d for %s\n",
                        entry->index, name));
        }
    }
    else
        entry->index = 0;
}

/**
 * copy interface entry data
 *
 * @retval -2 : malloc failed
 * @retval -1 : interfaces not the same
 * @retval  0 : no error
 */
int
netsnmp_access_interface_entry_copy(netsnmp_interface_entry * lhs,
                                    netsnmp_interface_entry * rhs)
{
    DEBUGMSGTL(("access:interface", "copy\n"));
    
    if ((NULL == lhs) || (NULL == rhs) ||
        (0 != strncmp(lhs->if_name, rhs->if_name, strlen(rhs->if_name))))
        return -1;

    /*
     * code doesn't take the possibility of dynamically changing
     * flags into account.
     */
    netsnmp_assert(lhs->flags == rhs->flags);

    /*
     * copy stats
     */
    memcpy(&lhs->stats, &rhs->stats, sizeof(rhs->stats));
    
    /*
     * update data
     */
    if((NULL != lhs->if_descr) && (NULL != rhs->if_descr) &&
       (0 == strcmp(lhs->if_descr, rhs->if_descr)))
        ;
    else {
        if (NULL != lhs->if_descr)
            SNMP_FREE(lhs->if_descr);
        if (rhs->if_descr) {
            lhs->if_descr = strdup(rhs->if_descr);
            if(NULL == lhs->if_descr)
                return -2;
        }
    }
    lhs->if_type = rhs->if_type;
    lhs->if_speed = rhs->if_speed;
    lhs->if_speed_high = rhs->if_speed_high;
    lhs->if_mtu = rhs->if_mtu;
    lhs->if_discontinuity = rhs->if_discontinuity;
    lhs->if_oper_status = rhs->if_oper_status;
    lhs->if_promiscuous = rhs->if_promiscuous;
    lhs->if_connector_present = rhs->if_connector_present;
    if(lhs->if_paddr_len == rhs->if_paddr_len) {
        if(rhs->if_paddr_len)
            memcpy(lhs->if_paddr,rhs->if_paddr,rhs->if_paddr_len);
    } else {
        if (NULL != lhs->if_paddr)
            SNMP_FREE(lhs->if_paddr);
        if (rhs->if_paddr) {
            lhs->if_paddr = malloc(rhs->if_paddr_len);
            if(NULL == lhs->if_paddr)
                return -2;
            memcpy(lhs->if_paddr,rhs->if_paddr,rhs->if_paddr_len);
        }
    }
    lhs->if_paddr_len = rhs->if_paddr_len;
    
    return 0;
}
