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
 * @retval NULL  error
 * @retval !NULL pointer to container
 */
netsnmp_container*
netsnmp_access_interface_container_load(netsnmp_container* container, u_int load_flags)
{
    int rc;

    DEBUGMSGTL(("access:interface:container", "load\n"));

    if (NULL == container)
        container = netsnmp_container_find("access:interface:table_container");
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
                 "invalid container for netsnmp_access_interface_entry_get_by_name\n");
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
    netsnmp_interface_entry *entry = SNMP_MALLOC_TYPEDEF(netsnmp_interface_entry);

    if(NULL != name)
        entry->if_name = strdup(name);

    _access_interface_entry_set_index(entry, name);

    entry->if_descr = strdup("unknown");
    // xxx-rks: if_alias? supposed to be persistent

    /*
     * make some assumptions
     */
    entry->if_connector_present = 1;
    entry->if_admin_status = IFADMINSTATUS_UP;
    entry->if_oper_status = IFOPERSTATUS_UP;

    entry->oid_index.len = 1;
    entry->oid_index.oids = (oid *) & entry->index;

    // xxx-rks: do this stuff.. ifspeed, etc..
    /*
     * XXX - initialise the "static" information
     *  a) Using the configure overrides
     *  b) Via (architecture-specific) utility routines
     */
    snmp_log(LOG_ERR, "netsnmp_access_interface_entry_info_init(entry);\n");

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

    if (NULL != entry->if_alias)
        free(entry->if_alias);

    if (NULL != entry->if_old_alias)
        free(entry->if_old_alias);

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
void
_access_interface_entry_release(netsnmp_interface_entry * entry, void *context)
{
    netsnmp_access_interface_entry_free(entry);
}

/**
 */
void
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
