/*
 *  Ipaddress MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
//#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/ipaddress.h>

/**---------------------------------------------------------------------*/
/*
 * local static prototypes
 */
//static int _access_ipaddress_entry_compare_name(const void *lhs,
//                                                const void *rhs);
static void _access_ipaddress_entry_release(netsnmp_ipaddress_entry * entry,
                                            void *unused);

/**---------------------------------------------------------------------*/
/*
 * external per-architecture functions prototypes
 *
 * These shouldn't be called by the general public, so they aren't in
 * the header file.
 */
extern int
netsnmp_access_ipaddress_container_arch_load(netsnmp_container* container,
                                             u_int load_flags);


/**---------------------------------------------------------------------*/
/*
 * container functions
 */
/**
 */
netsnmp_container *
netsnmp_access_ipaddress_container_init(u_int flags)
{
    netsnmp_container *container1;

    DEBUGMSGTL(("access:ipaddress:container", "init\n"));

    /*
     * create the containers. one indexed by ifIndex, the other
     * indexed by ifName.
     */
    container1 = netsnmp_container_find("access_ipaddress:table_container");
    if (NULL == container1)
        return NULL;

    if (flags & NETSNMP_ACCESS_IPADDRESS_INIT_ADDL_IDX_BY_NAME) {
        netsnmp_container *container2 =
            netsnmp_container_find("access_ipaddress:table_container");
        if (NULL == container2)
            return NULL;

// xxx-rks        container2->compare = _access_ipaddress_entry_compare_name;
        
        netsnmp_container_add_index(container1, container2);
    }

    return container1;
}

/**
 * @retval NULL  error
 * @retval !NULL pointer to container
 */
netsnmp_container*
netsnmp_access_ipaddress_container_load(netsnmp_container* container, u_int load_flags)
{
    int rc;

    DEBUGMSGTL(("access:ipaddress:container", "load\n"));

    if (NULL == container)
        container = netsnmp_container_find("access:ipaddress:table_container");
    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_ipaddress\n");
        return NULL;
    }

    rc =  netsnmp_access_ipaddress_container_arch_load(container, load_flags);
    if (0 != rc) {
        netsnmp_access_ipaddress_container_free(container,
                                                NETSNMP_ACCESS_IPADDRESS_FREE_NOFLAGS);
        container = NULL;
    }

    return container;
}

void
netsnmp_access_ipaddress_container_free(netsnmp_container *container, u_int free_flags)
{
    DEBUGMSGTL(("access:ipaddress:container", "free\n"));

    if (NULL == container) {
        snmp_log(LOG_ERR, "invalid container for netsnmp_access_ipaddress_free\n");
        return;
    }

    if(! (free_flags & NETSNMP_ACCESS_IPADDRESS_FREE_DONT_CLEAR)) {
        /*
         * free all items.
         */
        CONTAINER_CLEAR(container,
                        (netsnmp_container_obj_func*)_access_ipaddress_entry_release,
                        NULL);
    }

    CONTAINER_FREE(container);
}

/**---------------------------------------------------------------------*/
/*
 * ipaddress_entry functions
 */
/**
 */
/**
 */
netsnmp_ipaddress_entry *
netsnmp_access_ipaddress_entry_create(void)
{
    netsnmp_ipaddress_entry *entry =
        SNMP_MALLOC_TYPEDEF(netsnmp_ipaddress_entry);

    entry->oid_index.len = 1;
    entry->oid_index.oids = &entry->ns_ia_index;

    return entry;
}

/**
 */
void
netsnmp_access_ipaddress_entry_free(netsnmp_ipaddress_entry * entry)
{
    if (NULL == entry)
        return;

    if (NULL != entry->ia_prefix_oid)
        free(entry->ia_prefix_oid);

    free(entry);
}

/**---------------------------------------------------------------------*/
/*
 * Utility routines
 */

/**
 */
void
_access_ipaddress_entry_release(netsnmp_ipaddress_entry * entry, void *context)
{
    netsnmp_access_ipaddress_entry_free(entry);
}
