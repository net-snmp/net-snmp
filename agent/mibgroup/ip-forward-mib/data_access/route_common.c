/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/route.h>

/**---------------------------------------------------------------------*/
/*
 * local static prototypes
 */
static void _access_route_entry_release(netsnmp_route_entry * entry, void *unused);

/**---------------------------------------------------------------------*/
/*
 * external per-architecture functions prototypes
 *
 * These shouldn't be called by the general public, so they aren't in
 * the header file.
 */
extern int netsnmp_access_route_container_arch_load(netsnmp_container* container,
                                                    u_int load_flags);


/**---------------------------------------------------------------------*/
/*
 * container functions
 */

/**
 * @retval NULL  error
 * @retval !NULL pointer to container
 */
netsnmp_container*
netsnmp_access_route_container_load(netsnmp_container* container, u_int load_flags)
{
    int rc;

    DEBUGMSGTL(("access:route:container", "load\n"));

    if (NULL == container)
        container = netsnmp_container_find("access:_route:table_container");
    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_route\n");
        return NULL;
    }

    rc =  netsnmp_access_route_container_arch_load(container, load_flags);
    if (0 != rc) {
        netsnmp_access_route_container_free(container, NETSNMP_ACCESS_ROUTE_FREE_NOFLAGS);
        container = NULL;
    }

    return container;
}

void
netsnmp_access_route_container_free(netsnmp_container *container, u_int free_flags)
{
    DEBUGMSGTL(("access:route:container", "free\n"));

    if (NULL == container) {
        snmp_log(LOG_ERR, "invalid container for netsnmp_access_route_free\n");
        return;
    }

    if(! (free_flags & NETSNMP_ACCESS_ROUTE_FREE_DONT_CLEAR)) {
        /*
         * free all items.
         */
        CONTAINER_CLEAR(container,
                        (netsnmp_container_obj_func*)_access_route_entry_release,
                        NULL);
    }

    if(! (free_flags & NETSNMP_ACCESS_ROUTE_FREE_KEEP_CONTAINER))
        CONTAINER_FREE(container);
}

/**---------------------------------------------------------------------*/
/*
 * ifentry functions
 */
/** create route entry
 *
 * @note:
 *  if you create a route for entry into a container of your own, you
 *  must set ns_rt_index to a unique index for your container.
 */
netsnmp_route_entry *
netsnmp_access_route_entry_create(void)
{
    netsnmp_route_entry *entry = SNMP_MALLOC_TYPEDEF(netsnmp_route_entry);
    if(NULL == entry) {
        snmp_log(LOG_ERR, "could not allocate route entry\n");
        return NULL;
    }

    entry->oid_index.oids = &entry->ns_rt_index;
    entry->oid_index.len = 1;

    entry->rt_metric1 = -1;
    entry->rt_metric2 = -1;
    entry->rt_metric3 = -1;
    entry->rt_metric4 = -1;
    entry->rt_metric5 = -1;

    /** entry->row_status? */

    return entry;
}

/**
 */
void
netsnmp_access_route_entry_free(netsnmp_route_entry * entry)
{
    if (NULL == entry)
        return;

#ifdef USING_IP_FORWARD_MIB_INETCIDRROUTETABLE_INETCIDRROUTETABLE_MODULE
    if (NULL != entry->rt_policy)
        free(entry->rt_policy);
#endif
#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
    if (NULL != entry->rt_info)
        free(entry->rt_info);
#endif

    free(entry);
}

/**---------------------------------------------------------------------*/
/*
 * Utility routines
 */

/**
 */
void
_access_route_entry_release(netsnmp_route_entry * entry, void *context)
{
    netsnmp_access_route_entry_free(entry);
}
