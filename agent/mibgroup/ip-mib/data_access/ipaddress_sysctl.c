/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/ipaddress.h>
#include <net-snmp/data_access/interface.h>

#include "ip-mib/ipAddressTable/ipAddressTable_constants.h"
#include "ip-mib/ipAddressPrefixTable/ipAddressPrefixTable_constants.h"
#include "mibgroup/util_funcs.h"

#include <errno.h>
#include <sys/ioctl.h>

netsnmp_feature_require(prefix_info)
netsnmp_feature_require(find_prefix_info)

netsnmp_feature_child_of(ipaddress_arch_entry_copy, ipaddress_common)

#ifdef NETSNMP_FEATURE_REQUIRE_IPADDRESS_ARCH_ENTRY_COPY
netsnmp_feature_require(ipaddress_ioctl_entry_copy)
#endif /* NETSNMP_FEATURE_REQUIRE_IPADDRESS_ARCH_ENTRY_COPY */

#include "ipaddress_ioctl.h"
#ifdef SUPPORT_PREFIX_FLAGS
extern prefix_cbx *prefix_head_list;
#endif
int _load_v6(netsnmp_container *container, int idx_offset);

/*
 * initialize arch specific storage
 *
 * @retval  0: success
 * @retval <0: error
 */
int
netsnmp_arch_ipaddress_entry_init(netsnmp_ipaddress_entry *entry)
{
    /*
     * init ipv4 stuff
     */
    //if (NULL == netsnmp_ioctl_ipaddress_entry_init(entry))
    //    return -1;

    /*
     * init ipv6 stuff
     *   so far, we can just share the ipv4 stuff, so nothing to do
     */
    
    return 0;
}

/*
 * cleanup arch specific storage
 */
void
netsnmp_arch_ipaddress_entry_cleanup(netsnmp_ipaddress_entry *entry)
{
    /*
     * cleanup ipv4 stuff
     */
    //netsnmp_ioctl_ipaddress_entry_cleanup(entry);

    /*
     * cleanup ipv6 stuff
     *   so far, we can just share the ipv4 stuff, so nothing to do
     */
}

#ifndef NETSNMP_FEATURE_REMOVE_IPADDRESS_ARCH_ENTRY_COPY
/*
 * copy arch specific storage
 */
int
netsnmp_arch_ipaddress_entry_copy(netsnmp_ipaddress_entry *lhs,
                                  netsnmp_ipaddress_entry *rhs)
{
    int rc;

    rc = 0;

    /*
     * copy ipv4 stuff
     */
    //rc = netsnmp_ioctl_ipaddress_entry_copy(lhs, rhs);
    if (rc)
        return rc;

    /*
     * copy ipv6 stuff
     *   so far, we can just share the ipv4 stuff, so nothing to do
     */

    return rc;
}
#endif /* NETSNMP_FEATURE_REMOVE_IPADDRESS_ARCH_ENTRY_COPY */

/*
 * create a new entry
 */
int
netsnmp_arch_ipaddress_create(netsnmp_ipaddress_entry *entry)
{
    if (NULL == entry)
        return -1;

    if (4 == entry->ia_address_len) {
        return -1;
    } else if (16 == entry->ia_address_len) {
        return -1;
    } else {
        DEBUGMSGT(("access:ipaddress:create", "wrong length of IP address\n"));
        return -2;
    }
}

/*
 * create a new entry
 */
int
netsnmp_arch_ipaddress_delete(netsnmp_ipaddress_entry *entry)
{
    if (NULL == entry)
        return -1;

    if (4 == entry->ia_address_len) {
        return -2;
    } else if (16 == entry->ia_address_len) {
        return -3;
    } else {
        DEBUGMSGT(("access:ipaddress:create", "only ipv4 supported\n"));
        return -2;
    }
}

/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
int
netsnmp_arch_ipaddress_container_load(netsnmp_container *container,
                                      u_int load_flags)
{
    int rc = 0, idx_offset = 0;

    if (0 == (load_flags & NETSNMP_ACCESS_IPADDRESS_LOAD_IPV6_ONLY)) {
        rc = -1;
        if (rc < 0) {
            u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
            netsnmp_access_ipaddress_container_free(container, flags);
        }
    }

#if defined (NETSNMP_ENABLE_IPV6)

    if (0 == (load_flags & NETSNMP_ACCESS_IPADDRESS_LOAD_IPV4_ONLY)) {
        if (rc < 0)
            rc = 0;

        idx_offset = rc;

        /*
         * load ipv6, ignoring errors if file not found
         */
        rc = _load_v6(container, idx_offset);
        if (-2 == rc)
            rc = 0;
        else if (rc < 0) {
            u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
            netsnmp_access_ipaddress_container_free(container, flags);
        }
    }
#endif

    /*
     * return no errors (0) if we found any interfaces
     */
    if (rc > 0)
        rc = 0;

    return rc;
}

#if defined (NETSNMP_ENABLE_IPV6)
/**
 */
int
_load_v6(netsnmp_container *container, int idx_offset)
{

    return idx_offset;
}
#endif

