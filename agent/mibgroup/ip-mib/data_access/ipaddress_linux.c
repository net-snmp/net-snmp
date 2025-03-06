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
#include "../../if-mib/data_access/interface_private.h"

#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

netsnmp_feature_require(prefix_info);
netsnmp_feature_require(find_prefix_info);

netsnmp_feature_child_of(ipaddress_arch_entry_copy, ipaddress_common);

#ifdef NETSNMP_FEATURE_REQUIRE_IPADDRESS_ARCH_ENTRY_COPY
netsnmp_feature_require(ipaddress_ioctl_entry_copy);
#endif /* NETSNMP_FEATURE_REQUIRE_IPADDRESS_ARCH_ENTRY_COPY */

#include <linux/types.h>
#include <asm/types.h>
#ifndef HAVE_LIBNL3
#error libnl-3 is required. Please install the libnl-3 and libnl-route-3 development packages and remove --without-nl from the configure options if necessary.
#endif
#include <netlink/cache.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#define SUPPORT_PREFIX_FLAGS 1

#include "ipaddress.h"
#include "ipaddress_ioctl.h"
#include "ipaddress_private.h"

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
    if (NULL == netsnmp_ioctl_ipaddress_entry_init(entry))
        return -1;

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
    netsnmp_ioctl_ipaddress_entry_cleanup(entry);

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

    /*
     * copy ipv4 stuff
     */
    rc = netsnmp_ioctl_ipaddress_entry_copy(lhs, rhs);
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
        return _netsnmp_ioctl_ipaddress_set_v4(entry);
    } else if (16 == entry->ia_address_len) {
        return _netsnmp_ioctl_ipaddress_set_v6(entry);
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
        return _netsnmp_ioctl_ipaddress_delete_v4(entry);
    } else if (16 == entry->ia_address_len) {
        return _netsnmp_ioctl_ipaddress_delete_v6(entry);
    } else {
        DEBUGMSGT(("access:ipaddress:create", "only ipv4 supported\n"));
        return -2;
    }
}

#if defined (NETSNMP_ENABLE_IPV6)
static int load_v6_interfaces(struct nl_sock *nl_sock,
                              netsnmp_container *container, int idx_offset)
{
    struct nl_cache *link_cache, *addr_cache;
    struct nl_object *link_obj;
    int             rc;

    rc = rtnl_link_alloc_cache(nl_sock, AF_UNSPEC, &link_cache);
    if (rc)
        return rc;

    rc = rtnl_addr_alloc_cache(nl_sock, &addr_cache);
    if (rc)
        goto put_link_cache;

    for (link_obj = nl_cache_get_first(link_cache); link_obj;
         link_obj = nl_cache_get_next(link_obj)) {
        struct rtnl_link *rtnl_link = (void *)link_obj;
        int if_index = rtnl_link_get_ifindex(rtnl_link);
        const char *if_name = rtnl_link_get_name(rtnl_link);
        struct rtnl_addr *rtnl_addr;
        netsnmp_ipaddress_entry *entry;
        _ioctl_extras *extras;

        DEBUGMSGTL(("access:ipaddress:container",
                    " interface %d, %s\n", idx_offset, if_name));

        rtnl_addr = addr_of_type(if_index, addr_cache, AF_INET6);
        if (!rtnl_addr)
            continue;

        if (!netsnmp_access_interface_include(if_name))
            continue;

	if (netsnmp_access_interface_max_reached(if_name))
            /* we may need to stop tracking ifaces if a max was set */
            continue;

        entry = netsnmp_access_ipaddress_entry_create();
        if (!entry) {
            rc = -3;
            break;
        }
        entry->ns_ia_index = ++idx_offset;

        /*
         * save if name
         */
        extras = netsnmp_ioctl_ipaddress_extras_get(entry);
        strlcpy((char *)extras->name, rtnl_link_get_ifalias(rtnl_link) ? :
                if_name, sizeof(extras->name));

        /*
         * save ifindex
         */
        entry->if_index = if_index;
        if (entry->if_index == 0) {
            snmp_log(LOG_ERR,"no ifindex found for interface\n");
            netsnmp_access_ipaddress_entry_free(entry);
            continue;
        }

        /*
         * get flags (IFF_*)
         */
        extras->flags = rtnl_link_get_flags(rtnl_link);

        entry->ia_onlink_flag = 1;  /*Set by default as true*/
        entry->ia_autonomous_flag = 2; /*Set by default as false*/

        /*
         * get IP address
         */
        struct nl_addr *local_addr = rtnl_addr_get_local(rtnl_addr);
        void *addr = nl_addr_get_binary_addr(local_addr);
        int addr_len = nl_addr_get_len(local_addr);
        netsnmp_assert(addr_len <= sizeof(entry->ia_address));
        memcpy(entry->ia_address, addr, addr_len);
        entry->ia_address_len = addr_len;

        /*
         * get netmask
         */
        entry->ia_prefix_len = nl_addr_get_prefixlen(local_addr);

        /*
         * address flags
         */
        const unsigned int flags = rtnl_addr_get_flags(rtnl_addr);
        if ((flags & IFA_F_PERMANENT) || (!flags))
            entry->ia_status = IPADDRESSSTATUSTC_PREFERRED; /* ?? */
#ifdef IFA_F_TEMPORARY
        else if (flags & IFA_F_TEMPORARY)
            entry->ia_status = IPADDRESSSTATUSTC_PREFERRED; /* ?? */
#endif
        else if (flags & IFA_F_DEPRECATED)
            entry->ia_status = IPADDRESSSTATUSTC_DEPRECATED;
        else if (flags & IFA_F_TENTATIVE)
            entry->ia_status = IPADDRESSSTATUSTC_TENTATIVE;
        else {
            entry->ia_status = IPADDRESSSTATUSTC_UNKNOWN;
            DEBUGMSGTL(("access:ipaddress:ipv6",
                        "unknown flags 0x%x\n", flags));
        }

        /* a_cacheinfo.aci_prefered */
        entry->ia_prefered_lifetime =
            rtnl_addr_get_preferred_lifetime(rtnl_addr);
        /* a_cacheinfo.aci_valid */
        entry->ia_valid_lifetime = rtnl_addr_get_valid_lifetime(rtnl_addr);

        /* anycast */
        if (rtnl_addr_get_anycast(rtnl_addr))
            entry->ia_type = IPADDRESSTYPE_ANYCAST;
        else
            entry->ia_type = IPADDRESSTYPE_UNICAST;

        /*
         * can we figure out if an address is from DHCP?
         * use manual until then...
         *
         *#define IPADDRESSORIGINTC_OTHER  1
         *#define IPADDRESSORIGINTC_MANUAL  2
         *#define IPADDRESSORIGINTC_DHCP  4
         *#define IPADDRESSORIGINTC_LINKLAYER  5
         *#define IPADDRESSORIGINTC_RANDOM  6
         *
         * are 'local' address assigned by link layer??
         */
        if (!flags)
            entry->ia_origin = IPADDRESSORIGINTC_LINKLAYER;
#ifdef IFA_F_TEMPORARY
        else if (flags & IFA_F_TEMPORARY)
            entry->ia_origin = IPADDRESSORIGINTC_RANDOM;
#endif
        else if (IN6_IS_ADDR_LINKLOCAL(entry->ia_address))
            entry->ia_origin = IPADDRESSORIGINTC_LINKLAYER;
        else
            entry->ia_origin = IPADDRESSORIGINTC_MANUAL;

        if (entry->ia_origin == IPADDRESSORIGINTC_LINKLAYER)
            entry->ia_storagetype = STORAGETYPE_PERMANENT;

        if (CONTAINER_INSERT(container, entry) < 0) {
            DEBUGMSGTL(("access:ipaddress:container", "error with ipaddress_entry: insert into container failed.\n"));
            netsnmp_access_ipaddress_entry_free(entry);
            continue;
        }
    }
    nl_cache_put(addr_cache);

put_link_cache:
    nl_cache_put(link_cache);

    return rc < 0 ? rc : idx_offset;
}

static int _load_v6(netsnmp_container *container, int idx_offset)
{
    struct nl_sock *nl_sock;
    int             rc;

    nl_sock = nl_socket_alloc();
    if (!nl_sock)
        return -1;

    rc = nl_connect(nl_sock, NETLINK_ROUTE);
    if (rc < 0)
        goto free_socket;

    rc = load_v6_interfaces(nl_sock, container, idx_offset);

free_socket:
    nl_socket_free(nl_sock);

    /*
     * return number of interfaces seen
     */
    return rc;
}
#endif /* defined(NETSNMP_ENABLE_IPV6) */

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
        rc = _netsnmp_ioctl_ipaddress_container_load_v4(container, idx_offset);
        if(rc < 0) {
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
        else if(rc < 0) {
            u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
            netsnmp_access_ipaddress_container_free(container, flags);
        }
    }
#endif

    /*
     * return no errors (0) if we found any interfaces
     */
    if(rc > 0)
        rc = 0;

    return rc;
}
