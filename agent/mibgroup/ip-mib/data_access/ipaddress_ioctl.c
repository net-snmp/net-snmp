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
#include "if-mib/data_access/interface_ioctl.h"

#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>

#ifndef HAVE_LIBNL3
#error libnl-3 is required. Please install the libnl-3 and libnl-route-3 development packages and remove --without-nl from the configure options if necessary.
#endif
#include <netlink/cache.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>

#include "ipaddress_ioctl.h"

netsnmp_feature_child_of(ipadress_ioctl_entry_copy, ipaddress_common);

static void _print_flags(short flags);

#define LIST_TOKEN "ioctl_extras"

/*
 * get extra structure
 *
 * @returns the extras structure from the entry
 */
_ioctl_extras *
netsnmp_ioctl_ipaddress_extras_get(netsnmp_ipaddress_entry *entry)
{
    if ((NULL == entry) || (NULL == entry->arch_data))
        return NULL;

    return (_ioctl_extras*)netsnmp_get_list_data(entry->arch_data, LIST_TOKEN);
}

/**
 * initialize ioctl extras
 *
 * @returns _ioctl_extras pointer, or NULL on error
 */
_ioctl_extras *
netsnmp_ioctl_ipaddress_entry_init(netsnmp_ipaddress_entry *entry)
{
    netsnmp_data_list *node;
    _ioctl_extras     *extras;

    if (NULL == entry)
        return NULL;

    extras = SNMP_MALLOC_TYPEDEF(_ioctl_extras);
    if (NULL == extras)
        return NULL;

    node = netsnmp_create_data_list(LIST_TOKEN, extras, free);
    if (NULL == node) {
        free(extras);
        return NULL;
    }

    netsnmp_data_list_add_node( &entry->arch_data, node );
    
    return extras;
}

/**
 * cleanup ioctl extras
 */
void
netsnmp_ioctl_ipaddress_entry_cleanup(netsnmp_ipaddress_entry *entry)
{
    if (NULL == entry) {
        netsnmp_assert(NULL != entry);
        return;
    }

    if (NULL == entry->arch_data) {
        netsnmp_assert(NULL != entry->arch_data);
        return;
    }

    netsnmp_remove_list_node(&entry->arch_data, LIST_TOKEN);
}

#ifndef NETSNMP_FEATURE_REMOVE_IPADDRESS_IOCTL_ENTRY_COPY
/**
 * copy ioctl extras
 *
 * @retval  0: success
 * @retval <0: error
 */
int
netsnmp_ioctl_ipaddress_entry_copy(netsnmp_ipaddress_entry *lhs,
                                   netsnmp_ipaddress_entry *rhs)
{
    _ioctl_extras *lhs_extras, *rhs_extras;
    int            rc = SNMP_ERR_NOERROR;

    if ((NULL == lhs) || (NULL == rhs)) {
        netsnmp_assert((NULL != lhs) && (NULL != rhs));
        return -1;
    }

    rhs_extras = netsnmp_ioctl_ipaddress_extras_get(rhs);
    lhs_extras = netsnmp_ioctl_ipaddress_extras_get(lhs);
    if (NULL == rhs_extras) {
        if (NULL != lhs_extras)
            netsnmp_ioctl_ipaddress_entry_cleanup(lhs);
    }
    else {
        if (NULL == lhs_extras)
            lhs_extras = netsnmp_ioctl_ipaddress_entry_init(lhs);
        
        if (NULL != lhs_extras)
            memcpy(lhs_extras, rhs_extras, sizeof(_ioctl_extras));
        else
            rc = -1;
    }

    return rc;
}
#endif /* NETSNMP_FEATURE_REMOVE_IPADDRESS_IOCTL_ENTRY_COPY */

struct rtnl_addr *addr_of_type(int if_index, struct nl_cache *addr_cache,
                               unsigned int af)
{
    struct nl_object *addr_obj;

    for (addr_obj = nl_cache_get_first(addr_cache); addr_obj;
         addr_obj = nl_cache_get_next(addr_obj)) {
        struct rtnl_addr *rtnl_addr = (struct rtnl_addr *)addr_obj;
        struct nl_addr *local_addr = rtnl_addr_get_local(rtnl_addr);

        if (rtnl_addr_get_ifindex(rtnl_addr) == if_index
            && nl_addr_get_family(local_addr) == af) {
            return rtnl_addr;
        }
    }
    return NULL;
}

static int load_v4_interfaces(struct nl_sock *nl_sock,
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

        rtnl_addr = addr_of_type(if_index, addr_cache, AF_INET);
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
        /*
         * The obsolete IP aliasing approach uses network interface names
         * where the interface name and the alias ID are separated by a colon.
         * See also https://docs.kernel.org/networking/alias.html and
         * https://en.wikipedia.org/wiki/IP_aliasing.
         */
        if (strchr(if_name, ':'))
            entry->flags |= NETSNMP_ACCESS_IPADDRESS_ISALIAS;
        strlcpy((char *)extras->name, if_name,
                sizeof(extras->name));

        /*
         * get IP address
         */
        struct nl_addr *local_addr = rtnl_addr_get_local(rtnl_addr);
        void *addr = nl_addr_get_binary_addr(local_addr);
        int addr_len = nl_addr_get_len(local_addr);
        entry->ia_address_len = addr_len;
        in_addr_t ipval;
        netsnmp_assert(sizeof(ipval) == addr_len);
        memcpy(&ipval, addr, addr_len);
        memcpy(entry->ia_address, addr, addr_len);

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

        /** entry->ia_prefix_oid ? */

        /*
         * per the MIB:
         *   In the absence of other information, an IPv4 address is
         *   always preferred(1).
         */
        entry->ia_status = IPADDRESSSTATUSTC_PREFERRED;

        /*
         * get netmask
         */
        entry->ia_prefix_len = nl_addr_get_prefixlen(local_addr);

        /* anycast */
        if (rtnl_addr_get_anycast(rtnl_addr))
           entry->ia_type = IPADDRESSTYPE_ANYCAST;
        else
           entry->ia_type = IPADDRESSTYPE_UNICAST;

        /*
         * can we figure out if an address is from DHCP?
         * use manual until then...
         */
        if (IS_APIPA(ipval)) {
           entry->ia_origin = IPADDRESSORIGINTC_RANDOM;
        } else {
           entry->ia_origin = IPADDRESSORIGINTC_MANUAL;
        }

        DEBUGIF("access:ipaddress:container") {
            DEBUGMSGT_NC(("access:ipaddress:container",
                          " if %d: addr len %d, index 0x%" NETSNMP_PRIo "x\n",
                          if_index, entry->ia_address_len, entry->if_index));
            if (entry->ia_address_len == 4)
                DEBUGMSGT_NC(("access:ipaddress:container",
                              " address %d.%d.%d.%d\n",
                              entry->ia_address[0], entry->ia_address[1],
                              entry->ia_address[2], entry->ia_address[3]));
            DEBUGMSGT_NC(("access:ipaddress:container", "flags 0x%x\n",
                          extras->flags));
            _print_flags(extras->flags);

        }

        if (CONTAINER_INSERT(container, entry) < 0) {
            DEBUGMSGTL(("access:ipaddress:container","error with ipaddress_entry: insert into container failed.\n"));
            NETSNMP_LOGONCE((LOG_ERR, "Duplicate IPv4 address detected, some interfaces may not be visible in IP-MIB\n"));
            netsnmp_access_ipaddress_entry_free(entry);
            continue;
        }

        /*
         * get broadcast
         */
        struct nl_addr *bc_addr = rtnl_addr_get_broadcast(rtnl_addr);
        if (!bc_addr)
            continue;

        netsnmp_ipaddress_entry *bcastentry =
            netsnmp_access_ipaddress_entry_create();
        if (!bcastentry) {
            rc = -3;
            break;
        }
        bcastentry->if_index = entry->if_index;
        bcastentry->ns_ia_index = ++idx_offset;
        bcastentry->ia_address_len = nl_addr_get_len(bc_addr);
        memcpy(bcastentry->ia_address, nl_addr_get_binary_addr(bc_addr),
               nl_addr_get_len(bc_addr));
        bcastentry->ia_prefix_len = entry->ia_prefix_len;
        bcastentry->ia_type = IPADDRESSTYPE_BROADCAST;
        bcastentry->ia_status = IPADDRESSSTATUSTC_PREFERRED;
        if (IS_APIPA(ipval)) {
            bcastentry->ia_origin = IPADDRESSORIGINTC_RANDOM;
        } else {
            bcastentry->ia_origin = IPADDRESSORIGINTC_MANUAL;
        }

        /*
         * add entry to container
         */
        if (CONTAINER_INSERT(container, bcastentry) < 0) {
            DEBUGMSGTL(("access:ipaddress:container","error with ipaddress_entry: insert broadcast entry into container failed.\n"));
            netsnmp_access_ipaddress_entry_free(bcastentry);
            continue;
        }
    }

    nl_cache_put(addr_cache);

put_link_cache:
    nl_cache_put(link_cache);

    return rc < 0 ? rc : idx_offset;
}

/**
 * load IPv4 addresses via libnl
 */
int
_netsnmp_ioctl_ipaddress_container_load_v4(netsnmp_container *container,
                                           int idx_offset)
{
    struct nl_sock *nl_sock;
    int             rc;

    nl_sock = nl_socket_alloc();
    if (!nl_sock)
        return -1;

    rc = nl_connect(nl_sock, NETLINK_ROUTE);
    if (rc < 0)
        goto free_socket;

    rc = load_v4_interfaces(nl_sock, container, idx_offset);

free_socket:
    nl_socket_free(nl_sock);

    /*
     * return number of interfaces seen
     */
    return rc;
}

/**
 * find unused alias number
 */
static int
_next_alias(const char *if_name)
{
    int             i, j, k, sd, interfaces = 0, len;
    struct ifconf   ifc;
    struct ifreq   *ifrp;
    char                    *alias;
    int                     *alias_list;

    if (NULL == if_name)
        return -1;
    len = strlen(if_name);

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snmp_log_perror("_next_alias: could not create socket");
        return -1;
    }

    interfaces =
        netsnmp_access_ipaddress_ioctl_get_interface_count(sd, &ifc);
    if(interfaces < 0) {
        close(sd);
        return -2;
    }
    netsnmp_assert(NULL != ifc.ifc_buf);
    DEBUGMSGTL(("access:ipaddress:container", "processing %d interfaces\n", interfaces));

    alias_list = (int*)malloc(interfaces * sizeof(int));
    if (NULL == alias_list) {
        close(sd);
        return -2;
    }

    ifrp = ifc.ifc_req;
    for(i=0,j=0; i < interfaces; ++i, ++ifrp) {

        if (strncmp(ifrp->ifr_name, if_name, len) != 0)
            continue;

        DEBUGMSGTL(("access:ipaddress:container",
                    " interface %d, %s\n", i, ifrp->ifr_name));

        alias = strchr(ifrp->ifr_name, ':');
        if (NULL == alias)
            continue;

        ++alias; /* skip ':' */
        alias_list[j++] = atoi(alias);
    }

    /*
     * clean up
     */
    free(ifc.ifc_buf);
    close(sd);

    /*
     * return first unused alias
     */
    for(i=1; i<=interfaces; ++i) {
        for(k=0;k<j;++k)
            if (alias_list[k] == i)
                break;
        if (k == j) {
            free(alias_list);
            return i;
        }
    }

    free(alias_list);
    return interfaces + 1;
}


/**
 *
 * @retval  0 : no error
 * @retval -1 : bad parameter
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl failed
 */
int
_netsnmp_ioctl_ipaddress_set_v4(netsnmp_ipaddress_entry * entry)
{
    struct ifreq                   ifrq;
    struct sockaddr_in            *sin;
    int                            rc, fd = -1;
    _ioctl_extras                 *extras;

    if (NULL == entry)
        return -1;

    netsnmp_assert(4 == entry->ia_address_len);

    extras = netsnmp_ioctl_ipaddress_extras_get(entry);
    if (NULL == extras)
        return -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        snmp_log_perror("_netsnmp_ioctl_ipaddress_set_v4: couldn't create socket");
        return -2;
    }
    memset(&ifrq, 0, sizeof(ifrq));

    if ('\0' == extras->name[0]) {
        const char *name = netsnmp_access_interface_name_find(entry->if_index);
        int   alias_idx;

        if (NULL == name) {
            DEBUGMSGT(("access:ipaddress:set",
                       "cant find name for index %" NETSNMP_PRIo "d\n",
                       entry->if_index));
            close(fd);
            return -1;
        }

        /*
         * search for unused alias
         */
        alias_idx = _next_alias(name);
        snprintf(ifrq.ifr_name, sizeof(ifrq.ifr_name), "%s:%d",
                 name, alias_idx);
    }
    else
        strlcpy(ifrq.ifr_name, (char *) extras->name, sizeof(ifrq.ifr_name));

    sin = (struct sockaddr_in*)&ifrq.ifr_addr;
    sin->sin_family = AF_INET;
    memcpy(&sin->sin_addr.s_addr, entry->ia_address,
           entry->ia_address_len);

    rc = ioctl(fd, SIOCSIFADDR, &ifrq);
    close(fd);
    if(rc < 0) {
        snmp_log(LOG_ERR,"error setting address\n");
        return -3;
    }

    return 0;
}

/**
 *
 * @retval  0 : no error
 * @retval -1 : bad parameter
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl failed
 */
int
_netsnmp_ioctl_ipaddress_delete_v4(netsnmp_ipaddress_entry * entry)
{
    struct ifreq                   ifrq;
    int                            rc, fd = -1;
    _ioctl_extras                 *extras;

    if (NULL == entry)
        return -1;

    netsnmp_assert(4 == entry->ia_address_len);

    extras = netsnmp_ioctl_ipaddress_extras_get(entry);
    if (NULL == extras)
        return -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        snmp_log_perror("_netsnmp_ioctl_ipaddress_delete_v4: couldn't create socket");
        return -2;
    }

    memset(&ifrq, 0, sizeof(ifrq));

    strlcpy(ifrq.ifr_name, (char *) extras->name, sizeof(ifrq.ifr_name));

    ifrq.ifr_flags = 0;

    rc = ioctl(fd, SIOCSIFFLAGS, &ifrq);
    close(fd);
    if(rc < 0) {
        snmp_log(LOG_ERR,"error deleting address\n");
        return -3;
    }

    return 0;
}


/**
 * Add/remove IPv6 address using ioctl.
 * @retval  0 : no error
 * @retval -1 : bad parameter
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl failed
 */
int
_netsnmp_ioctl_ipaddress_v6(netsnmp_ipaddress_entry * entry, int operation)
{
#ifdef linux
    /*
     * From linux/ipv6.h. It cannot be included because it collides
     * with netinet/in.h
     */
    struct in6_ifreq {
            struct in6_addr ifr6_addr;
            uint32_t        ifr6_prefixlen;
            int             ifr6_ifindex;
    };

    struct in6_ifreq               ifrq;
    int                            rc, fd = -1;

    DEBUGMSGT(("access:ipaddress:set", "_netsnmp_ioctl_ipaddress_set_v6 started\n"));

    if (NULL == entry)
        return -1;

    netsnmp_assert(16 == entry->ia_address_len);

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if(fd < 0) {
        snmp_log_perror("_netsnmp_ioctl_ipaddress_v6: couldn't create socket");
        return -2;
    }
    memset(&ifrq, 0, sizeof(ifrq));
    ifrq.ifr6_ifindex = entry->if_index;
    ifrq.ifr6_prefixlen = 64;

    memcpy(&ifrq.ifr6_addr, entry->ia_address,
           entry->ia_address_len);

    rc = ioctl(fd, operation, &ifrq);
    close(fd);
    if(rc < 0) {
        snmp_log(LOG_ERR,"error setting address: %s(%d)\n", strerror(errno), errno);
        return -3;
    }
    DEBUGMSGT(("access:ipaddress:set", "_netsnmp_ioctl_ipaddress_set_v6 finished\n"));
    return 0;
#else
    /* we don't support ipv6 on this platform (yet) */
    return -3;
#endif

}

/**
 *
 * @retval  0 : no error
 * @retval -1 : bad parameter
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl failed
 */
int
_netsnmp_ioctl_ipaddress_set_v6(netsnmp_ipaddress_entry * entry)
{
    return _netsnmp_ioctl_ipaddress_v6(entry, SIOCSIFADDR);
}

/**
 *
 * @retval  0 : no error
 * @retval -1 : bad parameter
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl failed
 */
int
_netsnmp_ioctl_ipaddress_delete_v6(netsnmp_ipaddress_entry * entry)
{
    return _netsnmp_ioctl_ipaddress_v6(entry, SIOCDIFADDR);
}

/**
 * get the interface count and populate the ifc_buf
 *
 * Note: the caller assumes responsibility for the ifc->ifc_buf
 *       memory, and should free() it when done.
 *
 * @retval -1 : malloc error
 */
int
netsnmp_access_ipaddress_ioctl_get_interface_count(int sd, struct ifconf * ifc)
{
    int lastlen = 0, i, i_max;
    struct ifconf ifc_tmp;

    if (NULL == ifc) {
        memset(&ifc_tmp, 0x0, sizeof(ifc_tmp));
        ifc = &ifc_tmp;
    }

    /*
     * Cope with lots of interfaces and brokenness of ioctl SIOCGIFCONF
     * on some platforms; see W. R. Stevens, ``Unix Network Programming
     * Volume I'', p.435.  
     */

    i_max = INT_MAX / sizeof(struct ifreq);
    for (i = 8; i <= i_max; i *= 2) {
        ifc->ifc_buf = calloc(i, sizeof(struct ifreq));
        if (NULL == ifc->ifc_buf) {
            snmp_log(LOG_ERR, "could not allocate memory for %d interfaces\n",
                     i);
            return -1;
        }
        ifc->ifc_len = i * sizeof(struct ifreq);

        if (ioctl(sd, SIOCGIFCONF, (char *) ifc) < 0) {
            if (errno != EINVAL || lastlen != 0) {
                /*
                 * Something has gone genuinely wrong.  
                 */
                snmp_log(LOG_ERR, "bad rc from ioctl, errno %d", errno);
                SNMP_FREE(ifc->ifc_buf);
                return -1;
            }
            /*
             * Otherwise, it could just be that the buffer is too small.  
             */
        } else {
            if (ifc->ifc_len == lastlen) {
                /*
                 * The length is the same as the last time; we're done.  
                 */
                break;
            }
            lastlen = ifc->ifc_len;
        }
        free(ifc->ifc_buf); /* no SNMP_FREE, getting ready to reassign */
    }

    if (ifc == &ifc_tmp)
        free(ifc_tmp.ifc_buf);

    return ifc->ifc_len / sizeof(struct ifreq);
}

/**
 */
static void
_print_flags(short flags)
{
/** Standard interface flags. */
    struct {
       short flag;
       const char *name;
    } map[] = {
        { IFF_UP,          "interface is up"},
        { IFF_BROADCAST,   "broadcast address valid"},
        { IFF_DEBUG,       "turn on debugging"},
        { IFF_LOOPBACK,    "is a loopback net"},
        { IFF_POINTOPOINT, "interface is has p-p link"},
        { IFF_NOTRAILERS,  "avoid use of trailers"},
        { IFF_RUNNING,     "resources allocated"},
        { IFF_NOARP,       "no ARP protocol"},
        { IFF_PROMISC,     "receive all packets"},
        { IFF_ALLMULTI,    "receive all multicast packets"},
        { IFF_MASTER,      "master of a load balancer"},
        { IFF_SLAVE,       "slave of a load balancer"},
        { IFF_MULTICAST,   "Supports multicast"},
        { IFF_PORTSEL,     "can set media type"},
        { IFF_AUTOMEDIA,   "auto media select active"},
    };
    short unknown = flags;
    size_t i;

    for(i = 0; i < sizeof(map)/sizeof(map[0]); ++i)
        if(flags & map[i].flag) {
            DEBUGMSGT_NC(("access:ipaddress:container","  %s\n", map[i].name));
            unknown &= ~map[i].flag;
        }

    if(unknown)
        DEBUGMSGT_NC(("access:ipaddress:container","  unknown 0x%x\n", unknown));
}
