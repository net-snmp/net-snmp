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
#include <net-snmp/data_access/route.h>

#include "ip-forward-mib/inetCidrRouteTable/inetCidrRouteTable_constants.h"

static int
_load_ipv4(netsnmp_container* container, u_long *index )
{
    FILE           *in;
    char            line[256];
    netsnmp_route_entry *entry = NULL;
    char            name[16];

    DEBUGMSGTL(("access:route:container",
                "route_container_arch_load ipv4\n"));

    assert(NULL != container);

    /*
     * fetch routes from the proc file-system:
     */
    if (!(in = fopen("/proc/net/route", "r"))) {
        snmp_log(LOG_ERR, "cannot open /proc/net/route\n");
        return -2;
    }

    fgets(line, sizeof(line), in); /* skip header */

    while (fgets(line, sizeof(line), in)) {
        char            rtent_name[32];
        int             refcnt, flags, rc;
        u_int32_t       dest, nexthop, mask;
        unsigned        use;

        entry = netsnmp_access_route_entry_create();

        /*
         * as with 1.99.14:
         * Iface Dest     GW       Flags RefCnt Use Metric Mask     MTU  Win IRTT
         * eth0  0A0A0A0A 00000000 05    0      0   0      FFFFFFFF 1500 0   0 
         */
        rc = sscanf(line, "%s %x %x %x %u %d %d %x %*d %*d %*d\n",
                    rtent_name, &dest, &nexthop,
                    /*
                     * XXX: fix type of the args 
                     */
                    &flags, &refcnt, &use, &entry->rt_metric1,
                    &mask);
        DEBUGMSGTL(("9:access:route:container", "line |%s|\n", line));
        if (8 != rc) {
            snmp_log(LOG_ERR,
                     "/proc/net/route data format error (%d!=8), line ==|%s|",
                     rc, line);
            continue;
        }

        /*
         * temporary null terminated name
         */
        strncpy(name, rtent_name, sizeof(name));
        name[ sizeof(name)-1 ] = 0;
        /*
         * linux says ``lo'', but the interface is stored as ``lo0'': 
         * xxx-rks: sez who? stored where? not on 2.4.20...
         */
        //if (!strcmp(name, "lo"))
        //   strcat(name, "0");

        // xxx-rks: how to make sure interfaces has been loaded?
        entry->if_index = se_find_value_in_slist("interfaces", name);
        if(SE_DNE == entry->if_index) {
            snmp_log(LOG_ERR,"unknown interface '%s' in /proc/net/route\n",
                     name);
            netsnmp_access_route_entry_free(entry);
            continue;
        }
         /*
         * arbitrary index
         */
        entry->ns_rt_index = ++(*index);

#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
        entry->rt_mask = mask;
        /** entry->rt_tos = XXX; */
        /** rt info ?? */
#endif
        /*
         * copy dest & next hop
         */
        entry->rt_dest_type = INETADDRESSTYPE_IPV4;
        entry->rt_dest_len = 4;
        dest = htonl(dest);
        memcpy(entry->rt_dest, &dest, 4);

        entry->rt_nexthop_type = INETADDRESSTYPE_IPV4;
        entry->rt_nexthop_len = 4;
        nexthop = htonl(nexthop);
        memcpy(entry->rt_nexthop, &nexthop, 4);

        /*
         * count bits in mask
         */
        while (0x80000000 & mask) {
            ++entry->rt_pfx_len;
            mask = mask << 1;
        }

#ifdef USING_IP_FORWARD_MIB_INETCIDRROUTETABLE_INETCIDRROUTETABLE_MODULE
        /** policy info ?? */
#endif

        /*
         * get protocol and type from flags
         */
        if (flags & RTF_UP) {
            if (flags & RTF_GATEWAY) {
                entry->rt_type = INETCIDRROUTETYPE_REMOTE;
            } else {
                entry->rt_type = INETCIDRROUTETYPE_LOCAL;
            }
        } else 
            entry->rt_type = INETCIDRROUTETYPE_REJECT;
        
        entry->rt_proto = (flags & RTF_DYNAMIC)
            ? IANAIPROUTEPROTOCOL_ICMP : IANAIPROUTEPROTOCOL_LOCAL;

        /*
         * insert into container
         */
        CONTAINER_INSERT(container, entry);
    }

    fclose(in);
    return 0;
}

#ifdef INET6
static int
_load_ipv6(netsnmp_container* container, u_long *index )
{
    DEBUGMSGTL(("access:route:container",
                "route_container_arch_load ipv6\n"));

    assert(NULL != container);

    return 0;
}
#endif

/** arch specific load
 * @internal
 *
 * @retval  0 success
 * @retval -1 no container specified
 * @retval -2 could not open data file
 */
int
netsnmp_access_route_container_arch_load(netsnmp_container* container,
                                         u_int load_flags)
{
    u_long          count = 0;
    int             rc;

    DEBUGMSGTL(("access:route:container",
                "route_container_arch_load (flags %p)\n", load_flags));

    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_route\n");
        return -1;
    }

    rc = _load_ipv4(container, &count);
    
#ifdef INET6
    if((0 != rc) || (load_flags & NETSNMP_ACCESS_ROUTE_LOAD_IPV4_ONLY))
        return rc;

    rc = _load_ipv6(container, &count);
#endif

    return rc;
}
