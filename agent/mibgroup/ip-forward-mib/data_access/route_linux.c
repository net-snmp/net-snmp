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

#include "ip-forward-mib/ipCidrRouteTable/ipCidrRouteTable_constants.h"

/**
 *
 * @retval  0 success
 * @retval -1 no container specified
 * @retval -2 could not open /proc/net/route
 */
int
netsnmp_access_route_container_arch_load(netsnmp_container* container,
                                         u_int load_flags)
{
    FILE           *in;
    char            line[256];
    netsnmp_route_entry *entry = NULL;
    char            name[16];

    DEBUGMSGTL(("access:route:container",
                "route_container_arch_load (flags %p)\n", load_flags));

    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_if\n");
        return -1;
    }

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
        unsigned        use;

        entry = netsnmp_access_route_entry_create();

        /*
         * as with 1.99.14:
         * Iface Dest     GW       Flags RefCnt Use Metric Mask     MTU  Win IRTT
         * eth0  0A0A0A0A 00000000 05    0      0   0      FFFFFFFF 1500 0   0 
         */
        rc = sscanf(line, "%s %x %x %x %u %d %d %x %*d %*d %*d\n",
                    rtent_name, &entry->rt_dest, &entry->rt_nexthop,
                    /*
                     * XXX: fix type of the args 
                     */
                    &flags, &refcnt, &use, &entry->rt_metric1,
                    &entry->rt_mask);
        DEBUGMSGTL(("9:access:route:container", "line |%s|\n", line));
        if (8 != rc) {
            snmp_log(LOG_ERR,
                     "/proc/net/route data format error (%d!=8), line ==|%s|",
                     rc, line);
            continue;
        }

        strncpy(name, rtent_name, sizeof(name));
        name[ sizeof(name)-1 ] = 0;
        /*
         * linux says ``lo'', but the interface is stored as ``lo0'': 
         * xxx-rks: sez who? not on 2.4.20?
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

        if (flags & RTF_UP) {
            if (flags & RTF_GATEWAY) {
                entry->rt_type = IPCIDRROUTETYPE_REMOTE;
            } else {
                entry->rt_type = IPCIDRROUTETYPE_LOCAL;
            }
        } else 
            entry->rt_type = IPCIDRROUTETYPE_REJECT;
        
        entry->rt_proto = (flags & RTF_DYNAMIC)
            ? IPCIDRROUTEPROTO_ICMP : IPCIDRROUTEPROTO_LOCAL;

        // xxx-rks: does this belong here? probably not...
        entry->row_status = ROWSTATUS_ACTIVE;

        CONTAINER_INSERT(container, entry);
    }

    fclose(in);
    return 0;
}
