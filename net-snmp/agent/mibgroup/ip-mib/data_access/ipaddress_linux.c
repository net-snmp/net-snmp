/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/ipaddress.h>

#include <errno.h>
#include <sys/ioctl.h>

#include "ipaddress_ioctl.h"

/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
int
netsnmp_access_ipaddress_container_arch_load(netsnmp_container *container)
{
    int rc = 0, idx_offset = 0;

    rc = _netsnmp_access_ipaddress_container_ioctl_load_v4(container, idx_offset);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
        netsnmp_access_ipaddress_container_free(container, flags);
        return rc;
    }

#if defined (INET6)
    idx_offset = rc;

    rc = _load_v6(container, idx_offset);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
        netsnmp_access_ipaddress_container_free(container, flags);
    }
#endif

    /*
     * return no errors (0) if we found any interfaces
     */
    if(rc > 0)
        rc = 0;

    return rc;
}

#if defined (INET6)
/**
 */
int
_load_v6(netsnmp_container *container, int idx_offset)
{
    FILE           *in;
    char            line[80], addr[33], if_name[9];
    u_char          *buf;
    int             if_index, pfx_len, scope, flags, rc, in_len, out_len;
    netsnmp_ipaddress_entry *entry;
    
    assert(NULL != container);

#define PROCFILE "/proc/net/if_inet6"
    if (!(in = fopen(PROCFILE, "r"))) {
        snmp_log(LOG_ERR,"could not open " PROCFILE "\n");
        return -2;
    }

    /*
     * address index prefix_len scope status if_name
     */
    while (fgets(line, sizeof(line), in)) {
        
        rc = sscanf(line, "%32s %02x %02x %02x %02x %8s\n",
                    addr, &if_index, &pfx_len, &scope, &flags, if_name);
        if( 6 != rc ) {
            snmp_log(LOG_ERR, PROCFILE " data format error (%d!=6), line ==|%s|\n",
                     rc, line);
            continue;
        }
        DEBUGMSGTL(("access:ipaddress:container",
                    "addr %s, index %d, pfx %d, scope %d, flags 0x%X, name %s\n",
                    addr, if_index, pfx_len, scope, flags, if_name));
        /*
         */
        entry = netsnmp_access_ipaddress_entry_create();
        if(NULL == entry) {
            rc = -3;
            break;
        }

        in_len = entry->ia_address_len = sizeof(entry->ia_address);
        netsnmp_assert(16 == in_len);
        out_len = 0;
        buf = entry->ia_address;
        if(1 != snmp_hex_to_binary(&buf,
                                   &in_len, &out_len, 0, addr)) {
            snmp_log(LOG_ERR,"error parsing '%s', skipping\n",
                     entry->ia_address);
            netsnmp_access_ipaddress_entry_free(entry);
            continue;
        }
        netsnmp_assert(16 == out_len);
        entry->ia_address_len = out_len;

        entry->ns_ia_index = ++idx_offset;

        /*
         */
#ifndef NETSNMP_USE_IOCTL_IFINDEX
        /*
         * there is an iotcl to get an ifindex, but I'm not sure that
         * it has the correct characteristics required to be the actual
         * ifIndex for the mib, so we'll use the netsnmp interface method
         * (which is based on the interface name).
         */
        entry->if_index = netsnmp_access_interface_index_find(ifrp->ifr_name);
#else
        entry->if_index = if_index;
#endif

        entry->ia_flags = flags;

        entry->ia_type = 1; /* assume unicast? */

        /** entry->ia_prefix_oid ? */

        /** entry->ia_status = ?; */

        /*
         * can we figure out if an address is from DHCP?
         * use manual until then...
         */
        entry->ia_origin = 2; /* 2 = manual */

        // xxx-rks: what can we do with scope?

        /*
         * add entry to container
         */
        CONTAINER_INSERT(container, entry);
    }

    if(rc<0)
        return rc;

    return idx_offset;
}
#endif
