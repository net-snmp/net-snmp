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

static int _get_interface_count(int sd, struct ifconf * ifc);
static void _print_flags(short flags);

/**
 */
int
netsnmp_access_ipaddress_container_arch_load(netsnmp_container *container)
{
    int rc = 0, idx_offset = 0;

    rc = netsnmp_access_ipaddress_container_ioctl_load_v4(container, idx_offset);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
        netsnmp_access_ipaddress_container_free(container, flags);
        return rc;
    }

#if defined (INET6)
    idx_offset += rc;

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
#define PROCFILE "/proc/net/if_inet6"

#define IPV6_ADDR_ANY           0x0000U
#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U
#define IPV6_ADDR_COMPATv4      0x0080U
    
    u_char *buf;
    int if_index, pfx_len, scope, flags, rc, in_len, out_len;
    netsnmp_ipaddress_entry *entry;
    
    assert(NULL != container);

    if (!(in = fopen(PROCFILE, "r"))) {
        snmp_log(LOG_ERR,"could not open " PROCFILE "\n");
        return -2;
    }

    snmp_log(LOG_ERR,"\n\n*** proc belongs in ipaddress_linux.c, not ioctl ***\n\n\n");
    
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

        entry->if_index = if_index;
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

    return rc;
}
#endif
