/*
 *  Interface MIB architecture support
 *
 * $Id: ipv6scopezone_linux.c 14170 2007-04-29 02:22:12Z varun_c $
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/scopezone.h>

#if defined (NETSNMP_ENABLE_IPV6)
static int _scopezone_v6(netsnmp_container* container, int idx_offset);
#endif

/*
 *
 * @retval  0 success
 * @retval -1 no container specified
 * @retval -2 could not open file
 * @retval -3 could not create entry (probably malloc)
 * @retval -4 file format error
 */
int
netsnmp_access_scopezone_container_arch_load(netsnmp_container* container,
                                             u_int load_flags)
{
    int rc1 = 0, idx_offset = 0;
#if defined (NETSNMP_ENABLE_IPV6)

    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_scopezone_\n");
        return -1;
    }

    rc1 = _scopezone_v6(container, idx_offset);
#endif
    if(rc1 > 0)
        rc1 = 0;
    return rc1;
}

#if defined (NETSNMP_ENABLE_IPV6)
static int
_scopezone_v6(netsnmp_container* container, int idx_offset)
{

    FILE           *in;
    char            line[80], addr[40];
    int             if_index, pfx_len, scope, flags, rc = 0;
    netsnmp_v6scopezone_entry *entry;
    static int      log_open_err = 1;
    
    netsnmp_assert(NULL != container);

#define PROCFILE "/proc/net/if_inet6"
    if (!(in = fopen(PROCFILE, "r"))) {
        if (1 == log_open_err) {
            snmp_log(LOG_ERR,"could not open " PROCFILE "\n");
            log_open_err = 0;
        }
        return -2;
    }
    /*
     * if we hadn't been able to open file and turned of err logging,
     * turn it back on now that we opened the file.
     */
    if (0 == log_open_err)
        log_open_err = 1;

    /*
     * address index prefix_len scope status if_name
     */
    while (fgets(line, sizeof(line), in)) {
        /*
         * fe800000000000000200e8fffe5b5c93 05 40 20 80 eth0
         *             A                    D  P  S  F  I
         * A: address
         * D: device number
         * P: prefix len
         * S: scope (see include/net/ipv6.h, net/ipv6/addrconf.c)
         * F: flags (see include/linux/rtnetlink.h, net/ipv6/addrconf.c)
         * I: interface
         */
        rc = sscanf(line, "%39s %02x %02x %02x %02x\n",
                    addr, &if_index, &pfx_len, &scope, &flags);
        if( 5 != rc ) {
            snmp_log(LOG_ERR, PROCFILE " data format error (%d!=5), line ==|%s|\n",
                     rc, line);
            continue;
        }
        DEBUGMSGTL(("access:scopezone:container",
                    "addr %s, index %d, pfx %d, scope %d, flags 0x%X\n",
                    addr, if_index, pfx_len, scope, flags));
        /*
         */
        entry = netsnmp_access_scopezone_entry_create();
        if(NULL == entry) {
            rc = -3;
            break;
        }
        entry->ns_scopezone_index = ++idx_offset;
        entry->index = if_index;
        entry->scopezone_linklocal = if_index;
 
        CONTAINER_INSERT(container, entry);
    }
    fclose(in);
    if(rc<0)
        return rc;

    return idx_offset;
}
#endif 
