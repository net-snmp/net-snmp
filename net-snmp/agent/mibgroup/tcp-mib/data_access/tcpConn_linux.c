/*
 *  tcpConnTable MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/tcpConn.h>

#include "tcp-mib/tcpConnTable/tcpConnTable_constants.h"

/*
 * initialize arch specific storage
 *
 * @retval  0: success
 * @retval <0: error
 */
int
netsnmp_arch_tcpconn_entry_init(netsnmp_tcpconn_entry *entry)
{
    /*
     * init
     */
    return 0;
}

/*
 * cleanup arch specific storage
 */
void
netsnmp_arch_tcpconn_entry_cleanup(netsnmp_tcpconn_entry *entry)
{
    /*
     * cleanup
     */
}

/*
 * copy arch specific storage
 */
int
netsnmp_arch_tcpconn_entry_copy(netsnmp_tcpconn_entry *lhs,
                                  netsnmp_tcpconn_entry *rhs)
{
    return 0;
}

/*
 * delete an entry
 */
int
netsnmp_arch_tcpconn_delete(netsnmp_tcpconn_entry *entry)
{
    if (NULL == entry)
        return -1;
    /** xxx-rks:9 tcpConn delete not implemented */
    return -1;
}

/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
int
netsnmp_arch_tcpconn_container_load(netsnmp_container *container,
                                    u_int load_flags)
{
    int             rc = 0;
    FILE           *in;
    char            line[160];
    u_char          *buf;
    netsnmp_tcpconn_entry *entry;
    
    netsnmp_assert(NULL != container);

#define PROCFILE "/proc/net/tcp"
    if (!(in = fopen(PROCFILE, "r"))) {
        snmp_log(LOG_ERR,"could not open " PROCFILE "\n");
        return -2;
    }
    
    fgets(line, sizeof(line), in); /* skip header */

    /*
     *   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
     *   0: 00000000:8000 00000000:0000 0A 00000000:00000000 00:00000000 00000000    29        0 1028 1 df7b1b80 300 0 0 2 -1
     */
    while (fgets(line, sizeof(line), in)) {
        netsnmp_tcpconn_entry *entry;
        static int      linux_states[12] =
            { 1, 5, 3, 4, 6, 7, 11, 1, 8, 9, 2, 10 };
        int             state, rc, local_port, remote_port;

        /*
         */
        entry = netsnmp_access_tcpconn_entry_create();
        if(NULL == entry) {
            rc = -3;
            break;
        }

        if (5 != (rc = sscanf(line, "%*d: %x:%x %x:%x %x",
                              &entry->indexes[NETSNMP_TCPCONN_IDX_LOCAL_ADDR],
                              &local_port,
                              &entry->indexes[NETSNMP_TCPCONN_IDX_REMOTE_ADDR],
                              &remote_port, &state))) {
            DEBUGMSGT(("access:tcpconn:container",
                       "error parsing line (%d != 5)\n", rc));
            DEBUGMSGT(("access:tcpconn:container"," line '%s'\n", line));
            netsnmp_access_tcpconn_entry_free(entry);
            continue;
        }
        DEBUGMSGT(("verbose:access:tcpconn:container"," line '%s'\n", line));
        entry->indexes[NETSNMP_TCPCONN_IDX_LOCAL_PORT] =
            htons((unsigned short) local_port);
        entry->indexes[NETSNMP_TCPCONN_IDX_REMOTE_PORT] =
            htons((unsigned short) remote_port);
        entry->tcpConnState = (state & 0xf) < 12 ? linux_states[state & 0xf] : 2;

        /*
         * add entry to container
         */
        CONTAINER_INSERT(container, entry);
    }

    fclose(in);

    if(rc<0)
        return rc;

    return 0;
}
