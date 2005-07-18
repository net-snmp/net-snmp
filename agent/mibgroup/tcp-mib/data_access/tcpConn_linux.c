/*
 *  tcpConnTable MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/tcpConn.h>

#include "tcp-mib/tcpConnectionTable/tcpConnectionTable_constants.h"
#include "tcp-mib/data_access/tcpConn_private.h"

static int
linux_states[12] = { 1, 5, 3, 4, 6, 7, 11, 1, 8, 9, 2, 10 };

static int _load4(netsnmp_container *container, u_int flags);
#if defined (INET6)
static int _load6(netsnmp_container *container, u_int flags);
#endif

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
#warning "tcpConn delete not implemented"
    return -1;
}


/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
int
netsnmp_arch_tcpconn_container_load(netsnmp_container *container,
                                    u_int load_flags )
{
    int rc = 0;

    rc = _load4(container, load_flags);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_TCPCONN_FREE_KEEP_CONTAINER;
        netsnmp_access_tcpconn_container_free(container, flags);
        return rc;
    }

#if defined (INET6)
    rc = _load6(container, load_flags);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_TCPCONN_FREE_KEEP_CONTAINER;
        netsnmp_access_tcpconn_container_free(container, flags);
        return rc;
    }
#endif

    return 0;
}

/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
static int
_load4(netsnmp_container *container, u_int load_flags)
{
    int             rc = 0;
    FILE           *in;
    char            line[160];
    
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
        int             state, rc, local_port, remote_port, buf_len, offset, tmp_state;
        u_char          local_addr[10], remote_addr[10];
        u_char         *tmp_ptr;

        if (5 != (rc = sscanf(line, "%*d: %8[0-9A-Z]:%x %8[0-9A-Z]:%x %x",
                              local_addr, &local_port,
                              remote_addr, &remote_port, &tmp_state))) {
            DEBUGMSGT(("access:tcpconn:container",
                       "error parsing line (%d != 5)\n", rc));
            DEBUGMSGT(("access:tcpconn:container"," line '%s'\n", line));
            continue;
        }
        DEBUGMSGT(("verbose:access:tcpconn:container"," line '%s'\n", line));

        /*
         * check if we care about listen state
         */
        state = (tmp_state & 0xf) < 12 ? linux_states[tmp_state & 0xf] : 2;
        if (load_flags) {
            if (TCPCONNECTIONSTATE_LISTEN == state) {
                if (load_flags & NETSNMP_ACCESS_TCPCONN_LOAD_NOLISTEN) {
                    DEBUGMSGT(("verbose:access:tcpconn:container",
                               " skipping listen\n"));
                    continue;
                }
            }
            else if (load_flags & NETSNMP_ACCESS_TCPCONN_LOAD_ONLYLISTEN) {
                    DEBUGMSGT(("verbose:access:tcpconn:container",
                               " skipping non-listen\n"));
                    continue;
            }
        }

        /*
         */
        entry = netsnmp_access_tcpconn_entry_create();
        if(NULL == entry) {
            rc = -3;
            break;
        }

        entry->loc_port = htons((unsigned short) local_port);
        entry->rmt_port = htons((unsigned short) remote_port);
        entry->tcpConnState = state;
        buf_len = strlen(local_addr);
        netsnmp_assert(8 == buf_len);
        offset = 0;
        tmp_ptr = entry->loc_addr;
        rc = netsnmp_hex_to_binary(&tmp_ptr, &buf_len,
                                   &offset, 0, local_addr, NULL);
        entry->loc_addr_len = offset;
        if ( 4 != entry->loc_addr_len ) {
            DEBUGMSGT(("access:tcpconn:container",
                       "error parsing local addr (%d != 4)\n",
                       entry->loc_addr_len));
            DEBUGMSGT(("access:tcpconn:container"," line '%s'\n", line));
            netsnmp_access_tcpconn_entry_free(entry);
            continue;
        }

        buf_len = strlen(remote_addr);
        netsnmp_assert(8 == buf_len);
        offset = 0;
        tmp_ptr = entry->rmt_addr;
        rc = netsnmp_hex_to_binary(&tmp_ptr, &buf_len,
                                   &offset, 0, remote_addr, NULL);
        entry->rmt_addr_len = offset;
        if ( 4 != entry->rmt_addr_len ) {
            DEBUGMSGT(("access:tcpconn:container",
                       "error parsing remote addr (%d != 4)\n",
                       entry->rmt_addr_len));
            DEBUGMSGT(("access:tcpconn:container"," line '%s'\n", line));
            netsnmp_access_tcpconn_entry_free(entry);
            continue;
        }

        /*
         * add entry to container
         */
        entry->arbitrary_index = CONTAINER_SIZE(container) + 1;
        CONTAINER_INSERT(container, entry);
    }

    fclose(in);

    if(rc<0)
        return rc;

    return 0;
}

#if defined (INET6)
#warning "using ipv6"
/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
static int
_load6(netsnmp_container *container, u_int load_flags)
{
    int             rc = 0;
    FILE           *in;
    char            line[180];
    
    netsnmp_assert(NULL != container);

#undef PROCFILE
#define PROCFILE "/proc/net/tcp6"
    if (!(in = fopen(PROCFILE, "r"))) {
        snmp_log(LOG_ERR,"could not open " PROCFILE "\n");
        return -2;
    }
    
    fgets(line, sizeof(line), in); /* skip header */

    /*
     *   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
     *  0: 00000000000000000000000000000001:1466 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   500        0 326699 1 efb81580 3000 0 0 2 -1
     */
    while (fgets(line, sizeof(line), in)) {
        netsnmp_tcpconn_entry *entry;
        int             state, rc, local_port, remote_port, buf_len, offset,
                        tmp_state;
        u_char          local_addr[48], remote_addr[48];
        u_char         *tmp_ptr;

        if (5 != (rc = sscanf(line, "%*d: %47[0-9A-Z]:%x %47[0-9A-Z]:%x %x",
                              local_addr, &local_port,
                              remote_addr, &remote_port, &tmp_state))) {
            DEBUGMSGT(("access:tcpconn:container",
                       "error parsing line (%d != 5)\n", rc));
            DEBUGMSGT(("access:tcpconn:container"," line '%s'\n", line));
            continue;
        }
        DEBUGMSGT(("verbose:access:tcpconn:container"," line '%s'\n", line));

        /*
         * check if we care about listen state
         */
        state = (tmp_state & 0xf) < 12 ? linux_states[tmp_state & 0xf] : 2;
        if (load_flags) {
            if (TCPCONNECTIONSTATE_LISTEN == state) {
                if (load_flags & NETSNMP_ACCESS_TCPCONN_LOAD_NOLISTEN) {
                    DEBUGMSGT(("verbose:access:tcpconn:container",
                               " skipping listen\n"));
                    continue;
                }
            }
            else if (load_flags & NETSNMP_ACCESS_TCPCONN_LOAD_ONLYLISTEN) {
                    DEBUGMSGT(("verbose:access:tcpconn:container",
                               " skipping non-listen\n"));
                    continue;
            }
        }

        /*
         */
        entry = netsnmp_access_tcpconn_entry_create();
        if(NULL == entry) {
            rc = -3;
            break;
        }

        entry->loc_port = htons((unsigned short) local_port);
        entry->rmt_port = htons((unsigned short) remote_port);
        entry->tcpConnState = state;

        buf_len = strlen(local_addr);
        offset = 0;
        tmp_ptr = entry->loc_addr;
        rc = netsnmp_hex_to_binary(&tmp_ptr, &buf_len,
                                   &offset, 0, local_addr, NULL);
        entry->loc_addr_len = offset;
        if (( 16 != entry->loc_addr_len ) && ( 20 != entry->loc_addr_len )) {
            DEBUGMSGT(("access:tcpconn:container",
                       "error parsing local addr (%d != 16|20)\n",
                       entry->loc_addr_len));
            DEBUGMSGT(("access:tcpconn:container"," line '%s'\n", line));
            netsnmp_access_tcpconn_entry_free(entry);
            continue;
        }

        buf_len = strlen(remote_addr);
        offset = 0;
        tmp_ptr = entry->rmt_addr;
        rc = netsnmp_hex_to_binary(&tmp_ptr, &buf_len,
                                   &offset, 0, remote_addr, NULL);
        entry->rmt_addr_len = offset;
        if (( 16 != entry->rmt_addr_len ) && ( 20 != entry->rmt_addr_len )) {
            DEBUGMSGT(("access:tcpconn:container",
                       "error parsing remote addr (%d != 16|20)\n",
                       entry->rmt_addr_len));
            DEBUGMSGT(("access:tcpconn:container"," line '%s'\n", line));
            netsnmp_access_tcpconn_entry_free(entry);
            continue;
        }


        /*
         * add entry to container
         */
        entry->arbitrary_index = CONTAINER_SIZE(container) + 1;
        CONTAINER_INSERT(container, entry);
    }

    fclose(in);

    if(rc<0)
        return rc;

    return 0;
}
#endif /* INET6 */
