/*
 * standard Net-SNMP includes 
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/*
 * include our parent header 
 */
#include "etherlike-mib/dot3StatsTable/dot3StatsTable.h"
#include "etherlike-mib/dot3StatsTable/dot3StatsTable_data_access.h"
#include "etherlike-mib/dot3StatsTable/ioctl_imp_common.h"

/*
 * @retval  0 success
 * @retval -1 getifaddrs failed 
 * @retval -2 memory allocation failed
 */

struct ifname *
dot3stats_interface_name_list_get (struct ifname *list_head, int *retval)
{
    struct ifaddrs *addrs = NULL, *p = NULL;
    struct ifname *nameptr1=NULL, *nameptr2 = NULL;

    DEBUGMSGTL(("access:dot3StatsTable:interface_name_list_get",
                "called\n"));

    if ((getifaddrs(&addrs)) < 0) {
        DEBUGMSGTL(("access:dot3StatsTable:interface_name_list_get",
                    "getifaddrs failed\n"));
        snmp_log (LOG_ERR, "access:dot3StatsTable,interface_name_list_get, getifaddrs failed\n");
        *retval = -1;
        return NULL;
    }

    for (p = addrs; p; p = p->ifa_next) {

        if (!list_head) {
            if ( (list_head = (struct ifname *) malloc (sizeof(struct ifname))) < 0) {
                DEBUGMSGTL(("access:dot3StatsTable:interface_name_list_get",
                            "memory allocation failed\n"));
                snmp_log (LOG_ERR, "access:dot3StatsTable,interface_name_list_get, memory allocation failed\n");
                freeifaddrs(addrs);
                *retval = -2;
                return NULL;
            }
            memset (list_head, 0, sizeof (struct ifname));
            strncpy (list_head->name, p->ifa_name, IF_NAMESIZE);
            continue;
        }

         for (nameptr1 = list_head; nameptr1; nameptr2 = nameptr1, nameptr1 = nameptr1->ifn_next)
            if (!strncmp(p->ifa_name, nameptr1->name, IF_NAMESIZE))
                break;

        if (nameptr1)
            continue;

        if ( (nameptr2->ifn_next = (struct ifname *) malloc (sizeof(struct ifname))) < 0) {
            DEBUGMSGTL(("access:dot3StatsTable:interface_name_list_get",
                        "memory allocation failed\n"));
            snmp_log (LOG_ERR, "access:dot3StatsTable,interface_name_list_get, memory allocation failed\n");
            interface_name_list_free (list_head);
            freeifaddrs(addrs);
            *retval = -2;
            return NULL;
        }
        nameptr2 = nameptr2->ifn_next;
        memset (nameptr2, 0, sizeof (struct ifname));
        strncpy (nameptr2->name, p->ifa_name, IF_NAMESIZE);
        continue;

    }

    freeifaddrs(addrs);
    return list_head;
}

/*
 * @retval 0 success
 * @retval -1 invalid pointer
 */

int
dot3stats_interface_name_list_free (struct ifname *list_head)
{
    struct ifname *nameptr1 = NULL, *nameptr2 = NULL;

    DEBUGMSGTL(("access:dot3StatsTable:interface_name_list_free",
                "called\n"));

    if (!list_head) {
        snmp_log (LOG_ERR, "access:dot3StatsTable:interface_name_list_free: invalid pointer list_head");
        DEBUGMSGTL(("access:dot3StatsTable:interface_name_list_free",
                    "invalid pointer list_head\n"));
        return -1;
    }

    for (nameptr1 = list_head; nameptr1; nameptr1 = nameptr2) {
            nameptr2 = nameptr1->ifn_next;
            free (nameptr1);
    }

    return 0;
}

/*
 * @retval  0 : not found
 * @retval !0 : ifIndex
 */

int 
dot3stats_interface_ioctl_ifindex_get (int fd, const char *name) {
#ifndef SIOCGIFINDEX
    return 0;
#else
    struct ifreq    ifrq;
    int rc = 0;

    DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_ifindex_get", "called\n"));
                 
    rc = _dot3Stats_ioctl_get(fd, SIOCGIFINDEX, &ifrq, name);
    if (rc < 0) {
        DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_ifindex_get",
                    "error on interface '%s'\n", name));
        snmp_log (LOG_ERR, "access:dot3StatsTable:interface_ioctl_ifindex_get, error on interface '%s'\n", name);
        return 0;

    }

    return ifrq.ifr_ifindex;
#endif /* SIOCGIFINDEX */
}

/*
 * @retval  0 success
 * @retval -1 cannot get ETHTOOL_DRVINFO failed 
 * @retval -2 nstats zero - no statistcs available
 * @retval -3 memory allocation for holding the statistics failed
 * @retval -4 cannot get ETHTOOL_GSTRINGS information
 * @retval -5 cannot get ETHTOOL_GSTATS information
 * @retval -6 function not supported if HAVE_LINUX_ETHTOOL_H not defined
 */


int 
interface_ioctl_dot3stats_get (dot3StatsTable_rowreq_ctx *rowreq_ctx, int fd, const char *name) {

#ifdef HAVE_LINUX_ETHTOOL_H
    dot3StatsTable_data *data = &rowreq_ctx->data;
    struct ethtool_drvinfo driver_info;
    struct ethtool_gstrings *eth_strings;
    struct ethtool_stats *eth_stats;
    struct ifreq ifr; 
    unsigned int nstats, size_str, size_stats, i;
    int err;

    DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_get",
                "called\n"));

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, name);

    memset(&driver_info, 0, sizeof (driver_info));
    driver_info.cmd = ETHTOOL_GDRVINFO;
    ifr.ifr_data = (char *)&driver_info;

    err = _dot3Stats_ioctl_get(fd, SIOCETHTOOL, &ifr, name);
    if (err < 0) {
        DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_get",
                    "ETHTOOL_GETDRVINFO failed for interface |%s| \n", name));
        return -1;
    }

    nstats = driver_info.n_stats;
    if (nstats < 1) {
        DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_get",
                    "no stats available for interface |%s| \n", name));
        return -2;
    }

    size_str = nstats * ETH_GSTRING_LEN;
    size_stats = nstats * sizeof(u64);

    eth_strings = malloc(size_str + sizeof (struct ethtool_gstrings));
    if (!eth_strings) {
        DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_get",
                    "no memory available\n"));
        snmp_log (LOG_ERR, "access:dot3StatsTable,interface_ioctl_dot3Stats_get, no memory available\n");

        return -3;
    }
    memset (eth_strings, 0, (size_str + sizeof (struct ethtool_gstrings)));

    eth_stats = malloc (size_str + sizeof (struct ethtool_stats));
    if (!eth_stats) {
        free (eth_strings);
        DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_get",
                    "no memory available\n"));
        snmp_log (LOG_ERR, "access:dot3StatsTable,interface_ioctl_dot3Stats_get, no memory available\n");

        return -3;
    }
     memset (eth_stats, 0, (size_str + sizeof (struct ethtool_stats)));

    eth_strings->cmd = ETHTOOL_GSTRINGS;
    eth_strings->string_set = ETH_SS_STATS;
    eth_strings->len = nstats;
    ifr.ifr_data = (char *) eth_strings;
    err = _dot3Stats_ioctl_get(fd, SIOCETHTOOL, &ifr, name);
    if (err < 0) {
        DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_get",
                    "cannot get stats strings information for interface |%s| \n", name));
        snmp_log (LOG_ERR, "access:dot3StatsTable,interface_ioctl_dot3Stats_get, cannot get stats strings information for interface |%s| \n", name);

        free(eth_strings);
        free(eth_stats);
        return -4;
    }

    eth_stats->cmd = ETHTOOL_GSTATS;
    eth_stats->n_stats = nstats;
    ifr.ifr_data = (char *) eth_stats;
    err = _dot3Stats_ioctl_get(fd, SIOCETHTOOL, &ifr, name);
    if (err < 0) {
        DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_get",
                    "cannot get stats strings information for interface |%s| \n", name));
        snmp_log (LOG_ERR, "access:dot3StatsTable,interface_ioctl_dot3Stats_get, cannot get stats information for interface |%s| \n", name);

        free(eth_strings);
        free(eth_stats);
        return -5;
    }

    for (i = 0; i < nstats; i++) {
        char s[ETH_GSTRING_LEN];

        strncpy(s, (const char *) &eth_strings->data[i * ETH_GSTRING_LEN],
            ETH_GSTRING_LEN);
    
        if (DOT3STATSALIGNMENTERRORS(s)) {
            data->dot3StatsAlignmentErrors = (u_long)eth_stats->data[i];
            rowreq_ctx->column_exists_flags |= COLUMN_DOT3STATSALIGNMENTERRORS_FLAG;
        }

        if (DOT3STATSMULTIPLECOLLISIONFRAMES(s)) {
            data->dot3StatsMultipleCollisionFrames = (u_long)eth_stats->data[i];
            rowreq_ctx->column_exists_flags |= COLUMN_DOT3STATSMULTIPLECOLLISIONFRAMES_FLAG;
        }
            
        if (DOT3STATSLATECOLLISIONS(s)) {
            data->dot3StatsLateCollisions = (u_long)eth_stats->data[i];
            rowreq_ctx->column_exists_flags |= COLUMN_DOT3STATSLATECOLLISIONS_FLAG;
        }

        if (DOT3STATSSINGLECOLLISIONFRAMES(s)) {
            data->dot3StatsSingleCollisionFrames = (u_long)eth_stats->data[i];
            rowreq_ctx->column_exists_flags |= COLUMN_DOT3STATSSINGLECOLLISIONFRAMES_FLAG;
        }

        if (DOT3STATSEXCESSIVECOLLISIONS(s)) {
            data->dot3StatsExcessiveCollisions = (u_long)eth_stats->data[i];
            rowreq_ctx->column_exists_flags |= COLUMN_DOT3STATSEXCESSIVECOLLISIONS_FLAG;
        }
    }

    free(eth_strings);
    free(eth_stats);

    return 0;
#else
    return -6;
#endif
}


/*
 * @retval  0 success
 * @retval -1 ETHTOOL_GSET failed
 * @retval -2 function not supported if HAVE_LINUX_ETHTOOL_H not defined
 */

int
interface_ioctl_dot3stats_duplex_get(dot3StatsTable_rowreq_ctx *rowreq_ctx, int fd, const char* name) {

#ifdef HAVE_LINUX_ETHTOOL_H
    dot3StatsTable_data *data = &rowreq_ctx->data;
    struct ethtool_cmd edata;
    struct ifreq ifr;
    int err;

    DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_duplex_get",
                "called\n"));

    memset(&edata, 0, sizeof (edata));
    memset(&ifr, 0, sizeof (ifr));
    edata.cmd = ETHTOOL_GSET;
    ifr.ifr_data = (char *)&edata;

    err = _dot3Stats_ioctl_get (fd, SIOCETHTOOL, &ifr, name);
    if (err < 0) {
        DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_duplex_get",
                    "ETHTOOL_GSET failed\n"));

        return -1;
    }
    
    if (err == 0) {
        rowreq_ctx->column_exists_flags |= COLUMN_DOT3STATSDUPLEXSTATUS_FLAG;
        switch (edata.duplex) {
        case DUPLEX_HALF:
            data->dot3StatsDuplexStatus = (u_long) DOT3STATSDUPLEXSTATUS_HALFDUPLEX;
            break;
        case DUPLEX_FULL:
            data->dot3StatsDuplexStatus = (u_long) DOT3STATSDUPLEXSTATUS_FULLDUPLEX;
            break;
        default:
            data->dot3StatsDuplexStatus = (u_long) DOT3STATSDUPLEXSTATUS_UNKNOWN;
            break;
        };
    }

    DEBUGMSGTL(("access:dot3StatsTable:interface_ioctl_dot3Stats_duplex_get",
                "ETHTOOL_GSET processed\n"));
    return err;
#else
    return -2;
#endif
}



/* ioctl wrapper
 *
 * @param      fd : socket fd to use w/ioctl, or -1 to open/close one
 * @param  which
 * @param ifrq
 * param ifentry : ifentry to update
 * @param name
 *
 * @retval  0 : success
 * @retval -1 : invalid parameters
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl call failed
 */
int
_dot3Stats_ioctl_get(int fd, int which, struct ifreq *ifrq, const char* name)
{
    int ourfd = -1, rc = 0;

    DEBUGMSGTL(("access:dot3StatsTable:ioctl", "_dot3Stats_ioctl_get\n"));

    /*
     * sanity checks
     */
    if(NULL == name) {
        DEBUGMSGTL(("access:dot3StatsTable:ioctl",
                    "_dot3Stats_ioctl_get invalid ifname '%s'\n", name));
        snmp_log (LOG_ERR, "access:dot3StatsTable:ioctl, _dot3Stats_ioctl_get error on interface '%s'\n", name);
        return -1;
    }

    /*
     * create socket for ioctls
     */
    if(fd < 0) {
        fd = ourfd = socket(AF_INET, SOCK_DGRAM, 0);
        if(ourfd < 0) {
            DEBUGMSGTL(("access:dot3StatsTable:ioctl",
                        "dot3Stats_ioctl_get couldn't create a socket\n", name));
            snmp_log (LOG_ERR, "access:dot3StatsTable:ioctl, _dot3Stats_ioctl_get error on interface '%s'\n", name);

            return -2;
        }
    }

    strncpy(ifrq->ifr_name, name, sizeof(ifrq->ifr_name));
    ifrq->ifr_name[ sizeof(ifrq->ifr_name)-1 ] = 0;
    rc = ioctl(fd, which, ifrq);
    if (rc < 0) {
        DEBUGMSGTL(("access:dot3StatsTable:ioctl",
                    "dot3Stats_ioctl_get ioctl %d returned %d\n", which, rc));
        rc = -3;
    }

    if(ourfd >= 0)
        close(ourfd);

    return rc;
}


