/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/arp.h>
#include <net-snmp/data_access/interface.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

int _load_v4(netsnmp_container *container, int idx_offset);

/**
 */
int
netsnmp_access_arp_container_arch_load(netsnmp_container *container)
{
    int rc = 0, idx_offset = 0;

    rc = _load_v4(container, idx_offset);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_ARP_FREE_KEEP_CONTAINER;
        netsnmp_access_arp_container_free(container, flags);
        return rc;
    }

#if defined (INET6) && 0 /* xx-rks: arp for v6? */
    idx_offset = rc;

    rc = _load_v6(container, idx_offset);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_ARP_FREE_KEEP_CONTAINER;
        netsnmp_access_arp_container_free(container, flags);
    }
#endif

    /*
     * return no errors (0) if we found any interfaces
     */
    if(rc > 0)
        rc = 0;

    return rc;
}

/**
 */
int
_load_v4(netsnmp_container *container, int idx_offset)
{
    FILE           *in;
    char            line[128];
    int             rc = 0;
    netsnmp_arp_entry *entry;
    char           arp[3*NETSNMP_ACCESS_ARP_PHYSADDR_BUF_SIZE+1];
    char           *arp_token;
    int             i;

    netsnmp_assert(NULL != container);

#define PROCFILE "/proc/net/arp"
    if (!(in = fopen(PROCFILE, "r"))) {
        snmp_log(LOG_ERR,"could not open " PROCFILE "\n");
        return -2;
    }

    /*
     * Get rid of the header line 
     */
    fgets(line, sizeof(line), in);

    /*
     * IP address | HW | Flag | HW address      | Mask | Device
     * 192.168.1.4  0x1  0x2   00:40:63:CC:1C:8C  *      eth0
     */
    while (fgets(line, sizeof(line), in)) {
        
        int             za, zb, zc, zd;
        int             tmp_flags;
        char            ifname[21];

        rc = sscanf(line,
                    "%d.%d.%d.%d 0x%*x 0x%x %96s %*[^ ] %20s\n",
                    &za, &zb, &zc, &zd, &tmp_flags, arp, ifname);
        if (7 != rc) {
            snmp_log(LOG_ERR, PROCFILE " data format error (%d!=12)\n", rc);
            snmp_log(LOG_ERR, " line ==|%s|\n", line);
            continue;
        }
        DEBUGMSGTL(("access:arp:container",
                    "ip addr %d.%d.%d.%d, flags 0x%X, hw addr "
                    "%s, name %s\n",
                    za,zb,zc,zd, tmp_flags, arp, ifname ));

        /*
         * Invalidated entries have their flag set to 0.
         * * We want to ignore them 
         */
        if (tmp_flags == 0) {
            continue;
        }

        /*
         */
        entry = netsnmp_access_arp_entry_create();
        if(NULL == entry) {
            rc = -3;
            break;
        }

        /*
         * look up ifIndex
         */
        entry->if_index = netsnmp_access_interface_index_find(ifname);
        if(0 == entry->if_index) {
            snmp_log(LOG_ERR,"couldn't find ifIndex for '%s', skipping\n",
                     ifname);
            netsnmp_access_arp_entry_free(entry);
            continue;
        }

        /*
         * now that we've passed all the possible 'continue', assign
         * index offset.
         */
        entry->ns_arp_index = ++idx_offset;

        /*
         * parse ip addr
         */
        entry->arp_ipaddress[0] = za;
        entry->arp_ipaddress[1] = zb;
        entry->arp_ipaddress[2] = zc;
        entry->arp_ipaddress[3] = zd;
        entry->arp_ipaddress_len = 4;

        /*
         * parse hw addr
         */
        for (arp_token = strtok(arp, ":"), i=0; arp_token != NULL; arp_token = strtok(NULL, ":"), i++) {
            entry->arp_physaddress[i] = strtol(arp_token, NULL, 16);
        }
        entry->arp_physaddress_len = i;

        /*
         * what can we do with hw? from arp manpage:

         default  value  of  this  parameter is ether (i.e. hardware code
         0x01 for  IEEE  802.3  10Mbps  Ethernet).   Other  values  might
         include  network  technologies  such as ARCnet (arcnet) , PROnet
         (pronet) , AX.25 (ax25) and NET/ROM (netrom).
        */

        /*
         * parse mask
         */
        /* xxx-rks: what is mask? how to interpret '*'? */


        /*
         * process type
         */
        if(tmp_flags & ATF_PERM)
            entry->arp_type = INETNETTOMEDIATYPE_STATIC;
        else
            entry->arp_type = INETNETTOMEDIATYPE_DYNAMIC;

        /*
         * process status
         */
        /** entry->arp_status = ?; */

        /*
         * add entry to container
         */
        if (CONTAINER_INSERT(container, entry) < 0)
        {
            DEBUGMSGTL(("access:arp:container","error with arp_entry: insert into container failed.\n"));
            netsnmp_access_arp_entry_free(entry);
            continue;
        }
    }

    fclose(in);
    if( rc < 0 )
        return rc;

    return idx_offset;
}
