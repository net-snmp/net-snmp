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
#include <net-snmp/data_access/interface.h>

#include <errno.h>
#include <sys/ioctl.h>

static int _get_interface_count(int sd, struct ifconf * ifc);
static void _print_flags(short flags);

/**
 */
int
_netsnmp_access_ipaddress_container_ioctl_load_v4(netsnmp_container *container,
                                                  int idx_offset)
{
    int             i, sd, rc = 0, interfaces = 0;
    struct ifconf   ifc;
    struct ifreq   *ifrp;
    struct sockaddr save_addr;
    netsnmp_ipaddress_entry *entry;

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snmp_log(LOG_ERR, "could not create socket\n");
        return -1;
    }

    interfaces = _get_interface_count(sd, &ifc);
    if(interfaces < 0) {
        close(sd);
        return -2;
    }
    netsnmp_assert(NULL != ifc.ifc_buf);
    DEBUGMSGTL(("access:ipaddress:container", "processing %d interfaces\n", interfaces));

    ifrp = ifc.ifc_req;
    for(i=0; i < interfaces; ++i, ++ifrp) {

        DEBUGMSGTL(("access:ipaddress:container",
                    " interface %d, %s\n", i, ifrp->ifr_name));
        /*
         */
        entry = netsnmp_access_ipaddress_entry_create();
        if(NULL == entry) {
            rc = -3;
            break;
        }
        entry->ns_ia_index = ++idx_offset;

        /*
         * each time we make an ioctl, we need to specify the address, but
         * it will be overwritten in the call. so we save address here.
         */
        save_addr = ifrp->ifr_addr;

        /*
         * set indexes
         */
        switch(ifrp->ifr_addr.sa_family) {
            case AF_INET: {
                struct sockaddr_in * si =
                    (struct sockaddr_in *) &ifrp->ifr_addr;
                entry->ia_address_len = sizeof(si->sin_addr.s_addr);
                memcpy(entry->ia_address, &si->sin_addr.s_addr,
                       entry->ia_address_len);
            }
                break;
                
            case AF_INET6: {
                struct sockaddr_in6 * si =
                    (struct sockaddr_in6 *) &ifrp->ifr_addr;

                entry->ia_address_len = sizeof(si->sin6_addr.s6_addr);
                memcpy(entry->ia_address, &si->sin6_addr.s6_addr,
                       entry->ia_address_len);
            }
                break;

            default:
                snmp_log(LOG_ERR,"unknown if family %d\n",
                         ifrp->ifr_addr.sa_family);
                netsnmp_access_ipaddress_entry_free(entry);
                continue;
        }

        /*
         * get ifindex
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
        /*
         * get ifindex. not sure how if it is appropriate for use as
         * the mib index.
         */
        if (ioctl(sd, SIOCGIFINDEX, ifrp) < 0) {
            snmp_log(LOG_ERR,
                     "error getting if_index for interface %d\n", i);
            netsnmp_access_ipaddress_entry_free(entry);
            continue;
        }
        entry->if_index = ifrp->ifr_ifindex;
#endif

        /*
         * get flags
         */
        ifrp->ifr_addr = save_addr;
        if (ioctl(sd, SIOCGIFFLAGS, ifrp) < 0) {
            snmp_log(LOG_ERR,
                     "error getting if_flags for interface %d\n", i);
            netsnmp_access_ipaddress_entry_free(entry);
        }
        entry->ia_flags = ifrp->ifr_flags;

        entry->ia_type = 1; /* assume unicast? */

        /** entry->ia_prefix_oid ? */

        /*
         * per the MIB:
         *   In the absence of other information, an IPv4 address is
         *   always preferred(1).
         */
        entry->ia_status = 1;

        /*
         * can we figure out if an address is from DHCP?
         * use manual until then...
         */
        entry->ia_origin = 2; /* 2 = manual */

        DEBUGIF("access:ipaddress:container") {
            DEBUGMSGT_NC(("access:ipaddress:container",
                          " if %d: addr len %d, index 0x%x\n",
                          i, entry->ia_address_len, entry->if_index));
            DEBUGMSGT_NC(("access:ipaddress:container", "flags 0x%x\n",
                          entry->ia_flags));
            _print_flags(entry->ia_flags);

        }

        /*
         * add entry to container
         */
        CONTAINER_INSERT(container, entry);
    }

    /*
     * clean up
     */
    free(ifc.ifc_buf);
    close(sd);

    /*
     * return number of interfaces seen
     */
    if(rc < 0)
        return rc;

    return idx_offset;
}

/**
 */
static int
_get_interface_count(int sd, struct ifconf * ifc)
{
    int lastlen = 0, i;

    assert(NULL != ifc);

    /*
     * Cope with lots of interfaces and brokenness of ioctl SIOCGIFCONF
     * on some platforms; see W. R. Stevens, ``Unix Network Programming
     * Volume I'', p.435.  
     */

    for (i = 8;; i *= 2) {
        ifc->ifc_buf = calloc(i, sizeof(struct ifreq));
        if (NULL == ifc->ifc_buf) {
            snmp_log(LOG_ERR, "could not allocate memory for %d interfaces\n",
                     i);
            break;
        }
        ifc->ifc_len = i * sizeof(struct ifreq);

        if (ioctl(sd, SIOCGIFCONF, (char *) ifc) < 0) {
            if (errno != EINVAL || lastlen != 0) {
                /*
                 * Something has gone genuinely wrong.  
                 */
                snmp_log(LOG_ERR, "bad rc from ioctl, errno %d", errno);
                SNMP_FREE(ifc->ifc_buf);
                break;
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
    int i;

    for(i = 0; i < sizeof(map)/sizeof(map[0]); ++i)
        if(flags & map[i].flag) {
            DEBUGMSGT_NC(("access:ipaddress:container","  %s\n", map[i].name));
            unknown &= ~map[i].flag;
        }

    if(unknown)
        DEBUGMSGT_NC(("access:ipaddress:container","  unknown 0x%x\n", unknown));
}

