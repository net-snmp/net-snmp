/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"
#include "if-mib/ifTable/ifTable_constants.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/interface.h>

#include <net/if.h>
#include <sys/ioctl.h>

/**
 * interface entry physaddr ioctl wrapper
 *
 * @param      fd : socket fd to use w/ioct, or -1 to open/close one
 * @param ifentry : ifentry to update
 *
 * @retval  0 : success
 * @retval -1 : ioctl not available
 * @retval -2 : invalid parameters
 * @retval -3 : couldn't create socket
 * @retval -4 : malloc error
 * @retval -5 : ioctl call failed
 */
int
netsnmp_access_interface_ioctl_physaddr_get(int fd,
                                            netsnmp_interface_entry *ifentry)
{
#ifndef SIOCGIFHWADDR
    return -1;
#else
    struct ifreq    ifrq;
    int ourfd = -1, rc = 0;

    /*
     * sanity checks
     */
    if((NULL == ifentry) || (NULL == ifentry->if_name)) {
        snmp_log(LOG_ERR, "invalid ifentry\n");
        return -2;
    }

    /*
     * create socket for ioctls
     */
    if(fd < 0) {
        fd = ourfd = socket(AF_INET, SOCK_DGRAM, 0);
        if(ourfd < 0) {
            snmp_log(LOG_ERR,"couldn't create socket\n");
            return -3;
        }
    }

    if(ifentry->if_paddr_len != 6) {
        SNMP_FREE(ifentry->if_paddr);
    }
    if(NULL == ifentry->if_paddr)
        ifentry->if_paddr = malloc(6);

    if(NULL == ifentry->if_paddr) {
            rc = -4;
    } else {
        ifentry->if_paddr_len = 6;

        strncpy(ifrq.ifr_name, ifentry->if_name, sizeof(ifrq.ifr_name));
        ifrq.ifr_name[ sizeof(ifrq.ifr_name)-1 ] = 0;
        rc = ioctl(fd, SIOCGIFHWADDR, &ifrq);
        if (rc < 0) {
            memset(ifentry->if_paddr, (0), 6);
            snmp_log(LOG_ERR, "bad rc %d from SIOCGIFHWADDR ioctl on %s\n",
                     rc, ifrq.ifr_name);
            rc = -5;
        }
        else {
            memcpy(ifentry->if_paddr, ifrq.ifr_hwaddr.sa_data, 6);

            /*
             * does this just work on linux? I hope not!
             * someone holler at me if so. -rstory
             */
#ifdef ARPHRD_LOOPBACK
            switch (ifrq.ifr_hwaddr.sa_family) {
            case ARPHRD_ETHER:
                ifentry->if_type = 6;
                break;
            case ARPHRD_TUNNEL:
            case ARPHRD_TUNNEL6:
#ifdef ARPHRD_IPGRE
            case ARPHRD_IPGRE:
#endif
            case ARPHRD_SIT:
                ifentry->if_type = 131;
                break;          /* tunnel */
            case ARPHRD_SLIP:
            case ARPHRD_CSLIP:
            case ARPHRD_SLIP6:
            case ARPHRD_CSLIP6:
                ifentry->if_type = 28;
                break;          /* slip */
            case ARPHRD_PPP:
                ifentry->if_type = 23;
                break;          /* ppp */
            case ARPHRD_LOOPBACK:
                ifentry->if_type = 24;
                break;          /* softwareLoopback */
            case ARPHRD_FDDI:
                ifentry->if_type = 15;
                break;
            case ARPHRD_ARCNET:
                ifentry->if_type = 35;
                break;
            case ARPHRD_LOCALTLK:
                ifentry->if_type = 42;
                break;
#ifdef ARPHRD_HIPPI
            case ARPHRD_HIPPI:
                ifentry->if_type = 47;
                break;
#endif
#ifdef ARPHRD_ATM
            case ARPHRD_ATM:
                ifentry->if_type = 37;
                break;
#endif
                /*
                 * XXX: more if_arp.h:ARPHDR_xxx to IANAifType mappings... 
                 */
            }
#endif
        }
    }

    if(ourfd >= 0)
        close(ourfd);

    return rc;
#endif /* SIOCGIFHWADDR */
}

/**
 * interface entry physaddr ioctl wrapper
 *
 * @param      fd : socket fd to use w/ioct, or -1 to open/close one
 * @param ifentry : ifentry to update
 *
 * @retval  0 : success
 * @retval -1 : ioctl not available
 * @retval -2 : invalid parameters
 * @retval -3 : couldn't create socket
 * @retval -5 : ioctl call failed
 */
int
netsnmp_access_interface_ioctl_flags_get(int fd,
                                         netsnmp_interface_entry *ifentry)
{
#ifndef SIOCGIFFLAGS
    return -1;
#else
    struct ifreq    ifrq;
    int ourfd = -1, rc = 0;

    /*
     * sanity checks
     */
    if((NULL == ifentry) || (NULL == ifentry->if_name)) {
        snmp_log(LOG_ERR, "invalid ifentry\n");
        return -2;
    }

    ifentry->if_flags = 0;

    /*
     * create socket for ioctls
     */
    if(fd < 0) {
        fd = ourfd = socket(AF_INET, SOCK_DGRAM, 0);
        if(ourfd < 0) {
            snmp_log(LOG_ERR,"couldn't create socket\n");
            return -3;
        }
    }

    strncpy(ifrq.ifr_name, ifentry->if_name, sizeof(ifrq.ifr_name));
    ifrq.ifr_name[ sizeof(ifrq.ifr_name)-1 ] = 0;
    rc = ioctl(fd, SIOCGIFFLAGS, &ifrq);
    if (rc < 0) {
        snmp_log(LOG_ERR, "bad rc %d from SIOCGIFFLAGS ioctl on %s\n",
                 rc, ifrq.ifr_name);
        ifentry->flags &= ~NETSNMP_INTERFACE_FLAGS_HAS_IF_FLAGS;
        rc = -5;
    }
    else {
        ifentry->flags |= NETSNMP_INTERFACE_FLAGS_HAS_IF_FLAGS;
        ifentry->if_flags = ifrq.ifr_flags;

        if(ifentry->if_flags & IFF_UP)
            ifentry->if_admin_status = IFADMINSTATUS_UP;
        else
            ifentry->if_admin_status = IFADMINSTATUS_DOWN;
    }
    
    if(ourfd >= 0)
        close(ourfd);

    return rc;
#endif /* SIOCGIFFLAGS */
}

#warning "xxx-rks: fix these ioctls"
#ifdef NOT_YET

        strncpy(ifrq.ifr_name, ifname, sizeof(ifrq.ifr_name));
        ifrq.ifr_name[ sizeof(ifrq.ifr_name)-1 ] = 0;
        nnew->if_metric = ioctl(fd, SIOCGIFMETRIC, &ifrq) < 0
            ? 0 : ifrq.ifr_metric;

        strncpy(ifrq.ifr_name, ifname, sizeof(ifrq.ifr_name));
        ifrq.ifr_name[ sizeof(ifrq.ifr_name)-1 ] = 0;
        if (ioctl(fd, SIOCGIFBRDADDR, &ifrq) < 0)
            memset((char *) &ifentry->ifu_broadaddr, 0,
                   sizeof(ifentry->ifu_broadaddr));
        else
            ifentry->ifu_broadaddr = ifrq.ifr_broadaddr;

        strncpy(ifrq.ifr_name, ifname, sizeof(ifrq.ifr_name));
        ifrq.ifr_name[ sizeof(ifrq.ifr_name)-1 ] = 0;
        if (ioctl(fd, SIOCGIFNETMASK, &ifrq) < 0)
            memset((char *) &ifentry->ia_subnetmask, 0,
                   sizeof(ifentry->ia_subnetmask));
        else
            ifentry->ia_subnetmask = ifrq.ifr_netmask;

#ifdef SIOCGIFMTU
        strncpy(ifrq.ifr_name, ifname, sizeof(ifrq.ifr_name));
        ifrq.ifr_name[ sizeof(ifrq.ifr_name)-1 ] = 0;
        ifentry->if_mtu = (ioctl(fd, SIOCGIFMTU, &ifrq) < 0)
            ? 0 : ifrq.ifr_mtu;
#else
        ifentry->if_mtu = 0;
#endif

            /*
             * do only guess if_type from name, if we could not read
             * * it before from SIOCGIFHWADDR 
             */
            if (!ifentry->if_type)
                ifentry->if_type = if_type_from_name(ifentry->if_name);
            ifentry->if_speed = ifentry->if_type == 6 ? getIfSpeed(fd, ifrq) :
                ifentry->if_type == 24 ? 10000000 :
                ifentry->if_type == 9 ? 4000000 : 0;
            /*Zero speed means link problem*/
            if(ifentry->if_speed == 0 && ifentry->if_flags & IFF_UP){
                ifentry->if_flags &= ~IFF_RUNNING;
            }
        }
#endif
