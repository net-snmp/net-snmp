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
#include "if-mib/data_access/interface.h"

#include <net/if.h>
#include <sys/ioctl.h>

/**
 * ioctl wrapper
 *
 * @param      fd : socket fd to use w/ioctl, or -1 to open/close one
 * @param ifentry : ifentry to update
 *
 * @retval  0 : success
 * @retval -1 : invalid parameters
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl call failed
 */
int
_ioctl_get(int fd, int which, struct ifreq *ifrq,
           netsnmp_interface_entry *ifentry)
{
    int ourfd = -1, rc = 0;

    DEBUGMSGTL(("verbose:access:interface:ioctl", "ioctl %d\n", which));

    /*
     * sanity checks
     */
    if((NULL == ifentry) || (NULL == ifentry->if_name)) {
        snmp_log(LOG_ERR, "invalid ifentry\n");
        return -1;
    }

    /*
     * create socket for ioctls
     */
    if(fd < 0) {
        fd = ourfd = socket(AF_INET, SOCK_DGRAM, 0);
        if(ourfd < 0) {
            snmp_log(LOG_ERR,"couldn't create socket\n");
            return -2;
        }
    }

    strncpy(ifrq->ifr_name, ifentry->if_name, sizeof(ifrq->ifr_name));
    ifrq->ifr_name[ sizeof(ifrq->ifr_name)-1 ] = 0;
    rc = ioctl(fd, which, ifrq);
    if (rc < 0) {
        snmp_log(LOG_ERR,"ioctl %d returned %d\n", which, rc);
        rc = -3;
    }

    if(ourfd >= 0)
        close(ourfd);

    return rc;
}

#ifdef SIOCGIFHWADDR
/**
 * interface entry physaddr ioctl wrapper
 *
 * @param      fd : socket fd to use w/ioctl, or -1 to open/close one
 * @param ifentry : ifentry to update
 *
 * @retval  0 : success
 * @retval -1 : invalid parameters
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl call failed
 * @retval -4 : malloc error
 */
int
netsnmp_access_interface_ioctl_physaddr_get(int fd,
                                            netsnmp_interface_entry *ifentry)
{
    struct ifreq    ifrq;
    int rc = 0;

    DEBUGMSGTL(("access:interface:ioctl", "physaddr_get\n"));

    if((NULL != ifentry->if_paddr) &&
       (ifentry->if_paddr_len != IFHWADDRLEN)) {
        SNMP_FREE(ifentry->if_paddr);
    }
    if(NULL == ifentry->if_paddr) 
        ifentry->if_paddr = malloc(IFHWADDRLEN);

    if(NULL == ifentry->if_paddr) {
            rc = -4;
    } else {

        /*
         * NOTE: this ioctl does not guarantee 6 bytes of a physaddr.
         * In particular, a 'sit0' interface only appears to get back
         * 4 bytes of sa_data. Uncomment this memset, and suddenly
         * the sit interface will be 0:0:0:0:?:? where ? is whatever was
         * in the memory before. Not sure if this memset should be done
         * for every ioctl, as the rest seem to work ok...
         */
        memset(ifrq.ifr_hwaddr.sa_data, (0), IFHWADDRLEN);
        ifentry->if_paddr_len = IFHWADDRLEN;
        rc = _ioctl_get(fd, SIOCGIFHWADDR, &ifrq, ifentry);
        if (rc < 0) {
            memset(ifentry->if_paddr, (0), IFHWADDRLEN);
            rc = -3; /* msg already logged */
        }
        else {
            memcpy(ifentry->if_paddr, ifrq.ifr_hwaddr.sa_data, IFHWADDRLEN);

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

    return rc;
}
#endif /* SIOCGIFHWADDR */


#ifdef SIOCGIFFLAGS
/**
 * interface entry flags ioctl wrapper
 *
 * @param      fd : socket fd to use w/ioctl, or -1 to open/close one
 * @param ifentry : ifentry to update
 *
 * @retval  0 : success
 * @retval -1 : invalid parameters
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl call failed
 */
int
netsnmp_access_interface_ioctl_flags_get(int fd,
                                         netsnmp_interface_entry *ifentry)
{
    struct ifreq    ifrq;
    int rc = 0;

    DEBUGMSGTL(("access:interface:ioctl", "flags_get\n"));

    rc = _ioctl_get(fd, SIOCGIFFLAGS, &ifrq, ifentry);
    if (rc < 0) {
        ifentry->flags &= ~NETSNMP_INTERFACE_FLAGS_HAS_IF_FLAGS;
        return rc; /* msg already logged */
    }
    else {
        ifentry->flags |= NETSNMP_INTERFACE_FLAGS_HAS_IF_FLAGS;
        ifentry->if_flags = ifrq.ifr_flags;

        /*
         * ifOperStatus description:
         *   If ifAdminStatus is down(2) then ifOperStatus should be down(2).
         */
        if(ifentry->if_flags & IFF_UP) {
            ifentry->if_admin_status = IFADMINSTATUS_UP;
            if(ifentry->if_flags & IFF_RUNNING)
                ifentry->if_oper_status = IFOPERSTATUS_UP;
            else
                ifentry->if_oper_status = IFOPERSTATUS_DOWN;
        }
        else {
            ifentry->if_admin_status = IFADMINSTATUS_DOWN;
            ifentry->if_oper_status = IFOPERSTATUS_DOWN;
        }
    }
    
    return rc;
}

/**
 * interface entry flags ioctl wrapper
 *
 * @param      fd : socket fd to use w/ioctl, or -1 to open/close one
 * @param ifentry : ifentry to update
 *
 * @retval  0 : success
 * @retval -1 : invalid parameters
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl get call failed
 * @retval -4 : ioctl set call failed
 */
int
netsnmp_access_interface_ioctl_flags_set(int fd,
                                         netsnmp_interface_entry *ifentry,
                                         unsigned int flags, int and_complement)
{
    struct ifreq    ifrq;
    int ourfd = -1, rc = 0;

    DEBUGMSGTL(("access:interface:ioctl", "flags_set\n"));

    /*
     * sanity checks
     */
    if((NULL == ifentry) || (NULL == ifentry->if_name)) {
        snmp_log(LOG_ERR, "invalid ifentry\n");
        return -1;
    }

    /*
     * create socket for ioctls
     */
    if(fd < 0) {
        fd = ourfd = socket(AF_INET, SOCK_DGRAM, 0);
        if(ourfd < 0) {
            snmp_log(LOG_ERR,"couldn't create socket\n");
            return -2;
        }
    }

    strncpy(ifrq.ifr_name, ifentry->if_name, sizeof(ifrq.ifr_name));
    ifrq.ifr_name[ sizeof(ifrq.ifr_name)-1 ] = 0;
    rc = ioctl(fd, SIOCGIFFLAGS, &ifrq);
    if(rc < 0) {
        snmp_log(LOG_ERR,"error getting flags\n");
        close(fd);
        return -3;
    }
    if(0 == and_complement)
        ifrq.ifr_flags |= flags;
    else
        ifrq.ifr_flags &= ~flags;
    rc = ioctl(fd, SIOCSIFFLAGS, &ifrq);
    if(rc < 0) {
        close(fd);
        snmp_log(LOG_ERR,"error setting flags\n");
        ifentry->if_flags = 0;
        return -4;
    }

    if(ourfd >= 0)
        close(ourfd);

    ifentry->if_flags = ifrq.ifr_flags;

    return 0;
}
#endif /* SIOCGIFFLAGS */

#ifdef SIOCGIFMTU
/**
 * interface entry mtu ioctl wrapper
 *
 * @param      fd : socket fd to use w/ioctl, or -1 to open/close one
 * @param ifentry : ifentry to update
 *
 * @retval  0 : success
 * @retval -1 : invalid parameters
 * @retval -2 : couldn't create socket
 * @retval -3 : ioctl call failed
 */
int
netsnmp_access_interface_ioctl_mtu_get(int fd,
                                       netsnmp_interface_entry *ifentry)
{
    struct ifreq    ifrq;
    int rc = 0;

    DEBUGMSGTL(("access:interface:ioctl", "mtu_get\n"));

    rc = _ioctl_get(fd, SIOCGIFMTU, &ifrq, ifentry);
    if (rc < 0) {
        ifentry->if_mtu = 0;
        return rc; /* msg already logged */
    }
    else {
        ifentry->if_mtu = ifrq.ifr_mtu;
    }

    return rc;
}
#endif /* SIOCGIFMTU */
