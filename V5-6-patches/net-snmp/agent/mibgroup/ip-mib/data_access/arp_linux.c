/*
 *  Interface MIB architecture support
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
#include <linux/types.h>
#include <asm/types.h>
#ifdef HAVE_LINUX_RTNETLINK_H
#include <linux/rtnetlink.h>
#endif
#ifdef NETSNMP_ENABLE_IPV6
#define NIP6(addr) \
        ntohs((addr).s6_addr16[0]), \
        ntohs((addr).s6_addr16[1]), \
        ntohs((addr).s6_addr16[2]), \
        ntohs((addr).s6_addr16[3]), \
        ntohs((addr).s6_addr16[4]), \
        ntohs((addr).s6_addr16[5]), \
        ntohs((addr).s6_addr16[6]), \
        ntohs((addr).s6_addr16[7])
#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#endif

int _load_v4(netsnmp_container *container, int idx_offset);
#ifdef NETSNMP_ENABLE_IPV6
static int _load_v6(netsnmp_container *container, int idx_offset);
#endif
#ifdef HAVE_LINUX_RTNETLINK_H
int get_translation_table_info (int sd, int *status, 
                                char *buff, size_t size);
int fillup_entry_info(netsnmp_arp_entry *entry,
                      struct nlmsghdr *nlmp);
#endif
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
    }

#if defined (NETSNMP_ENABLE_IPV6)
    idx_offset = (rc < 0) ? 0 : rc;

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
        snmp_log(LOG_DEBUG,"could not open " PROCFILE "\n");
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
        unsigned int    tmp_flags;
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
         * if flags are 0, we can't tell the difference between
         * stale or incomplete.
         */
        if(tmp_flags & ATF_COM)
            entry->arp_state = INETNETTOMEDIASTATE_REACHABLE;
        else
            entry->arp_state = INETNETTOMEDIASTATE_UNKNOWN;

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

#if defined (NETSNMP_ENABLE_IPV6)
static int
_load_v6(netsnmp_container *container, int idx_offset)
{
    char              buffer[16384];
#if defined(HAVE_LINUX_RTNETLINK_H)
    struct nlmsghdr   *nlmp;
#endif
    int               sd = 0;
    int               status = 0;
    int               rc = 0;
    int               len, req_len;
    netsnmp_arp_entry *entry;

    netsnmp_assert(NULL != container);
#if defined(HAVE_LINUX_RTNETLINK_H)
    if((sd = socket (PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        snmp_log(LOG_ERR,"Unable to create netlink socket\n");
        return -2;
    }

    if(get_translation_table_info (sd, &status, buffer, sizeof(buffer)) < 0) {
       snmp_log(LOG_ERR,"Unable to fetch translation table info\n");
       close(sd);
       return -2;
    }

    for (nlmp = (struct nlmsghdr *)buffer; status > sizeof(*nlmp); ) {
         len = nlmp->nlmsg_len;
         req_len = len - sizeof(*nlmp);
         if (req_len < 0 || len > status) {
             snmp_log(LOG_ERR,"invalid length\n");
             return -2;
         }
         if (!NLMSG_OK (nlmp, status)) {
             snmp_log(LOG_ERR,"NLMSG not OK\n");
             return -2;
         }
         entry = netsnmp_access_arp_entry_create();
         if(NULL == entry) {
            rc = -3;
            break;
         }
         entry->ns_arp_index = ++idx_offset;
         if(fillup_entry_info (entry, nlmp) < 0) {
            DEBUGMSGTL(("access:arp:load_v6", "skipping netlink message that"
                        " did not contain valid ARP information\n"));
            netsnmp_access_arp_entry_free(entry);
            status -= NLMSG_ALIGN(len);
            nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));
            continue;
         }
         CONTAINER_INSERT(container, entry);
         status -= NLMSG_ALIGN(len);
         nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));
    }

    close(sd);
#endif
    if(rc<0) {
        return rc;
    }

    return idx_offset;
}
#if defined(HAVE_LINUX_RTNETLINK_H)
int 
get_translation_table_info (int sd, int *status, char *buff, size_t size)
{
    struct {
                struct nlmsghdr n;
                struct ndmsg r;
                char   buf[1024];
    } req;
    struct rtattr   *rta;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH (sizeof(struct ndmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    req.n.nlmsg_type = RTM_GETNEIGH;

    req.r.ndm_family = AF_INET6;
    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_len = RTA_LENGTH(16);

    if(send(sd, &req, req.n.nlmsg_len, 0) < 0) {
       snmp_log(LOG_ERR,"Sending request failed\n");
       return -1;
    }
    if((*status = recv(sd, buff, size, 0)) < 0) {
       snmp_log(LOG_ERR,"Recieving request failed\n");
       return -1;
    }
    if(*status == 0) {
       snmp_log(LOG_ERR,"End of file\n");
       return -1;
    }
    return 0;
}

int
fillup_entry_info(netsnmp_arp_entry *entry, struct nlmsghdr *nlmp)
{
    struct ndmsg   *rtmp;
    struct in6_addr *in6p;
    struct rtattr  *tb[NDA_MAX + 1], *rta;
    size_t          in_len, out_len;
    unsigned int    i;
    int             length;
    char            addr[40];
    u_char         *buf;
    u_char         *hwaddr;

    rtmp = (struct ndmsg *) NLMSG_DATA(nlmp);
    if (nlmp->nlmsg_type != RTM_NEWNEIGH) {
        snmp_log(LOG_ERR, "Wrong netlink message type %d\n", nlmp->nlmsg_type);
        return -1;
    }

    if (rtmp->ndm_state != NUD_NOARP) {
        memset(tb, 0, sizeof(struct rtattr *) * (NDA_MAX + 1));
        length = nlmp->nlmsg_len - NLMSG_LENGTH(sizeof(*rtmp));
        if (length < 0) {
            snmp_log(LOG_ERR, "netlink message length %d < %d is invalid\n",
                     nlmp->nlmsg_len, NLMSG_LENGTH(sizeof(*rtmp)));
            return -1;
        }
        /*
         * this is what the kernel-removed NDA_RTA define did 
         */
        rta = ((struct rtattr *) (((char *) (rtmp)) +
                                  NLMSG_ALIGN(sizeof(struct ndmsg))));
        while (RTA_OK(rta, length)) {
            if (rta->rta_type <= NDA_MAX)
                tb[rta->rta_type] = rta;
            rta = RTA_NEXT(rta, length);
        }
        if (length) {
            snmp_log(LOG_ERR, "Received uneven number of netlink"
                        " messages - %d bytes remaining\n", length);
            return -1;
        }
        /*
         * Fill up the index
         */
        entry->if_index = rtmp->ndm_ifindex;
        /*
         * Fill up ip address 
         */
        if (tb[NDA_DST]) {
            memset(&addr, '\0', sizeof(addr));
            in6p = (struct in6_addr *) RTA_DATA(tb[NDA_DST]);
            sprintf(addr, NIP6_FMT, NIP6(*in6p));
            in_len = entry->arp_ipaddress_len =
                sizeof(entry->arp_ipaddress);
            netsnmp_assert(16 == in_len);
            out_len = 0;
            buf = entry->arp_ipaddress;
            if (1 != netsnmp_hex_to_binary(&buf, &in_len,
                                           &out_len, 0, addr, ":")) {
                snmp_log(LOG_ERR, "error parsing '%s', skipping\n",
                         entry->arp_ipaddress);
                return -1;
            }
            netsnmp_assert(16 == out_len);
            entry->arp_ipaddress_len = out_len;
        }
        if (tb[NDA_LLADDR]) {
            memset(&addr, '\0', sizeof(addr));
            hwaddr = RTA_DATA(tb[NDA_LLADDR]);
            entry->arp_physaddress_len = RTA_PAYLOAD(tb[NDA_LLADDR]);
            buf = entry->arp_physaddress;
            for (i = 0; i < entry->arp_physaddress_len; i++)
                entry->arp_physaddress[i] = hwaddr[i];
        }

        switch (rtmp->ndm_state) {
        case NUD_INCOMPLETE:
            entry->arp_state = INETNETTOMEDIASTATE_INCOMPLETE;
            break;
        case NUD_REACHABLE:
        case NUD_PERMANENT:
            entry->arp_state = INETNETTOMEDIASTATE_REACHABLE;
            break;
        case NUD_STALE:
            entry->arp_state = INETNETTOMEDIASTATE_STALE;
            break;
        case NUD_DELAY:
            entry->arp_state = INETNETTOMEDIASTATE_DELAY;
            break;
        case NUD_PROBE:
            entry->arp_state = INETNETTOMEDIASTATE_PROBE;
            break;
        case NUD_FAILED:
            entry->arp_state = INETNETTOMEDIASTATE_INVALID;
            break;
        case NUD_NONE:
            entry->arp_state = INETNETTOMEDIASTATE_UNKNOWN;
            break;
        default:
            snmp_log(LOG_ERR, "Unrecognized ARP entry state %d", rtmp->ndm_state);
            break;
        }

        switch (rtmp->ndm_state) {
        case NUD_INCOMPLETE:
        case NUD_FAILED:
        case NUD_NONE:
            entry->arp_type = INETNETTOMEDIATYPE_INVALID;
            break;
        case NUD_REACHABLE:
        case NUD_STALE:
        case NUD_DELAY:
        case NUD_PROBE:
            entry->arp_type = INETNETTOMEDIATYPE_DYNAMIC;
            break;
        case NUD_PERMANENT:
            entry->arp_type = INETNETTOMEDIATYPE_STATIC;
            break;
        default:
            entry->arp_type = INETNETTOMEDIATYPE_LOCAL;
            break;
        }
    } else {
        return -1;              /* could not create data for this interface */
    }

    return 0;
}
#endif
#endif
