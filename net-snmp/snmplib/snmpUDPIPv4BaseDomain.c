/* IPV4 base transport support functions
 */

#include <net-snmp/net-snmp-config.h>

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#include <errno.h>

#include <net-snmp/types.h>
#include <net-snmp/library/snmpUDPIPv4BaseDomain.h>
#include <net-snmp/library/snmp_debug.h>

#if defined(linux) && defined(IP_PKTINFO)

# define netsnmp_dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr))

int netsnmp_ipv4_recvfrom(int s, void *buf, int len, struct sockaddr *from, socklen_t *fromlen, struct in_addr *dstip, int *if_index)
{
    int r;
    struct iovec iov[1];
    char cmsg[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct cmsghdr *cmsgptr;
    struct msghdr msg;

    iov[0].iov_base = buf;
    iov[0].iov_len = len;

    memset(&msg, 0, sizeof msg);
    msg.msg_name = from;
    msg.msg_namelen = *fromlen;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg;
    msg.msg_controllen = sizeof(cmsg);

    r = recvmsg(s, &msg, NETSNMP_DONTWAIT);

    if (r == -1) {
        return -1;
    }

    DEBUGMSGTL(("netsnmp_ipv4", "got source addr: %s\n", inet_ntoa(((struct sockaddr_in *)from)->sin_addr)));
    for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
        if (cmsgptr->cmsg_level == SOL_IP && cmsgptr->cmsg_type == IP_PKTINFO) {
            memcpy((void *) dstip, netsnmp_dstaddr(cmsgptr), sizeof(struct in_addr));
            *if_index = (((struct in_pktinfo *)(CMSG_DATA(cmsgptr)))->ipi_ifindex);
            DEBUGMSGTL(("netsnmp_ipv4", "got destination (local) addr %s, iface %d\n",
                    inet_ntoa(*dstip), *if_index));
        }
    }
    return r;
}

int netsnmp_ipv4_sendto(int fd, struct in_addr *srcip, int if_index, struct sockaddr *remote,
                void *data, int len)
{
    struct iovec iov = { data, len };
    struct {
        struct cmsghdr cm;
        struct in_pktinfo ipi;
    } cmsg;
    struct msghdr m;
    int ret;

    memset(&cmsg, 0, sizeof(cmsg));
    cmsg.cm.cmsg_len = sizeof(struct cmsghdr) + sizeof(struct in_pktinfo);
    cmsg.cm.cmsg_level = SOL_IP;
    cmsg.cm.cmsg_type = IP_PKTINFO;
    cmsg.ipi.ipi_ifindex = if_index;
    cmsg.ipi.ipi_spec_dst.s_addr = (srcip ? srcip->s_addr : INADDR_ANY);

    m.msg_name		= remote;
    m.msg_namelen	= sizeof(struct sockaddr_in);
    m.msg_iov		= &iov;
    m.msg_iovlen	= 1;
    m.msg_control	= &cmsg;
    m.msg_controllen	= sizeof(cmsg);
    m.msg_flags		= 0;

    DEBUGMSGTL(("netsnmp_ipv4",
                "netsnmp_ipv4_sendto: sending from %s iface %d\n",
                (srcip ? inet_ntoa(*srcip) : "NULL"), if_index));
    errno = 0;
    ret = sendmsg(fd, &m, MSG_NOSIGNAL|MSG_DONTWAIT);
    if (ret < 0 && errno == EINVAL && srcip) {
        /* The error might be caused by broadcast srcip (i.e. we're responding
         * to broadcast request) - sendmsg does not like it. Try to resend it
         * with global address. */
        cmsg.ipi.ipi_spec_dst.s_addr = INADDR_ANY;
        DEBUGMSGTL(("netsnmp_ipv4",
                "netsnmp_ipv4_sendto: re-sending the message\n"));
        ret = sendmsg(fd, &m, MSG_NOSIGNAL|MSG_DONTWAIT);
    }
    return ret;
}
#endif /* linux && IP_PKTINFO */
