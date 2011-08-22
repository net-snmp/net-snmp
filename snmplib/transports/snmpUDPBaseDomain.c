/* UDP base transport support functions
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/types.h>
#include <net-snmp/library/snmpUDPBaseDomain.h>

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
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <errno.h>

#include <net-snmp/types.h>
#include <net-snmp/library/snmpSocketBaseDomain.h>
#include <net-snmp/library/snmpUDPDomain.h>
#include <net-snmp/library/snmp_debug.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/default_store.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/snmp_assert.h>

void
_netsnmp_udp_sockopt_set(int fd, int local)
{
#ifdef  SO_BSDCOMPAT
    /*
     * Patch for Linux.  Without this, UDP packets that fail get an ICMP
     * response.  Linux turns the failed ICMP response into an error message
     * and return value, unlike all other OS's.  
     */
    if (0 == netsnmp_os_prematch("Linux","2.4"))
    {
        int             one = 1;
        DEBUGMSGTL(("socket:option", "setting socket option SO_BSDCOMPAT\n"));
        setsockopt(fd, SOL_SOCKET, SO_BSDCOMPAT, (void *) &one,
                   sizeof(one));
    }
#endif                          /*SO_BSDCOMPAT */
    /*
     * SO_REUSEADDR will allow multiple apps to open the same port at
     * the same time. Only the last one to open the socket will get
     * data. Obviously, for an agent, this is a bad thing. There should
     * only be one listener.
     */
#ifdef ALLOW_PORT_HIJACKING
#ifdef  SO_REUSEADDR
    /*
     * Allow the same port to be specified multiple times without failing.
     *    (useful for a listener)
     */
    {
        int             one = 1;
        DEBUGMSGTL(("socket:option", "setting socket option SO_REUSEADDR\n"));
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &one,
                   sizeof(one));
    }
#endif                          /*SO_REUSEADDR */
#endif

    /*
     * Try to set the send and receive buffers to a reasonably large value, so
     * that we can send and receive big PDUs (defaults to 8192 bytes (!) on
     * Solaris, for instance).  Don't worry too much about errors -- just
     * plough on regardless.  
     */
    netsnmp_sock_buffer_set(fd, SO_SNDBUF, local, 0);
    netsnmp_sock_buffer_set(fd, SO_RCVBUF, local, 0);
}

/*
 * You can write something into opaque that will subsequently get passed back 
 * to your send function if you like.  For instance, you might want to
 * remember where a PDU came from, so that you can send a reply there...  
 */

int
netsnmp_udpbase_recv(netsnmp_transport *t, void *buf, int size,
                     void **opaque, int *olength)
{
    int             rc = -1;
    socklen_t       fromlen = sizeof(struct sockaddr);
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    struct sockaddr *from;

    if (t != NULL && t->sock >= 0) {
        addr_pair = (netsnmp_indexed_addr_pair *) malloc(sizeof(netsnmp_indexed_addr_pair));
        if (addr_pair == NULL) {
            *opaque = NULL;
            *olength = 0;
            return -1;
        } else {
            memset(addr_pair, 0, sizeof(netsnmp_indexed_addr_pair));
            from = &addr_pair->remote_addr.sa;
        }

	while (rc < 0) {
#if defined(linux) && defined(IP_PKTINFO)
            socklen_t local_addr_len = sizeof(addr_pair->local_addr);
            rc = netsnmp_udp_recvfrom(t->sock, buf, size, from, &fromlen,
                                      (struct sockaddr*)&(addr_pair->local_addr),
                                      &local_addr_len, &(addr_pair->if_index));
#else
            rc = recvfrom(t->sock, buf, size, NETSNMP_DONTWAIT, from, &fromlen);
#endif /* linux && IP_PKTINFO */
	    if (rc < 0 && errno != EINTR) {
		break;
	    }
	}

        if (rc >= 0) {
            char *str = netsnmp_udp_fmtaddr(NULL, addr_pair, sizeof(netsnmp_indexed_addr_pair));
            DEBUGMSGTL(("netsnmp_udp",
			"recvfrom fd %d got %d bytes (from %s)\n",
			t->sock, rc, str));
            free(str);
        } else {
            DEBUGMSGTL(("netsnmp_udp", "recvfrom fd %d err %d (\"%s\")\n",
                        t->sock, errno, strerror(errno)));
        }
        *opaque = (void *)addr_pair;
        *olength = sizeof(netsnmp_indexed_addr_pair);
    }
    return rc;
}



int
netsnmp_udpbase_send(netsnmp_transport *t, void *buf, int size,
                     void **opaque, int *olength)
{
    int rc = -1;
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    struct sockaddr *to = NULL;

    if (opaque != NULL && *opaque != NULL &&
        ((*olength == sizeof(netsnmp_indexed_addr_pair) ||
          (*olength == sizeof(struct sockaddr_in))))) {
        addr_pair = (netsnmp_indexed_addr_pair *) (*opaque);
    } else if (t != NULL && t->data != NULL &&
                t->data_length == sizeof(netsnmp_indexed_addr_pair)) {
        addr_pair = (netsnmp_indexed_addr_pair *) (t->data);
    }

    to = &addr_pair->remote_addr.sa;

    if (to != NULL && t != NULL && t->sock >= 0) {
        char *str = netsnmp_udp_fmtaddr(NULL, (void *) addr_pair,
                                        sizeof(netsnmp_indexed_addr_pair));
        DEBUGMSGTL(("netsnmp_udp", "send %d bytes from %p to %s on fd %d\n",
                    size, buf, str, t->sock));
        free(str);
	while (rc < 0) {
#if defined(linux) && defined(IP_PKTINFO)
            rc = netsnmp_udp_sendto(t->sock,
                    addr_pair ? &(addr_pair->local_addr.sin.sin_addr) : NULL,
                    addr_pair ? addr_pair->if_index : 0, to, buf, size);
#else
            rc = sendto(t->sock, buf, size, 0, to, sizeof(struct sockaddr));
#endif /* linux && IP_PKTINFO */
	    if (rc < 0 && errno != EINTR) {
                DEBUGMSGTL(("netsnmp_udp", "sendto error, rc %d (errno %d)\n",
                            rc, errno));
		break;
	    }
	}
    }
    return rc;
}

#if (defined(linux) && defined(IP_PKTINFO)) \
    || defined(IP_RECVDSTADDR) && HAVE_STRUCT_MSGHDR_MSG_CONTROL \
                               && HAVE_STRUCT_MSGHDR_MSG_FLAGS
#if  defined(linux) && defined(IP_PKTINFO)
# define netsnmp_dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr))
#elif defined(IP_RECVDSTADDR)
# define netsnmp_dstaddr(x) (&(struct cmsghr *)(CMSG_DATA(x)))
# ifndef IP_SENDSRCADDR
#  define IP_SENDSRCADDR IP_RECVDSTADDR /* DragonFly BSD */
# endif
#endif

int
netsnmp_udpbase_recvfrom(int s, void *buf, int len, struct sockaddr *from,
                         socklen_t *fromlen, struct sockaddr *dstip,
                         socklen_t *dstlen, int *if_index)
{
    int r, r2;
    struct iovec iov[1];
#if  defined(linux) && defined(IP_PKTINFO)
    char cmsg[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(IP_RECVDSTADDR)
    char cmsg[CMSG_SPACE(sizeof(struct in_addr))];
#endif
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

    r2 = getsockname(s, dstip, dstlen);
    netsnmp_assert(r2 == 0);

    DEBUGMSGTL(("udpbase:recv", "got source addr: %s\n",
                inet_ntoa(((struct sockaddr_in *)from)->sin_addr)));
#if  defined(linux) && defined(IP_PKTINFO)
    for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
        if (cmsgptr->cmsg_level != SOL_IP || cmsgptr->cmsg_type != IP_PKTINFO)
            continue;

        netsnmp_assert(dstip->sa_family == AF_INET);
        ((struct sockaddr_in*)dstip)->sin_addr = *netsnmp_dstaddr(cmsgptr);
        *if_index = (((struct in_pktinfo *)(CMSG_DATA(cmsgptr)))->ipi_ifindex);
        DEBUGMSGTL(("udpbase:recv",
                    "got destination (local) addr %s, iface %d\n",
                    inet_ntoa(((struct sockaddr_in*)dstip)->sin_addr),
                    *if_index));
    }
#elif defined(IP_RECVDSTADDR)
    for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
        if (cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == IP_RECVDSTADDR) {
            memcpy((void *) dstip, CMSG_DATA(cmsgptr), sizeof(struct in_addr));
            DEBUGMSGTL(("netsnmp_udp", "got destination (local) addr %s\n",
                    inet_ntoa(((struct sockaddr_in*)dstip)->sin_addr)));
        }
    }
#endif
    return r;
}

#if  defined(linux) && defined(IP_PKTINFO)
int netsnmp_udpbase_sendto(int fd, struct in_addr *srcip, int if_index,
                           struct sockaddr *remote, void *data, int len)
{
    struct iovec iov;
    struct {
        struct cmsghdr cm;
        struct in_pktinfo ipi;
    } cmsg;
    struct msghdr m;
    int ret;

    iov.iov_base = data;
    iov.iov_len  = len;
    memset(&cmsg, 0, sizeof(cmsg));
    cmsg.cm.cmsg_len = sizeof(struct cmsghdr) + sizeof(struct in_pktinfo);
    cmsg.cm.cmsg_level = SOL_IP;
    cmsg.cm.cmsg_type = IP_PKTINFO;
    cmsg.ipi.ipi_ifindex = 0;
    cmsg.ipi.ipi_spec_dst.s_addr = (srcip ? srcip->s_addr : INADDR_ANY);

    m.msg_name		= remote;
    m.msg_namelen	= sizeof(struct sockaddr_in);
    m.msg_iov		= &iov;
    m.msg_iovlen	= 1;
    m.msg_control	= &cmsg;
    m.msg_controllen	= sizeof(cmsg);
    m.msg_flags		= 0;

    DEBUGMSGTL(("udpbase:sendto", "sending from %s iface %d\n",
                (srcip ? inet_ntoa(*srcip) : "NULL"), if_index));
    errno = 0;
    ret = sendmsg(fd, &m, NETSNMP_NOSIGNAL|NETSNMP_DONTWAIT);
    if (ret < 0 && errno == EINVAL && srcip) {
        /* The error might be caused by broadcast srcip (i.e. we're responding
         * to broadcast request) - sendmsg does not like it. Try to resend it
         * with global address and using the interface on whicg it was
         * received */
        cmsg.ipi.ipi_ifindex = if_index;
        cmsg.ipi.ipi_spec_dst.s_addr = INADDR_ANY;
        DEBUGMSGTL(("udpbase:sendto", "re-sending the message\n"));
        ret = sendmsg(fd, &m, NETSNMP_NOSIGNAL|NETSNMP_DONTWAIT);
    }
    return ret;
}
#elif defined(IP_SENDSRCADDR)
int netsnmp_udpbase_sendto(int fd, struct in_addr *srcip, int if_index,
			struct sockaddr *remote, void *data, int len)
{
    struct iovec iov = { data, len };
    struct cmsghdr *cm;
    struct msghdr m;
    char   cmbuf[CMSG_SPACE(sizeof(struct in_addr))];

    memset(&m, 0, sizeof(struct msghdr));
    m.msg_name         = remote;
    m.msg_namelen      = sizeof(struct sockaddr_in);
    m.msg_iov          = &iov;
    m.msg_iovlen       = 1;
    m.msg_control      = cmbuf;
    m.msg_controllen   = sizeof(cmbuf);
    m.msg_flags                = 0;

    cm = CMSG_FIRSTHDR(&m);
    cm->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
    cm->cmsg_level = IPPROTO_IP;
    cm->cmsg_type = IP_SENDSRCADDR;

    memcpy((struct in_addr *)CMSG_DATA(cm), srcip, sizeof(struct in_addr));

    return sendmsg(fd, &m, NETSNMP_NOSIGNAL|NETSNMP_DONTWAIT);
}
#endif
#endif /* (linux && IP_PKTINFO) || IP_RECVDSTADDR */

