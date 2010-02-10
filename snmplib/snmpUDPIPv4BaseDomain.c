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
#include <net-snmp/library/tools.h>
#include <net-snmp/library/snmp_assert.h>
#include <net-snmp/library/default_store.h>

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

netsnmp_transport *
netsnmp_udpipv4base_transport(struct sockaddr_in *addr, int local)
{
    netsnmp_transport *t = NULL;
    int             rc = 0;
    char           *str = NULL;
    char           *client_socket = NULL;
    netsnmp_indexed_addr_pair addr_pair;

    if (addr == NULL || addr->sin_family != AF_INET) {
        return NULL;
    }

    memset(&addr_pair, 0, sizeof(netsnmp_indexed_addr_pair));
    memcpy(&(addr_pair.remote_addr), addr, sizeof(struct sockaddr_in));

    t = SNMP_MALLOC_TYPEDEF(netsnmp_transport);
    netsnmp_assert_or_return(t != NULL, NULL);

    str = netsnmp_udp_fmtaddr(NULL, (void *)&addr_pair,
                                 sizeof(netsnmp_indexed_addr_pair));
    DEBUGMSGTL(("netsnmp_udpbase", "open %s %s\n", local ? "local" : "remote",
                str));
    free(str);

    t->sock = socket(PF_INET, SOCK_DGRAM, 0);
    DEBUGMSGTL(("UDPBase", "openned socket %d as local=%d\n", t->sock, local)); 
    if (t->sock < 0) {
        netsnmp_transport_free(t);
        return NULL;
    }

    _netsnmp_udp_sockopt_set(t->sock, local);

    if (local) {
        /*
         * This session is inteneded as a server, so we must bind on to the
         * given IP address, which may include an interface address, or could
         * be INADDR_ANY, but certainly includes a port number.
         */

      t->local = (u_char *) malloc(6);
        if (t->local == NULL) {
            netsnmp_transport_free(t);
            return NULL;
        }
        memcpy(t->local, (u_char *) & (addr->sin_addr.s_addr), 4);
        t->local[4] = (htons(addr->sin_port) & 0xff00) >> 8;
        t->local[5] = (htons(addr->sin_port) & 0x00ff) >> 0;
        t->local_length = 6;

#if defined(linux) && defined(IP_PKTINFO)
        { 
            int sockopt = 1;
            if (setsockopt(t->sock, SOL_IP, IP_PKTINFO, &sockopt, sizeof sockopt) == -1) {
                DEBUGMSGTL(("netsnmp_udpbase", "couldn't set IP_PKTINFO: %s\n",
                    strerror(errno)));
                netsnmp_transport_free(t);
                return NULL;
            }
            DEBUGMSGTL(("netsnmp_udpbase", "set IP_PKTINFO\n"));
        }
#endif
        rc = bind(t->sock, (struct sockaddr *) addr,
                  sizeof(struct sockaddr));
        if (rc != 0) {
            netsnmp_socketbase_close(t);
            netsnmp_transport_free(t);
            return NULL;
        }
        t->data = NULL;
        t->data_length = 0;
    } else {
        /*
         * This is a client session.  If we've been given a
         * client address to send from, then bind to that.
         * Otherwise the send will use "something sensible".
         */
        client_socket = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                              NETSNMP_DS_LIB_CLIENT_ADDR);
        if (client_socket) {
            struct sockaddr_in client_addr;
            netsnmp_sockaddr_in2(&client_addr, client_socket, NULL);
            addr_pair.local_addr = client_addr.sin_addr;
            client_addr.sin_port = 0;
            DEBUGMSGTL(("netsnmp_udpbase", "binding socket: %d\n", t->sock));
            rc = bind(t->sock, (struct sockaddr *)&client_addr,
                  sizeof(struct sockaddr));
            if ( rc != 0 ) {
                DEBUGMSGTL(("netsnmp_udpbase", "failed to bind for clientaddr: %d %s\n",
                            errno, strerror(errno)));
                netsnmp_socketbase_close(t);
                netsnmp_transport_free(t);
                return NULL;
            }
        }

        str = netsnmp_udp_fmtaddr(NULL, (void *)&addr_pair,
                 sizeof(netsnmp_indexed_addr_pair));
        DEBUGMSGTL(("netsnmp_udpbase", "client open %s\n", str));
        free(str);

        /*
         * Save the (remote) address in the
         * transport-specific data pointer for later use by netsnmp_udp_send.
         */

        t->data = malloc(sizeof(netsnmp_indexed_addr_pair));
        t->remote = (u_char *)malloc(6);
        if (t->data == NULL || t->remote == NULL) {
            netsnmp_transport_free(t);
            return NULL;
        }
        memcpy(t->remote, (u_char *) & (addr->sin_addr.s_addr), 4);
        t->remote[4] = (htons(addr->sin_port) & 0xff00) >> 8;
        t->remote[5] = (htons(addr->sin_port) & 0x00ff) >> 0;
        t->remote_length = 6;
        memcpy(t->data, &addr_pair, sizeof(netsnmp_indexed_addr_pair));
        t->data_length = sizeof(netsnmp_indexed_addr_pair);
    }

    return t;
}
