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

#include <net-snmp/types.h>
#include <net-snmp/library/snmpIPv6BaseDomain.h>
#include <net-snmp/library/snmp_debug.h>

char *
netsnmp_ipv6_fmtaddr(const char *prefix, netsnmp_transport *t,
                     void *data, int len)
{
    struct sockaddr_in6 *to = NULL;
    char addr[INET6_ADDRSTRLEN];
    char tmp[INET6_ADDRSTRLEN + 18];

    DEBUGMSGTL(("netsnmp_udp6", "fmtaddr: t = %p, data = %p, len = %d\n", t,
                data, len));
    if (data != NULL && len == sizeof(struct sockaddr_in6)) {
        to = (struct sockaddr_in6 *) data;
    } else if (t != NULL && t->data != NULL) {
        to = (struct sockaddr_in6 *) t->data;
    }
    if (to == NULL) {
        snprintf(tmp, sizeof(tmp), "%s: unknown", prefix);
    } else {
        snprintf(tmp, sizeof(tmp), "%s: [%s]:%hu", prefix,
                 inet_ntop(AF_INET6, (void *) &(to->sin6_addr), addr,
                           INET6_ADDRSTRLEN), ntohs(to->sin6_port));
    }
    tmp[sizeof(tmp)-1] = '\0';
    return strdup(tmp);
}
