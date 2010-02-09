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

#include <net-snmp/types.h>
#include <net-snmp/library/snmpIPv4BaseDomain.h>

char *
netsnmp_ipv4_fmtaddr(const char *prefix, netsnmp_transport *t,
                     void *data, int len)
{
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    struct hostent *host;
    char tmp[64];

    if (data != NULL && len == sizeof(netsnmp_indexed_addr_pair)) {
	addr_pair = (netsnmp_indexed_addr_pair *) data;
    } else if (t != NULL && t->data != NULL) {
	addr_pair = (netsnmp_indexed_addr_pair *) t->data;
    }

    if (addr_pair == NULL) {
        snprintf(tmp, sizeof(tmp), "%s: unknown", prefix);
    } else {
        struct sockaddr_in *to = NULL;
        to = (struct sockaddr_in *) &(addr_pair->remote_addr);
        if (to == NULL) {
            snprintf(tmp, sizeof(tmp), "%s: unknown->[%s]", prefix,
                    inet_ntoa(addr_pair->local_addr));
        } else if ( t && t->flags & NETSNMP_TRANSPORT_FLAG_HOSTNAME ) {
            /* XXX: hmm...  why isn't this prefixed */
            /* assuming intentional */
            host = gethostbyaddr((char *)&to->sin_addr, 4, AF_INET);
            return (host ? strdup(host->h_name) : NULL); 
        } else {
            snprintf(tmp, sizeof(tmp), "%s: [%s]:%hu->", prefix,
                     inet_ntoa(to->sin_addr), ntohs(to->sin_port));
            snprintf(tmp + strlen(tmp), sizeof(tmp)-strlen(tmp), "[%s]",
                     inet_ntoa(addr_pair->local_addr));
        }
    }
    tmp[sizeof(tmp)-1] = '\0';
    return strdup(tmp);
}

