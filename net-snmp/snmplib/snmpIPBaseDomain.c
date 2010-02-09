/* IP base transport support functions
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
#include <net-snmp/library/snmpIPBaseDomain.h>

int
netsnmp_sockaddr_in(struct sockaddr_in *addr,
                    const char *inpeername, int remote_port)
{
    char buf[sizeof(int) * 3 + 2];
    sprintf(buf, ":%u", remote_port);
    return netsnmp_sockaddr_in2(addr, inpeername, remote_port ? buf : NULL);
}

