#ifndef SNMPSOCKETBASEDOMAIN_H
#define SNMPSOCKETBASEDOMAIN_H

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <net-snmp/library/snmp_transport.h>

#ifdef __cplusplus
extern          "C" {
#endif

/*
 * Prototypes
 */
    int netsnmp_socketbase_close(netsnmp_transport *t);
    int netsnmp_sock_buffer_set(NETSNMP_SOCKET sock, int optname, int local,
                                int size);
    int netsnmp_set_non_blocking_mode(NETSNMP_SOCKET sock,
                                      int non_blocking_mode);
    int netsnmp_set_tcp_nodelay(NETSNMP_SOCKET sock, int nodelay);

#ifdef __cplusplus
}
#endif

#endif /* SNMPSOCKETBASEDOMAIN_H */
