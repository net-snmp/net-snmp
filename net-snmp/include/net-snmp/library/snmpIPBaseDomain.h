/* IP base transport support functions
 */
#ifndef SNMPIPBASEDOMAIN_H
#define SNMPIPBASEDOMAIN_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/asn1.h>

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/*
 * Convert a "traditional" peername into a sockaddr_in structure which is
 * written to *addr_  Returns 1 if the conversion was successful, or 0 if it
 * failed_  
 */

    int netsnmp_sockaddr_in(struct sockaddr_in *addr, const char *peername,
                            int remote_port);
    int netsnmp_sockaddr_in2(struct sockaddr_in *addr, const char *inpeername,
                             const char *default_target);

#ifdef __cplusplus
}
#endif
#endif /* SNMPIPBASEDOMAIN_H */
