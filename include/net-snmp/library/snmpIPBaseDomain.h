/* IP base transport support functions
 */
#ifndef SNMPIPBASE_H
#define SNMPIPBASE_H

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

int             netsnmp_sockaddr_in(struct sockaddr_in *addr,
                                    const char *peername, int remote_port);


#ifdef __cplusplus
}
#endif
#endif /* SNMPIPBASE_H */
