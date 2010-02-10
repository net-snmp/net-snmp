/* UDPIPV4 base transport support functions
 */
#ifndef SNMPUDPIPV4BASE_H
#define SNMPUDPIPV4BASE_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/asn1.h>
#include <net-snmp/library/snmpIPBaseDomain.h>
#include <net-snmp/library/snmpUDPBaseDomain.h>

config_require(UDPBase);
config_require(IPv4Base);

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/*
 * Definitions
 */
#ifdef  MSG_DONTWAIT
#define NETSNMP_DONTWAIT MSG_DONTWAIT
#else
#define NETSNMP_DONTWAIT 0
#endif

/*
 * Prototypes
 */

#if defined(linux) && defined(IP_PKTINFO)
    int netsnmp_udpipv4_recvfrom(int s, void *buf, int len,
                                 struct sockaddr *from, socklen_t *fromlen,
                                 struct in_addr *dstip,
                                 int *if_index);
    int netsnmp_udpipv4_sendto(int fd, struct in_addr *srcip, int if_index,
                               struct sockaddr *remote, void *data, int len);
    netsnmp_transport *netsnmp_udpipv4base_transport(struct sockaddr_in *addr,
                                                     int local);

#endif


#ifdef __cplusplus
}
#endif
#endif /* SNMPUDPIPV4BASE_H */
