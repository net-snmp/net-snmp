/* IPV6 base transport support functions
 */
#ifndef SNMPIPV6BASE_H
#define SNMPIPV6BASE_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/asn1.h>
#include <net-snmp/library/snmpIPBaseDomain.h>

config_require(IPBase);

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef __cplusplus
}
#endif
#endif /* SNMPIPV6BASE_H */
