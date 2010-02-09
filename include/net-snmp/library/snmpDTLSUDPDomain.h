#ifndef _SNMPDTLSUDPDOMAIN_H
#define _SNMPDTLSUDPDOMAIN_H

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

#define TRANSPORT_DOMAIN_DTLS_UDP_IP	1,3,6,1,4,1,8072,3,3,8
NETSNMP_IMPORT oid netsnmpDTLSUDPDomain[10];
NETSNMP_IMPORT size_t netsnmpDTLSUDPDomain_len;

netsnmp_transport *netsnmp_dtlsudp_transport(struct sockaddr_in *addr,
                                             int local);


/*
 * Register any configuration tokens specific to the agent.  
 */

void            netsnmp_dtlsudp_agent_config_tokens_register(void);

/*
 * "Constructor" for transport domain object.  
 */

void            netsnmp_dtlsudp_ctor(void);

#ifdef __cplusplus
}
#endif
#endif/*_SNMPDTLSUDPDOMAIN_H*/
