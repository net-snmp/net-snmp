#ifndef _SNMPTLSTCPDOMAIN_H
#define _SNMPTLSTCPDOMAIN_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/asn1.h>
#include <net-snmp/library/snmpTCPIPv4BaseDomain.h>
#include <net-snmp/library/snmpTCPBaseDomain.h>

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

config_require(TCPIPv4Base)
config_require(TLSBase)

#define TRANSPORT_DOMAIN_TLS_TCP_IP	1,3,6,1,4,1,8072,3,3,10
NETSNMP_IMPORT oid netsnmpTLSTCPDomain[10];
NETSNMP_IMPORT size_t netsnmpTLSTCPDomain_len;

netsnmp_transport *netsnmp_tlstcp_transport(struct sockaddr_in *addr,
                                             int local);

/*
 * Register any configuration tokens specific to the agent.  
 */

void            netsnmp_tlstcp_agent_config_tokens_register(void);

/*
 * "Constructor" for transport domain object.  
 */

void            netsnmp_tlstcp_ctor(void);

#ifdef __cplusplus
}
#endif
#endif/*_SNMPTLSTCPDOMAIN_H*/
