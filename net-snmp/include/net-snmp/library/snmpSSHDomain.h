#ifndef _SNMPSSHDOMAIN_H
#define _SNMPSSHDOMAIN_H

#ifdef NETSNMP_TRANSPORT_SSH_DOMAIN

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
 * The SNMP over SSH over IPv4 transport domain is identified by
 * transportDomainSshIpv4 as defined in RFC 3419.
 */

#define TRANSPORT_DOMAIN_SSH_IP		1,3,6,1,2,1,100,1,100
NETSNMP_IMPORT oid netsnmp_snmpSSHDomain[];

netsnmp_transport *netsnmp_ssh_transport(struct sockaddr_in *addr, int local);

/*
 * "Constructor" for transport domain object.  
 */

void            netsnmp_ssh_ctor(void);

#ifdef __cplusplus
}
#endif
#endif                          /*NETSNMP_TRANSPORT_SSH_DOMAIN */

#endif/*_SNMPSSHDOMAIN_H*/
