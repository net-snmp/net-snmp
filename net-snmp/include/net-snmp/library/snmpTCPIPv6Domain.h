#ifndef _SNMPTCPIPV6DOMAIN_H
#define _SNMPTCPIPV6DOMAIN_H

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/asn1.h>

const oid netsnmp_ucdSnmpTCPIPv6Domain[9];  /* = { UCDAVIS_MIB, 251, 5 }; */

netsnmp_transport	*netsnmp_tcp6_transport	(struct sockaddr_in6 *addr,
					 int local);

/*  "Constructor" for transport domain object.  */

void		 netsnmp_tcp6_ctor		(void);

#endif/*_SNMPTCPIPV6DOMAIN_H*/
