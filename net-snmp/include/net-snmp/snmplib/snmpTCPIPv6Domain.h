#ifndef _SNMPTCPIPV6DOMAIN_H
#define _SNMPTCPIPV6DOMAIN_H

#include "snmp_transport.h"
#include "asn1.h"

const oid ucdSnmpTCPIPv6Domain[9];  /* = { UCDAVIS_MIB, 251, 5 }; */

snmp_transport	*snmp_tcp6_transport	(struct sockaddr_in6 *addr,
					 int local);

/*  "Constructor" for transport domain object.  */

void		 snmp_tcp6_ctor		(void);

#endif/*_SNMPTCPIPV6DOMAIN_H*/
