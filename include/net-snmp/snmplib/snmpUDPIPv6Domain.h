#ifndef _SNMPUDPIPV6DOMAIN_H
#define _SNMPUDPIPV6DOMAIN_H

#include "snmp_transport.h"
#include "asn1.h"

const oid ucdSnmpUDPIPv6Domain[9];  /* = { UCDAVIS_MIB, 251, 4 }; */

snmp_transport	*snmp_udp6_transport	(struct sockaddr_in6 *addr,
					 int local);


/*  Convert a "traditional" peername into a sockaddr_in6 structure which is
    written to *addr.  Returns 1 if the conversion was successful, or 0 if it
    failed.  */

int		 snmp_sockaddr_in6	(struct sockaddr_in6 *addr,
					 const char *peername,
					 int remote_port);

/*  "Constructor" for transport domain object.  */

void		 snmp_udp6_ctor		(void);

#endif/*_SNMPUDPIPV6DOMAIN_H*/
