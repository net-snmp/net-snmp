#ifndef _SNMPUNIXDOMAIN_H
#define _SNMPUNIXDOMAIN_H

#ifdef SNMP_TRANSPORT_UNIX_DOMAIN

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include "snmp_transport.h"
#include "asn1.h"

extern const oid ucdSnmpUnixDomain[9];  /*  = { UCDAVIS_MIB, 251, 2 };  */

snmp_transport		*snmp_unix_transport	(struct sockaddr_un *addr,
						 int local);

/*  "Constructor" for transport domain object.  */

void		snmp_unix_ctor		(void);

#endif/*SNMP_TRANSPORT_UNIX_DOMAIN*/

#endif/*_SNMPUNIXDOMAIN_H*/
