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

extern const oid ucdSnmpUnixDomain[9];  /*  = { 1, 3, 6, 1, 4, 1, 2021, 251, 2 };  */

snmp_transport		*snmp_unix_transport	(struct sockaddr_un *addr,
						 int local);

#endif/*SNMP_TRANSPORT_UNIX_DOMAIN*/

#endif/*_SNMPUNIXDOMAIN_H*/
