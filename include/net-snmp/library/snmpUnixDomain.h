#ifndef _SNMPUNIXDOMAIN_H
#define _SNMPUNIXDOMAIN_H

#ifdef SNMP_TRANSPORT_UNIX_DOMAIN

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/asn1.h>

extern const oid netsnmp_ucdSnmpUnixDomain[9];  /*  = { UCDAVIS_MIB, 251, 2 };  */

netsnmp_transport		*netsnmp_unix_transport	(struct sockaddr_un *addr,
						 int local);
int		netsnmp_unix_recv	(netsnmp_transport *t, void *buf, int size,
				 void **opaque, int *olength);
int		netsnmp_unix_send	(netsnmp_transport *t, void *buf, int size,
				 void **opaque, int *olength);
int		netsnmp_unix_close	(netsnmp_transport *t);
int		netsnmp_unix_accept	(netsnmp_transport *t);

/*  "Constructor" for transport domain object.  */

void		netsnmp_unix_ctor		(void);

#endif/*SNMP_TRANSPORT_UNIX_DOMAIN*/

#endif/*_SNMPUNIXDOMAIN_H*/
