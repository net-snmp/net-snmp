#ifndef _SNMPIPXDOMAIN_H
#define _SNMPIPXDOMAIN_H

#include "snmp_transport.h"
#include "asn1.h"
#if HAVE_NETIPX_IPX_H
#include <netipx/ipx.h>
#endif


snmp_transport		*snmp_ipx_transport	(struct sockaddr_ipx *addr,
						 int local);

/*  Convert an textually formatted IPX address into a sockaddr_ipx
    structure which is written to *addr.  Returns 1 if the conversion
    was successful, or 0 if it failed.  */

int			 snmp_sockaddr_ipx	(struct sockaddr_ipx *addr,
						 const char *peername);

#endif/*_SNMPIPXDOMAIN_H*/
