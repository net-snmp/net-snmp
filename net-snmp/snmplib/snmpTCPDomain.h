#ifndef _SNMPTCPDOMAIN_H
#define _SNMPTCPDOMAIN_H

#ifdef SNMP_TRANSPORT_TCP_DOMAIN

#include "snmp_transport.h"
#include "asn1.h"

const oid snmpTCPDomain[8];  /*  = { 1, 3, 6, 1, 3, 91, 1, 1 };  */

snmp_transport		*snmp_tcp_transport	(struct sockaddr_in *addr,
						 int local);

#endif/*SNMP_TRANSPORT_TCP_DOMAIN*/

#endif/*_SNMPTCPDOMAIN_H*/
