#ifndef NET_SNMP_SESSION_API_H
#define NET_SNMP_SESSION_API_H

    /**
     *  Library API routines concerned with specifying and using SNMP "sessions"
     *    including sending and receiving requests.
     */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>

    /*
     *  For the initial release, this will just refer to the
     *  relevant UCD header files.
     *    In due course, the routines relevant to this area of the
     *  API will be identified, and listed here directly.
     *
     *  But for the time being, this header file is a placeholder,
     *  to allow application writers to adopt the new header file names.
     */

#include <net-snmp/snmp_api.h>
#include <net-snmp/snmp_client.h>
#include <net-snmp/asn1.h>
#include <net-snmp/callback.h>

#include <net-snmp/snmp_transport.h>
#include <net-snmp/snmpCallbackDomain.h>
#ifdef SNMP_TRANSPORT_UNIX_DOMAIN
#include <net-snmp/snmpUnixDomain.h>
#endif
#ifdef SNMP_TRANSPORT_UDP_DOMAIN
#include <net-snmp/snmpUDPDomain.h>
#endif
#ifdef SNMP_TRANSPORT_TCP_DOMAIN
#include <net-snmp/snmpTCPDomain.h>
#endif
#ifdef SNMP_TRANSPORT_UDPIPV6_DOMAIN
#include <net-snmp/snmpUDPIPv6Domain.h>
#endif
#ifdef SNMP_TRANSPORT_TCPIPV6_DOMAIN
#include <net-snmp/snmpTCPIPv6Domain.h>
#endif
#ifdef SNMP_TRANSPORT_IPX_DOMAIN
#include <net-snmp/snmpIPXDomain.h>
#endif
#ifdef SNMP_TRANSPORT_AAL5PVC_DOMAIN
#include <net-snmp/snmpAAL5PVCDomain.h>
#endif

#endif /* NET_SNMP_SESSION_API_H */
