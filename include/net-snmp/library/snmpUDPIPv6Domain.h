#ifndef _SNMPUDPIPV6DOMAIN_H
#define _SNMPUDPIPV6DOMAIN_H

/*
 * Portions of this file are copyrighted by:
 * Copyright (c) 2016 VMware, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

#include <net-snmp/types.h>

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_transport.h>

config_require(IPv6Base);
config_require(UDPBase);

#include <net-snmp/library/snmpIPv6BaseDomain.h>

/*
 * The SNMP over UDP over IPv6 transport domain is identified by
 * transportDomainUdpIpv6 as defined in RFC 3419.
 */

#define TRANSPORT_DOMAIN_UDP_IPV6	1,3,6,1,2,1,100,1,2
NETSNMP_IMPORT const oid netsnmp_UDPIPv6Domain[];

netsnmp_transport *netsnmp_udp6_transport(const struct netsnmp_ep *ep,
                                          int local);

netsnmp_transport *
netsnmp_udp6_transport_with_source(const struct netsnmp_ep *ep, int local,
                                   const struct netsnmp_ep *src_addr);

    /** internal functions for derivatives of udpipv6 */

    netsnmp_transport *
    netsnmp_udp6_transport_init(const struct netsnmp_ep *ep, int local);

    int
    netsnmp_udp6_transport_socket(int flags);

    int
    netsnmp_udp6_transport_bind(netsnmp_transport *t,
                                const struct netsnmp_ep *ep,
                                int flags);

    void
    netsnmp_udp6_transport_get_bound_addr(netsnmp_transport *t);

NETSNMP_IMPORT
void            netsnmp_udp6_agent_config_tokens_register(void);
NETSNMP_IMPORT
void            netsnmp_udp6_parse_security(const char *token,
                                            char *param);

NETSNMP_IMPORT
int             netsnmp_udp6_getSecName(void *opaque, int olength,
                                        const char *community,
                                        int community_len,
                                        const char **secname,
                                        const char **contextName);

/*
 * "Constructor" for transport domain object.
 */

void netsnmp_udpipv6_ctor(void);

#ifdef __cplusplus
}
#endif
#endif/*_SNMPUDPIPV6DOMAIN_H*/
