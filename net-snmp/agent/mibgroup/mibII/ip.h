/*
 *  Template MIB group interface - ip.h
 *
 */

#ifndef _MIBGROUP_IP_H
#define _MIBGROUP_IP_H

#ifdef linux
struct ip_mib
{
 	unsigned long	IpForwarding;
 	unsigned long	IpDefaultTTL;
 	unsigned long	IpInReceives;
 	unsigned long	IpInHdrErrors;
 	unsigned long	IpInAddrErrors;
 	unsigned long	IpForwDatagrams;
 	unsigned long	IpInUnknownProtos;
 	unsigned long	IpInDiscards;
 	unsigned long	IpInDelivers;
 	unsigned long	IpOutRequests;
 	unsigned long	IpOutDiscards;
 	unsigned long	IpOutNoRoutes;
 	unsigned long	IpReasmTimeout;
 	unsigned long	IpReasmReqds;
 	unsigned long	IpReasmOKs;
 	unsigned long	IpReasmFails;
 	unsigned long	IpFragOKs;
 	unsigned long	IpFragFails;
 	unsigned long	IpFragCreates;
};
#endif

config_require(mibII/interfaces mibII/at mibII/var_route mibII/route_write)
config_arch_require(solaris2, kernel_sunos5)

#include "var_route.h"
#include "route_write.h"

extern void	init_ip __P((void));
extern u_char	*var_ip __P((struct variable*, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern u_char	*var_ipAddrEntry __P((struct variable*, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#include "at.h"		/* for var_atEntry() */


#define IPFORWARDING	0
#define IPDEFAULTTTL	1
#define IPINRECEIVES	2
#define IPINHDRERRORS	3
#define IPINADDRERRORS	4
#define IPFORWDATAGRAMS 5
#define IPINUNKNOWNPROTOS 6
#define IPINDISCARDS	7
#define IPINDELIVERS	8
#define IPOUTREQUESTS	9
#define IPOUTDISCARDS	10
#define IPOUTNOROUTES	11
#define IPREASMTIMEOUT	12
#define IPREASMREQDS	13
#define IPREASMOKS	14
#define IPREASMFAILS	15
#define IPFRAGOKS	16
#define IPFRAGFAILS	17
#define IPFRAGCREATES	18
#define IPROUTEDISCARDS	19

#define IPADADDR	1
#define IPADIFINDEX	2
#define IPADNETMASK	3
#define IPADBCASTADDR	4
#define IPADREASMMAX	5

#define IPROUTEDEST	0
#define IPROUTEIFINDEX	1
#define IPROUTEMETRIC1	2
#define IPROUTEMETRIC2	3
#define IPROUTEMETRIC3	4
#define IPROUTEMETRIC4	5
#define IPROUTENEXTHOP	6
#define IPROUTETYPE	7
#define IPROUTEPROTO	8
#define IPROUTEAGE	9
#define IPROUTEMASK	10
#define IPROUTEMETRIC5	11
#define IPROUTEINFO	12

#define IPMEDIAIFINDEX		0
#define IPMEDIAPHYSADDRESS	1
#define IPMEDIANETADDRESS	2
#define IPMEDIATYPE		3


#ifdef IN_SNMP_VARS_C

struct variable4 ip_variables[] = {
    {IPFORWARDING, ASN_INTEGER, RONLY, var_ip, 1, {1 }},
    {IPDEFAULTTTL, ASN_INTEGER, RONLY, var_ip, 1, {2 }},
#ifndef sunV3
    {IPINRECEIVES, ASN_COUNTER, RONLY, var_ip, 1, {3 }},
#endif
    {IPINHDRERRORS, ASN_COUNTER, RONLY, var_ip, 1, {4 }},
#ifndef sunV3
    {IPINADDRERRORS, ASN_COUNTER, RONLY, var_ip, 1, {5 }},
    {IPFORWDATAGRAMS, ASN_COUNTER, RONLY, var_ip, 1, {6 }},
#endif
    {IPINUNKNOWNPROTOS, ASN_COUNTER, RONLY, var_ip, 1, {7 }},
#ifndef sunV3
    {IPINDISCARDS, ASN_COUNTER, RONLY, var_ip, 1, {8 }},
    {IPINDELIVERS, ASN_COUNTER, RONLY, var_ip, 1, {9 }},
#endif
    {IPOUTREQUESTS, ASN_COUNTER, RONLY, var_ip, 1, {10 }},
    {IPOUTDISCARDS, ASN_COUNTER, RONLY, var_ip, 1, {11 }},
    {IPOUTNOROUTES, ASN_COUNTER, RONLY, var_ip, 1, {12 }},
    {IPREASMTIMEOUT, ASN_INTEGER, RONLY, var_ip, 1, {13 }},
#ifndef sunV3
    {IPREASMREQDS, ASN_COUNTER, RONLY, var_ip, 1, {14 }},
    {IPREASMOKS, ASN_COUNTER, RONLY, var_ip, 1, {15 }},
    {IPREASMFAILS, ASN_COUNTER, RONLY, var_ip, 1, {16 }},
#endif
    {IPFRAGOKS, ASN_COUNTER, RONLY, var_ip, 1, {17 }},
    {IPFRAGFAILS, ASN_COUNTER, RONLY, var_ip, 1, {18 }},
    {IPFRAGCREATES, ASN_COUNTER, RONLY, var_ip, 1, {19 }},
    {IPADADDR, ASN_IPADDRESS, RONLY, var_ipAddrEntry, 3, {20, 1, 1}},
    {IPADIFINDEX, ASN_INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 2}},
#ifndef sunV3
    {IPADNETMASK, ASN_IPADDRESS, RONLY, var_ipAddrEntry, 3, {20, 1, 3}},
#endif
    {IPADBCASTADDR, ASN_INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 4}},
    {IPADREASMMAX, ASN_INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 5}},
    {IPROUTEDEST, ASN_IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 1}},
    {IPROUTEIFINDEX, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 2}},
    {IPROUTEMETRIC1, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 3}},
    {IPROUTEMETRIC2, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 4}},
    {IPROUTEMETRIC3, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 5}},
    {IPROUTEMETRIC4, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 6}},
    {IPROUTENEXTHOP, ASN_IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 7}},
    {IPROUTETYPE, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 8}},
    {IPROUTEPROTO, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 9}},
    {IPROUTEAGE, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 10}},
    {IPROUTEMASK, ASN_IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 11}},
    {IPROUTEMETRIC5, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 12}},
    {IPROUTEINFO, ASN_OBJECT_ID, RONLY, var_ipRouteEntry, 3, {21, 1, 13}},
    {IPMEDIAIFINDEX, ASN_INTEGER, RONLY, var_atEntry, 3, {22, 1, 1}},
    {IPMEDIAPHYSADDRESS, ASN_OCTET_STR, RONLY, var_atEntry, 3, {22, 1, 2}},
    {IPMEDIANETADDRESS, ASN_IPADDRESS, RONLY, var_atEntry, 3, {22, 1, 3}},
    {IPMEDIATYPE, ASN_INTEGER, RONLY, var_atEntry, 3, {22, 1, 4}},
    {IPROUTEDISCARDS, ASN_COUNTER, RONLY, var_ip, 1, {23 }}
};
    config_load_mib(MIB.4, 7, ip_variables)
#endif

#endif /* _MIBGROUP_IP_H */
