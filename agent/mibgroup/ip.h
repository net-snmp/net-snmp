/*
 *  Template MIB group interface - ip.h
 *
 */

#ifndef _MIBGROUP_IP_H
#define _MIBGROUP_IP_H

config_require(interfaces)

extern void	init_ip __P((void));
extern u_char	*var_ip __P((struct variable*, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern int header_ip __P((struct variable*, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern u_char	*var_ipAddrEntry __P((struct variable*, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern u_char	*var_ipRouteEntry __P((struct variable*, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

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
    {IPFORWARDING, INTEGER, RONLY, var_ip, 1, {1 }},
    {IPDEFAULTTTL, INTEGER, RONLY, var_ip, 1, {2 }},
#ifndef sunV3
    {IPINRECEIVES, COUNTER, RONLY, var_ip, 1, {3 }},
#endif
    {IPINHDRERRORS, COUNTER, RONLY, var_ip, 1, {4 }},
#ifndef sunV3
    {IPINADDRERRORS, COUNTER, RONLY, var_ip, 1, {5 }},
    {IPFORWDATAGRAMS, COUNTER, RONLY, var_ip, 1, {6 }},
#endif
    {IPINUNKNOWNPROTOS, COUNTER, RONLY, var_ip, 1, {7 }},
#ifndef sunV3
    {IPINDISCARDS, COUNTER, RONLY, var_ip, 1, {8 }},
    {IPINDELIVERS, COUNTER, RONLY, var_ip, 1, {9 }},
#endif
    {IPOUTREQUESTS, COUNTER, RONLY, var_ip, 1, {10 }},
    {IPOUTDISCARDS, COUNTER, RONLY, var_ip, 1, {11 }},
    {IPOUTNOROUTES, COUNTER, RONLY, var_ip, 1, {12 }},
    {IPREASMTIMEOUT, INTEGER, RONLY, var_ip, 1, {13 }},
#ifndef sunV3
    {IPREASMREQDS, COUNTER, RONLY, var_ip, 1, {14 }},
    {IPREASMOKS, COUNTER, RONLY, var_ip, 1, {15 }},
    {IPREASMFAILS, COUNTER, RONLY, var_ip, 1, {16 }},
#endif
    {IPFRAGOKS, COUNTER, RONLY, var_ip, 1, {17 }},
    {IPFRAGFAILS, COUNTER, RONLY, var_ip, 1, {18 }},
    {IPFRAGCREATES, COUNTER, RONLY, var_ip, 1, {19 }},
    {IPADADDR, IPADDRESS, RONLY, var_ipAddrEntry, 3, {20, 1, 1}},
    {IPADIFINDEX, INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 2}},
#ifndef sunV3
    {IPADNETMASK, IPADDRESS, RONLY, var_ipAddrEntry, 3, {20, 1, 3}},
#endif
    {IPADBCASTADDR, INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 4}},
    {IPADREASMMAX, INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 5}},
    {IPROUTEDEST, IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 1}},
    {IPROUTEIFINDEX, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 2}},
    {IPROUTEMETRIC1, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 3}},
    {IPROUTEMETRIC2, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 4}},
    {IPROUTEMETRIC3, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 5}},
    {IPROUTEMETRIC4, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 6}},
    {IPROUTENEXTHOP, IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 7}},
    {IPROUTETYPE, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 8}},
    {IPROUTEPROTO, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 9}},
    {IPROUTEAGE, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 10}},
    {IPROUTEMASK, IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 11}},
    {IPROUTEMETRIC5, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 12}},
    {IPROUTEINFO, OBJID, RONLY, var_ipRouteEntry, 3, {21, 1, 13}},
    {IPMEDIAIFINDEX, INTEGER, RONLY, var_atEntry, 3, {22, 1, 1}},
    {IPMEDIAPHYSADDRESS, STRING, RONLY, var_atEntry, 3, {22, 1, 2}},
    {IPMEDIANETADDRESS, IPADDRESS, RONLY, var_atEntry, 3, {22, 1, 3}},
    {IPMEDIATYPE, INTEGER, RONLY, var_atEntry, 3, {22, 1, 4}},
    {IPROUTEDISCARDS, COUNTER, RONLY, var_ip, 1, {23 }}
};
    config_load_mib({MIB.4}, 7, ip_variables)
#endif

#endif /* _MIBGROUP_IP_H */
