/*
 *  Template MIB group interface - var_route.h
 *
 */
#ifndef _MIBGROUP_VAR_ROUTE_H
#define _MIBGROUP_VAR_ROUTE_H

config_require(util_funcs mibJJ/interfaces)
config_arch_require(solaris2, kernel_sunos5)

extern void  init_ipRoute (void);
extern FindVarMethod var_ipRouteEntry;

#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2) || defined(openbsd2)
struct sockaddr_in *klgetsa (struct sockaddr_in *);
#endif


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


#endif /* _MIBGROUP_VAR_ROUTE_H */
