/*
 *  TCP MIB group interface - tcp.h
 *
 */
#ifndef _MIBGROUP_TCP_H
#define _MIBGROUP_TCP_H

#ifdef linux

struct tcp_mib
{
 	unsigned long	tcpRtoAlgorithm;
 	unsigned long	tcpRtoMin;
 	unsigned long	tcpRtoMax;
 	unsigned long	tcpMaxConn;
 	unsigned long	tcpActiveOpens;
 	unsigned long	tcpPassiveOpens;
 	unsigned long	tcpAttemptFails;
 	unsigned long	tcpEstabResets;
 	unsigned long	tcpCurrEstab;
 	unsigned long	tcpInSegs;
 	unsigned long	tcpOutSegs;
 	unsigned long	tcpRetransSegs;
};

#endif

config_arch_require(solaris2, kernel_sunos5)
config_require(mibII/tcpTable util_funcs)

extern void	init_tcp (void);
extern FindVarMethod var_tcp;


#define TCPRTOALGORITHM      1
#define TCPRTOMIN	     2
#define TCPRTOMAX	     3
#define TCPMAXCONN	     4
#define TCPACTIVEOPENS	     5
#define TCPPASSIVEOPENS      6
#define TCPATTEMPTFAILS      7
#define TCPESTABRESETS	     8
#define TCPCURRESTAB	     9
#define TCPINSEGS	    10
#define TCPOUTSEGS	    11
#define TCPRETRANSSEGS	    12
#define TCPCONNSTATE	    13
#define TCPCONNLOCALADDRESS 14
#define TCPCONNLOCALPORT    15
#define TCPCONNREMADDRESS   16
#define TCPCONNREMPORT	    17
#define TCPINERRS           18
#define TCPOUTRSTS          19

#endif /* _MIBGROUP_TCP_H */
