/*
 *  TCP MIB group interface - tcp.h
 *
 */
#ifndef _MIBGROUP_TCP_H
#define _MIBGROUP_TCP_H

#ifdef linux
/* ugly mapping of `struct tcpstat' -> `struct tcp_mib' (but what the heck): */
#define tcpstat tcp_mib
#define tcps_connattempt TcpActiveOpens
#define tcps_accepts TcpPassiveOpens
#define tcps_conndrops TcpAttemptFails
#define tcps_drops TcpEstabResets
#define tcps_rcvtotal TcpInSegs
#define tcps_sndtotal TcpOutSegs
#define tcps_sndrexmitpack TcpRetransSegs

struct tcp_mib
{
 	unsigned long	TcpRtoAlgorithm;
 	unsigned long	TcpRtoMin;
 	unsigned long	TcpRtoMax;
 	unsigned long	TcpMaxConn;
 	unsigned long	TcpActiveOpens;
 	unsigned long	TcpPassiveOpens;
 	unsigned long	TcpAttemptFails;
 	unsigned long	TcpEstabResets;
 	unsigned long	TcpCurrEstab;
 	unsigned long	TcpInSegs;
 	unsigned long	TcpOutSegs;
 	unsigned long	TcpRetransSegs;
};

struct inpcb {
        struct  inpcb *inp_next;        /* pointers to other pcb's */
        struct  in_addr inp_faddr;      /* foreign host table entry */
        u_short inp_fport;              /* foreign port */
        struct  in_addr inp_laddr;      /* local host table entry */
        u_short inp_lport;              /* local port */
	int     inp_state;
	int     uid;			/* owner of the connection */
};
#endif

config_arch_require(solaris2, kernel_sunos5)

#ifndef solaris2
#ifndef linux
extern int TCP_Count_Connections __P((void));
#endif
extern  void TCP_Scan_Init __P((void));
extern  int TCP_Scan_Next __P((int *, struct inpcb *));
#endif

extern void	init_tcp __P((void));
extern u_char	*var_tcp __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern u_char	*var_tcpEntry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));


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


#ifdef IN_SNMP_VARS_C

struct variable13 tcp_variables[] = {
    {TCPRTOALGORITHM, INTEGER, RONLY, var_tcp, 1, {1}},
    {TCPRTOMIN, INTEGER, RONLY, var_tcp, 1, {2}},
#ifndef sunV3
    {TCPRTOMAX, INTEGER, RONLY, var_tcp, 1, {3}},
#endif
    {TCPMAXCONN, INTEGER, RONLY, var_tcp, 1, {4}},
#ifndef sunV3
    {TCPACTIVEOPENS, COUNTER, RONLY, var_tcp, 1, {5}},
    {TCPPASSIVEOPENS, COUNTER, RONLY, var_tcp, 1, {6}},
    {TCPATTEMPTFAILS, COUNTER, RONLY, var_tcp, 1, {7}},
    {TCPESTABRESETS, COUNTER, RONLY, var_tcp, 1, {8}},
#endif
    {  TCPCURRESTAB, GAUGE, RONLY, var_tcp, 1, {9}},
#ifndef sunV3
    {TCPINSEGS, COUNTER, RONLY, var_tcp, 1, {10}},
    {TCPOUTSEGS, COUNTER, RONLY, var_tcp, 1, {11} },
    {TCPRETRANSSEGS, COUNTER, RONLY, var_tcp, 1, {12}},
#endif
    {TCPCONNSTATE, INTEGER, RONLY, var_tcpEntry, 3, {13, 1, 1}},
    {TCPCONNLOCALADDRESS, IPADDRESS, RONLY, var_tcpEntry, 3, {13, 1, 2}},
    {TCPCONNLOCALPORT, INTEGER, RONLY, var_tcpEntry, 3, {13, 1, 3}},
    {TCPCONNREMADDRESS, IPADDRESS, RONLY, var_tcpEntry, 3, {13, 1, 4}},
    {TCPCONNREMPORT, INTEGER, RONLY, var_tcpEntry, 3, {13, 1, 5}},
    {TCPINERRS, COUNTER, RONLY, var_tcp, 1, {14}},
    {TCPOUTRSTS, COUNTER, RONLY, var_tcp, 1, {15}}
};

config_load_mib(MIB.6, 7, tcp_variables)
#endif
#endif /* _MIBGROUP_TCP_H */
