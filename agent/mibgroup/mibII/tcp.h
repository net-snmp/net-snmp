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
extern int TCP_Count_Connections (void);
#endif
extern  void TCP_Scan_Init (void);
struct inpcb;
extern  int TCP_Scan_Next (int *, struct inpcb *);
#endif

extern void	init_tcp (void);
extern FindVarMethod var_tcp;
extern FindVarMethod var_tcpEntry;


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
