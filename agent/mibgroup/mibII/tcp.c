
/*
 *  TCP MIB group implementation - tcp.c
 *
 */

#include <config.h>
#include <unistd.h>
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/socket.h>
#if HAVE_SYS_PROTOSW_H
#include <sys/protosw.h>
#endif

#if HAVE_SYS_SYSMP_H
#include <sys/sysmp.h>
#endif
#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#include <net/if.h>
#if HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
#ifdef _I_DEFINED_KERNEL
#undef _KERNEL
#endif
#if HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#if HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#if HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#endif
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif
#ifdef INET6
#if HAVE_NETINET6_IP6_VAR_H
#include <netinet6/ip6_var.h>
#endif
#endif
#if HAVE_SYS_SOCKETVAR_H
#include <sys/socketvar.h>
#endif
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef solaris2
#include "kernel_sunos5.h"
#else
#include "kernel.h"
#endif

#include "mibincl.h"
#include "../../../snmplib/system.h"
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if defined(osf4) || defined(aix4) || defined(hpux10)
/* these are undefed to remove a stupid warning on osf compilers
   because they get redefined with a slightly different notation of the
   same value.  -- Wes */
#undef TCP_NODELAY
#undef TCP_MAXSEG
#endif
#include <netinet/tcp.h>
#if HAVE_NETINET_TCPIP_H
#include <netinet/tcpip.h>
#endif
#if HAVE_NETINET_TCP_TIMER_H
#include <netinet/tcp_timer.h>
#endif
#if HAVE_NETINET_TCP_VAR_H
#include <netinet/tcp_var.h>
#endif
#if HAVE_NETINET_TCP_FSM_H
#include <netinet/tcp_fsm.h>
#endif
#if HAVE_SYS_TCPIPSTATS_H
#include <sys/tcpipstats.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "auto_nlist.h"

#ifdef hpux
#include <sys/mib.h>
#include <netinet/mib_kern.h>
#endif /* hpux */

/* #include "../common_header.h" */
#include "tcp.h"
#include "sysORTable.h"

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef linux
static void linux_read_tcp_stat (struct tcp_mib *);
#endif
#ifdef freebsd4
static unsigned int hz;
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

struct variable13 tcp_variables[] = {
    {TCPRTOALGORITHM, ASN_INTEGER, RONLY, var_tcp, 1, {1}},
    {TCPRTOMIN, ASN_INTEGER, RONLY, var_tcp, 1, {2}},
#ifndef sunV3
    {TCPRTOMAX, ASN_INTEGER, RONLY, var_tcp, 1, {3}},
#endif
    {TCPMAXCONN, ASN_INTEGER, RONLY, var_tcp, 1, {4}},
#ifndef sunV3
    {TCPACTIVEOPENS, ASN_COUNTER, RONLY, var_tcp, 1, {5}},
    {TCPPASSIVEOPENS, ASN_COUNTER, RONLY, var_tcp, 1, {6}},
    {TCPATTEMPTFAILS, ASN_COUNTER, RONLY, var_tcp, 1, {7}},
    {TCPESTABRESETS, ASN_COUNTER, RONLY, var_tcp, 1, {8}},
#endif
    {  TCPCURRESTAB, ASN_GAUGE, RONLY, var_tcp, 1, {9}},
#ifndef sunV3
    {TCPINSEGS, ASN_COUNTER, RONLY, var_tcp, 1, {10}},
    {TCPOUTSEGS, ASN_COUNTER, RONLY, var_tcp, 1, {11} },
    {TCPRETRANSSEGS, ASN_COUNTER, RONLY, var_tcp, 1, {12}},
#endif
    {TCPCONNSTATE, ASN_INTEGER, RONLY, var_tcpEntry, 3, {13, 1, 1}},
    {TCPCONNLOCALADDRESS, ASN_IPADDRESS, RONLY, var_tcpEntry, 3, {13, 1, 2}},
    {TCPCONNLOCALPORT, ASN_INTEGER, RONLY, var_tcpEntry, 3, {13, 1, 3}},
    {TCPCONNREMADDRESS, ASN_IPADDRESS, RONLY, var_tcpEntry, 3, {13, 1, 4}},
    {TCPCONNREMPORT, ASN_INTEGER, RONLY, var_tcpEntry, 3, {13, 1, 5}},
    {TCPINERRS, ASN_COUNTER, RONLY, var_tcp, 1, {14}},
    {TCPOUTRSTS, ASN_COUNTER, RONLY, var_tcp, 1, {15}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath, and the OID for the MIB module */
oid tcp_variables_oid[] = { SNMP_OID_MIB2,6 };
oid tcp_module_oid[]    = { SNMP_OID_MIB2,49 };

void init_tcp(void)
{
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/tcp", tcp_variables, variable13, tcp_variables_oid);
  REGISTER_SYSOR_ENTRY( tcp_module_oid,
		"The MIB module for managing TCP implementations");

#ifdef TCPSTAT_SYMBOL
  auto_nlist( TCPSTAT_SYMBOL,0,0 );
#endif
#ifdef TCP_SYMBOL
  auto_nlist( TCP_SYMBOL,0,0 );
#endif
#if freebsd4
  hz=sysconf(_SC_CLK_TCK); /* get ticks/s from system */
#endif
}

/*
  header_tcp(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/

static int
header_tcp(struct variable *vp,
	   oid *name,
	   size_t *length,
	   int exact,
	   size_t *var_len,
	   WriteMethod **write_method)
{
#define TCP_NAME_LENGTH	8
    oid newname[MAX_OID_LEN];
    int result;

    DEBUGMSGTL(("mibII/tcp", "var_tcp: "));
    DEBUGMSGOID(("mibII/tcp", name, *length));
    DEBUGMSG(("mibII/tcp"," %d\n", exact));

    memcpy( (char *)newname,(char *)vp->name, vp->namelen * sizeof(oid));
    newname[TCP_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, (vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

#ifndef solaris2

#ifdef HAVE_SYS_TCPIPSTATS_H

u_char *
var_tcp(struct variable *vp,
	oid *name,
	size_t *length,
	int exact,
	size_t *var_len,
	WriteMethod **write_method)
{
    static struct kna tcpipstats;
#ifdef TCPTV_NEEDS_HZ
    /*
     * I don't know of any such system now, but maybe they'll figure
     * it out some day.
     */
    int hz = 1000;
#endif

    /*
     *	Allow for a kernel w/o TCP
     */

	if (header_tcp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	    return NULL;

	/*
	 *  Get the TCP statistics from the kernel...
	 */

    if (sysmp (MP_SAGET, MPSA_TCPIPSTATS, &tcpipstats, sizeof tcpipstats) == -1) {
	snmp_log_perror ("sysmp(MP_SAGET)(MPSA_TCPIPSTATS)");
    }
#define tcpstat tcpipstats.tcpstat

	switch (vp->magic){
	    case TCPRTOALGORITHM:
#ifndef linux
		long_return = 4;	/* Van Jacobsen's algorithm *//* XXX */
#else
                if (! tcpstat.TcpRtoAlgorithm) {
		    /* 0 is illegal: assume `other' algorithm: */
		    long_return = 1;
		    return (u_char *) &long_return;
                }
                return (u_char *) &tcpstat.TcpRtoAlgorithm;
#endif
		return (u_char *) &long_return;
	    case TCPRTOMIN:
#ifndef linux
#ifdef TCPTV_NEEDS_HZ
		long_return = TCPTV_MIN;
#else
		long_return = TCPTV_MIN / PR_SLOWHZ * 1000;
#endif
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpRtoMin;
#endif
	    case TCPRTOMAX:
#ifndef linux
#ifdef TCPTV_NEEDS_HZ
		long_return = TCPTV_REXMTMAX;
#else
		long_return = TCPTV_REXMTMAX / PR_SLOWHZ * 1000;
#endif
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpRtoMax;
#endif
	    case TCPMAXCONN:
#ifndef linux
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = -1;
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpMaxConn;
#endif
	    case TCPACTIVEOPENS:
                long_return = tcpstat.tcps_connattempt;
		return (u_char *) &long_return;
	    case TCPPASSIVEOPENS:
                long_return = tcpstat.tcps_accepts;
		return (u_char *) &long_return;
	    case TCPATTEMPTFAILS:
#ifdef hpux
		long_return = MIB_tcpcounter[7];
#else
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = tcpstat.tcps_conndrops;	/* XXX */
#endif
		return (u_char *) &long_return;
	    case TCPESTABRESETS:
#ifdef hpux
		long_return = MIB_tcpcounter[8];
#else
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = tcpstat.tcps_drops;	/* XXX */
#endif
		return (u_char *) &long_return;
		/*
		 * NB:  tcps_drops is actually the sum of the two MIB
		 *	counters tcpAttemptFails and tcpEstabResets.
		 */
	    case TCPCURRESTAB:
#ifndef linux
		long_return = TCP_Count_Connections();
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpCurrEstab;
#endif
	    case TCPINSEGS:
                long_return = tcpstat.tcps_rcvtotal;
		return (u_char *) &long_return;
	    case TCPOUTSEGS:
		long_return = tcpstat.tcps_sndtotal
			    - tcpstat.tcps_sndrexmitpack;
		/*
		 * RFC 1213 defines this as the number of segments sent
		 * "excluding those containing only retransmitted octets"
		 */
		return (u_char *) &long_return;
	    case TCPRETRANSSEGS:
                long_return = tcpstat.tcps_sndrexmitpack;
		return (u_char *) &long_return;
#ifndef linux
	    case TCPINERRS:
		long_return = tcpstat.tcps_rcvbadsum + tcpstat.tcps_rcvbadoff 
#ifdef STRUCT_TCPSTAT_HAS_TCPS_RCVMEMDROP
                  + tcpstat.tcps_rcvmemdrop
#endif
                  + tcpstat.tcps_rcvshort;
		return (u_char *) &long_return;
	    case TCPOUTRSTS:
		long_return = tcpstat.tcps_sndctrl - tcpstat.tcps_closed;
		return (u_char *) &long_return;
#endif /* linux */
	    default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_tcp\n", vp->magic));
	}
    return NULL;
}

#else /* not HAVE_SYS_TCPIPSTATS_H */

u_char *
var_tcp(struct variable *vp,
	oid *name,
	size_t *length,
	int exact,
	size_t *var_len,
	WriteMethod **write_method)
{
    static struct tcpstat tcpstat;
#ifdef hpux
    static	counter MIB_tcpcounter[MIB_tcpMAXCTR+1];
#endif
#ifdef TCPTV_NEEDS_HZ
    int hz = 1000;
#endif

    /*
     *	Allow for a kernel w/o TCP
     */
#ifndef linux
#ifndef TCPSTAT_SYMBOL
    return NULL;
#else
    if (auto_nlist_value(TCPSTAT_SYMBOL) == -1) return(NULL);
#endif
#endif
    
	if (header_tcp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	    return NULL;

	/*
	 *  Get the TCP statistics from the kernel...
	 */
#if !defined(CAN_USE_SYSCTL) || !defined(TCPCTL_STATS)
#ifndef linux
	auto_nlist(TCPSTAT_SYMBOL, (char *)&tcpstat, sizeof (tcpstat));
#ifdef MIB_TCPCOUNTER_SYMBOL
	auto_nlist(MIB_TCPCOUNTER_SYMBOL, (char *)&MIB_tcpcounter,
                   (MIB_tcpMAXCTR+1)*sizeof (counter));
#endif
#else /* linux */
	linux_read_tcp_stat (&tcpstat);
#endif /* linux */
#else /* can use sysctl and net.inet.tcp.stats exists */
	{
		int sname[] = { CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_STATS };
		size_t len;

		len = sizeof tcpstat;
		if (sysctl(sname, 4, &tcpstat, &len, 0, 0) < 0)
			return NULL;
	}
#endif

	switch (vp->magic) {
	    case TCPRTOALGORITHM:
#ifndef linux
		long_return = 4;	/* Van Jacobsen's algorithm *//* XXX */
#else
                if (! tcpstat.TcpRtoAlgorithm) {
		    /* 0 is illegal: assume `other' algorithm: */
		    long_return = 1;
		    return (u_char *) &long_return;
                }
                return (u_char *) &tcpstat.TcpRtoAlgorithm;
#endif
		return (u_char *) &long_return;
	    case TCPRTOMIN:
#ifndef linux
#ifdef TCPTV_NEEDS_HZ
		long_return = TCPTV_MIN;
#else
		long_return = TCPTV_MIN / PR_SLOWHZ * 1000;
#endif
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpRtoMin;
#endif
	    case TCPRTOMAX:
#ifndef linux
#ifdef TCPTV_NEEDS_HZ
		long_return = TCPTV_REXMTMAX;
#else
		long_return = TCPTV_REXMTMAX / PR_SLOWHZ * 1000;
#endif
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpRtoMax;
#endif
	    case TCPMAXCONN:
#ifndef linux
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = -1;
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpMaxConn;
#endif
	    case TCPACTIVEOPENS:
                long_return = tcpstat.tcps_connattempt;
		return (u_char *) &long_return;
	    case TCPPASSIVEOPENS:
                long_return = tcpstat.tcps_accepts;
		return (u_char *) &long_return;
	    case TCPATTEMPTFAILS:
#ifdef hpux
		long_return = MIB_tcpcounter[7];
#else
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = tcpstat.tcps_conndrops;	/* XXX */
#endif
		return (u_char *) &long_return;
	    case TCPESTABRESETS:
#ifdef hpux
		long_return = MIB_tcpcounter[8];
#else
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = tcpstat.tcps_drops;	/* XXX */
#endif
		return (u_char *) &long_return;
		/*
		 * NB:  tcps_drops is actually the sum of the two MIB
		 *	counters tcpAttemptFails and tcpEstabResets.
		 */
	    case TCPCURRESTAB:
#ifndef linux
		long_return = TCP_Count_Connections();
#else
		long_return = tcpstat.TcpCurrEstab;
#endif
		return (u_char *) &long_return;
	    case TCPINSEGS:
                long_return = tcpstat.tcps_rcvtotal;
		return (u_char *) &long_return;
	    case TCPOUTSEGS:
		long_return = tcpstat.tcps_sndtotal
			    - tcpstat.tcps_sndrexmitpack;
		/*
		 * RFC 1213 defines this as the number of segments sent
		 * "excluding those containing only retransmitted octets"
		 */
		return (u_char *) &long_return;
	    case TCPRETRANSSEGS:
                long_return = tcpstat.tcps_sndrexmitpack;
		return (u_char *) &long_return;
#ifndef linux
	    case TCPINERRS:
		long_return = tcpstat.tcps_rcvbadsum + tcpstat.tcps_rcvbadoff 
#ifdef STRUCT_TCPSTAT_HAS_TCPS_RCVMEMDROP
                  + tcpstat.tcps_rcvmemdrop
#endif
                  + tcpstat.tcps_rcvshort;
		return (u_char *) &long_return;
	    case TCPOUTRSTS:
		long_return = tcpstat.tcps_sndctrl - tcpstat.tcps_closed;
		return (u_char *) &long_return;
#endif /* linux */
	    default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_tcp\n", vp->magic));
	}
    return NULL;
}

#endif /* not HAVE_SYS_TCPIPSTATS_H */

u_char *
var_tcpEntry(struct variable *vp,
	     oid *name,
	     size_t *length,
	     int exact,
	     size_t *var_len,
	     WriteMethod **write_method)
{
    int i;
    oid newname[MAX_OID_LEN], lowest[MAX_OID_LEN], *op;
    u_char *cp;
    int State, LowState;
    static struct inpcb inpcb, Lowinpcb;
    
    /*
     *	Allow for a kernel w/o TCP
     */
#ifdef TCPSTAT_SYMBOL
#ifndef linux
    if (auto_nlist_value(TCPSTAT_SYMBOL) == -1) return(NULL);
#endif
#endif
    
	memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
	lowest[0] = 9999;

	/* find "next" connection */
Again:
LowState = -1;	    /* Don't have one yet */
	TCP_Scan_Init();
	for (;;) {
	    if ((i = TCP_Scan_Next(&State, &inpcb)) < 0) goto Again;
	    if (i == 0) break;	    /* Done */
	    cp = (u_char *)&inpcb.inp_laddr.s_addr;
	    op = newname + 10;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    
	    newname[14] = ntohs(inpcb.inp_lport);

	    cp = (u_char *)&inpcb.inp_faddr.s_addr;
	    op = newname + 15;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    
	    newname[19] = ntohs(inpcb.inp_fport);

	    if (exact){
		if (snmp_oid_compare(newname, 20, name, *length) == 0){
		    memcpy( (char *)lowest,(char *)newname, 20 * sizeof(oid));
		    LowState = State;
		    Lowinpcb = inpcb;
		    break;  /* no need to search further */
		}
	    } else {
		if (snmp_oid_compare(newname, 20, name, *length) > 0 &&
		     snmp_oid_compare(newname, 20, lowest, 20) < 0){
		    /*
		     * if new one is greater than input and closer to input than
		     * previous lowest, save this one as the "next" one.
		     */
		    memcpy( (char *)lowest,(char *)newname, 20 * sizeof(oid));
		    LowState = State;
		    Lowinpcb = inpcb;
		}
	    }
	}
	if (LowState < 0) return(NULL);
	memcpy( (char *)name,(char *)lowest, (vp->namelen + 10) * sizeof(oid));
	*length = vp->namelen + 10;
	*write_method = 0;
	*var_len = sizeof(long);
	switch (vp->magic) {
	    case TCPCONNSTATE: {
#ifndef hpux
		static int StateMap[]={1, 2, 3, 4, 5, 8, 6, 10, 9, 7, 11};
#else
              static int StateMap[]={1, 2, 3, -1, 4, 5, 8, 6, 10, 9, 7, 11};
#endif
		return (u_char *) &StateMap[LowState];
	    }
	    case TCPCONNLOCALADDRESS:
		return (u_char *) &Lowinpcb.inp_laddr.s_addr;
	    case TCPCONNLOCALPORT:
		long_return = ntohs(Lowinpcb.inp_lport);
		return (u_char *) &long_return;
	    case TCPCONNREMADDRESS:
		return (u_char *) &Lowinpcb.inp_faddr.s_addr;
	    case TCPCONNREMPORT:
		long_return = ntohs(Lowinpcb.inp_fport);
		return (u_char *) &long_return;
	}
    return NULL;
}

#else  /* solaris2 - tcp */


static int
TCP_Cmp(void *addr, void *ep)
{
  if (memcmp((mib2_tcpConnEntry_t *)ep,(mib2_tcpConnEntry_t *)addr,
	     sizeof(mib2_tcpConnEntry_t))  == 0)
    return (0);
  else
    return (1);
}

u_char *
var_tcp(struct variable *vp,
	oid *name,
	size_t *length,
	int exact,
	size_t *var_len,
	WriteMethod **write_method)
{
  mib2_tcp_t tcpstat;
  mib2_ip_t ipstat;

    if (header_tcp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *  Get the TCP statistics from the kernel...
     */
    if (getMibstat(MIB_TCP, &tcpstat, sizeof(mib2_tcp_t), GET_FIRST, &Get_everything, NULL) < 0)
      return (NULL);		/* Things are ugly ... */

    switch (vp->magic){
    case TCPRTOALGORITHM:
      long_return = tcpstat.tcpRtoAlgorithm;
      return(u_char *) &long_return;
    case TCPRTOMIN:
      long_return = tcpstat.tcpRtoMin;
      return(u_char *) &long_return;
    case TCPRTOMAX:
      long_return = tcpstat.tcpRtoMax;
      return(u_char *) &long_return;
    case TCPMAXCONN:
      long_return = tcpstat.tcpMaxConn;
      return(u_char *) &long_return;
    case TCPACTIVEOPENS:
      long_return = tcpstat.tcpActiveOpens;
      return(u_char *) &long_return;
    case TCPPASSIVEOPENS:
      long_return = tcpstat.tcpPassiveOpens;
      return(u_char *) &long_return;
    case TCPATTEMPTFAILS:
      long_return = tcpstat.tcpAttemptFails;
      return(u_char *) &long_return;
    case TCPESTABRESETS:
      long_return = tcpstat.tcpEstabResets;
      return(u_char *) &long_return;
    case TCPCURRESTAB:
      long_return = tcpstat.tcpCurrEstab;
      return(u_char *) &long_return;
    case TCPINSEGS:
      long_return = tcpstat.tcpInSegs;
      return(u_char *) &long_return;
    case TCPOUTSEGS:
      long_return = tcpstat.tcpOutSegs;
      return(u_char *) &long_return;
    case TCPRETRANSSEGS:
      long_return = tcpstat.tcpRetransSegs;
      return(u_char *) &long_return;
    case TCPINERRS:
      if (getMibstat(MIB_IP, &ipstat, sizeof(mib2_ip_t), GET_FIRST, &Get_everything, NULL) < 0)
	return (NULL);		/* Things are ugly ... */
      long_return = ipstat.tcpInErrs;
      return(u_char *) &long_return;
    default:
      DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_tcp\n", vp->magic));
      return (NULL);
    }
}


u_char *
var_tcpEntry(struct variable *vp,
	     oid *name,
	     size_t *length,
	     int exact,
	     size_t *var_len,
	     WriteMethod **write_method)
{
  oid newname[MAX_OID_LEN], lowest[MAX_OID_LEN], *op;
  u_char *cp;

#define TCP_CONN_LENGTH	20
#define TCP_LOCADDR_OFF	10
#define TCP_LOCPORT_OFF	14
#define TCP_REMADDR_OFF	15
#define TCP_REMPORT_OFF	19
    mib2_tcpConnEntry_t	Lowentry, Nextentry, entry;
    req_e  		req_type;
    int			Found = 0;
    
    memset (&Lowentry, 0, sizeof (Lowentry));
    memcpy( (char *)newname,(char *)vp->name, vp->namelen * sizeof(oid));
    if (*length == TCP_CONN_LENGTH) /* Assume that the input name is the lowest */
      memcpy( (char *)lowest,(char *)name, TCP_CONN_LENGTH * sizeof(oid));
    for (Nextentry.tcpConnLocalAddress = (u_long)-1, req_type = GET_FIRST;
	 ;
	 Nextentry = entry, req_type = GET_NEXT) {
      if (getMibstat(MIB_TCP_CONN, &entry, sizeof(mib2_tcpConnEntry_t),
		 req_type, &TCP_Cmp, &entry) != 0)
	break;
      COPY_IPADDR(cp, (u_char *)&entry.tcpConnLocalAddress, op, newname + TCP_LOCADDR_OFF);
      newname[TCP_LOCPORT_OFF] = entry.tcpConnLocalPort;
      COPY_IPADDR(cp, (u_char *)&entry.tcpConnRemAddress, op, newname + TCP_REMADDR_OFF);
      newname[TCP_REMPORT_OFF] = entry.tcpConnRemPort;

      if (exact){
	if (snmp_oid_compare(newname, TCP_CONN_LENGTH, name, *length) == 0){
	  memcpy( (char *)lowest,(char *)newname, TCP_CONN_LENGTH * sizeof(oid));
	  Lowentry = entry;
	  Found++;
	  break;  /* no need to search further */
	}
      } else {
	if ((snmp_oid_compare(newname, TCP_CONN_LENGTH, name, *length) > 0) &&
	    ((Nextentry.tcpConnLocalAddress == (u_long)-1)
	     || (snmp_oid_compare(newname, TCP_CONN_LENGTH, lowest, TCP_CONN_LENGTH) < 0)
	     || (snmp_oid_compare(name, *length, lowest, TCP_CONN_LENGTH) == 0))){

	  /* if new one is greater than input and closer to input than
	   * previous lowest, and is not equal to it, save this one as the "next" one.
	   */
	  memcpy( (char *)lowest,(char *)newname, TCP_CONN_LENGTH * sizeof(oid));
	  Lowentry = entry;
	  Found++;
	}
      }
    }
    if (Found == 0)
      return(NULL);
    memcpy((char *)name, (char *)lowest,
	  (vp->namelen + TCP_CONN_LENGTH - TCP_LOCADDR_OFF) * sizeof(oid));
    *length = vp->namelen + TCP_CONN_LENGTH - TCP_LOCADDR_OFF;
    *write_method = 0;
    *var_len = sizeof(long);
    switch (vp->magic) {
    case TCPCONNSTATE:
      long_return = Lowentry.tcpConnState;
      return(u_char *) &long_return;
    case TCPCONNLOCALADDRESS:
      long_return = Lowentry.tcpConnLocalAddress;
      return(u_char *) &long_return;
    case TCPCONNLOCALPORT:
      long_return = Lowentry.tcpConnLocalPort;
      return(u_char *) &long_return;
    case TCPCONNREMADDRESS:
      long_return = Lowentry.tcpConnRemAddress;
      return(u_char *) &long_return;
    case TCPCONNREMPORT:
      long_return = Lowentry.tcpConnRemPort;
      return(u_char *) &long_return;
    default:
      DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_tcpEntry\n", vp->magic));
      return (NULL);
    }
}

#endif /* solaris2 - tcp */


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/


#ifdef linux
/*
 * lucky days. since 1.1.16 the tcp statistics are avail by the proc
 * file-system.
 */

static void
linux_read_tcp_stat (struct tcp_mib *tcpstat)
{
  FILE *in = fopen ("/proc/net/snmp", "r");
  char line [1024];

  memset ((char *) tcpstat, (0), sizeof (*tcpstat));

  if (! in)
    return;

  while (line == fgets (line, sizeof(line), in))
    {
      if (12 == sscanf (line, "Tcp: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
	&tcpstat->TcpRtoAlgorithm, &tcpstat->TcpRtoMin, &tcpstat->TcpRtoMax, 
	&tcpstat->TcpMaxConn, &tcpstat->TcpActiveOpens, &tcpstat->TcpPassiveOpens,
	&tcpstat->TcpAttemptFails, &tcpstat->TcpEstabResets, &tcpstat->TcpCurrEstab, 
	&tcpstat->TcpInSegs, &tcpstat->TcpOutSegs, &tcpstat->TcpRetransSegs))
	break;
    }
  fclose (in);
}

#endif /* linux */

#ifndef solaris2
#ifndef linux
/*
 *	Print INTERNET connections
 */

int TCP_Count_Connections (void)
{
	int Established;
	struct inpcb cb;
	register struct inpcb *next;
#if !(defined(freebsd2) || defined(netbsd2) || defined(openbsd2))
	register struct inpcb *prev;
#endif
	struct inpcb inpcb;
	struct tcpcb tcpcb;

Again:	/*
	 *	Prepare to scan the control blocks
	 */
	Established = 0;

	auto_nlist(TCP_SYMBOL, (char *)&cb, sizeof(struct inpcb));
	inpcb = cb;
#if !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2))
	prev = (struct inpcb *) auto_nlist_value(TCP_SYMBOL);
#endif /*  !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2)) */
	/*
	 *	Scan the control blocks
	 */
#if defined(freebsd2) || defined(netbsd1) || defined(openbsd2)
	while ((inpcb.INP_NEXT_SYMBOL != NULL) && (inpcb.INP_NEXT_SYMBOL != (struct inpcb *) auto_nlist_value(TCP_SYMBOL))) {
#else /*  defined(freebsd2) || defined(netbsd1) || defined(openbsd2) */
	while (inpcb.INP_NEXT_SYMBOL != (struct inpcb *) auto_nlist_value(TCP_SYMBOL)) {
#endif /*  defined(freebsd2) || defined(netbsd1) */
		next = inpcb.INP_NEXT_SYMBOL;

		if((klookup((unsigned long)next, (char *)&inpcb, sizeof (inpcb)) == 0)) {
		    snmp_log_perror("TCP_Count_Connections - inpcb");
		    break;
		}
#if !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2))
		if (inpcb.INP_PREV_SYMBOL != prev) {	    /* ??? */
			sleep(1);
			goto Again;
		}
#endif /*  !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2)) */
		if (inet_lnaof(inpcb.inp_laddr) == INADDR_ANY) {
#if !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2))
			prev = next;
#endif /*  !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2)) */
			continue;
		}
		if(klookup((unsigned long)inpcb.inp_ppcb, (char *)&tcpcb, sizeof (tcpcb)) == 0) {
		    snmp_log_perror("TCP_Count_Connections - tcpcb");
		    break;
		}

		if ((tcpcb.t_state == TCPS_ESTABLISHED) ||
		    (tcpcb.t_state == TCPS_CLOSE_WAIT))
		    Established++;
#if !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2))
		prev = next;
#endif /*  !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2)) */
	}
	return(Established);
}
#endif

static struct inpcb tcp_inpcb, *tcp_prev;
#ifdef PCB_TABLE
static struct inpcb *tcp_next, *tcp_head;
#endif
#ifdef linux
static struct inpcb *inpcb_list;
#endif

#if defined(CAN_USE_SYSCTL) && defined(TCPCTL_PCBLIST)
static char *tcpcb_buf = NULL;
static struct xinpgen *xig = NULL;
#endif /* !defined(CAN_USE_SYSCTL) || !define(TCPCTL_PCBLIST) */

void TCP_Scan_Init (void)
{
#if !defined(CAN_USE_SYSCTL) || !defined(TCPCTL_PCBLIST)
#ifdef PCB_TABLE
    struct inpcbtable table;
#endif
#ifndef linux
#ifdef PCB_TABLE
    auto_nlist(TCP_SYMBOL, (char *)&table, sizeof(table));
    tcp_head = tcp_prev = (struct inpcb *)&((struct inpcbtable *)auto_nlist_value(TCP_SYMBOL))->inpt_queue.cqh_first;
    tcp_next = table.inpt_queue.cqh_first;
#else	/* PCB_TABLE */
    auto_nlist(TCP_SYMBOL, (char *)&tcp_inpcb, sizeof(tcp_inpcb));
#if !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2))
    tcp_prev = (struct inpcb *) auto_nlist_value(TCP_SYMBOL);
#endif
#endif	/* PCB_TABLE */
#else	/* linux */
    FILE *in;
    char line [256];
    struct inpcb **pp;
    struct timeval now;
    static unsigned long Time_Of_Last_Reload = 0;

    /*
     * save some cpu-cycles, and reload after 5 secs...
     */
    gettimeofday (&now, (struct timezone *) 0);
    if (Time_Of_Last_Reload + 5 > now.tv_sec)
      {
	tcp_prev = inpcb_list;
	return;
      }
    Time_Of_Last_Reload = now.tv_sec;


    if (! (in = fopen ("/proc/net/tcp", "r")))
      {
 snmp_log(LOG_ERR, "snmpd: cannot open /proc/net/tcp ...\n");
	tcp_prev = NULL;
	return;
      }

    /* free old chain: */
    while (inpcb_list)
      {
	struct inpcb *p = inpcb_list;
	inpcb_list = inpcb_list->INP_NEXT_SYMBOL;
	free (p);
      }

    /* scan proc-file and append: */

    pp = &inpcb_list;
    
    while (line == fgets (line, sizeof(line), in))
      {
	struct inpcb pcb, *nnew;
	static int linux_states [12] = { 0, 4, 2, 3, 6, 9, 10, 0, 5, 8, 1, 7 };
	int state, lp, fp, uid;

	if (6 != sscanf (line,
			 "%*d: %x:%x %x:%x %x %*X:%*X %*X:%*X %*X %d",
			 &pcb.inp_laddr.s_addr, &lp,
			 &pcb.inp_faddr.s_addr, &fp,
			 &state, &uid))
	  continue;

	pcb.inp_lport = htons ((unsigned short) lp);
	pcb.inp_fport = htons ((unsigned short) fp);

	pcb.inp_state = (state & 0xf) < 12 ? linux_states [state & 0xf] : 1;
	pcb.uid = uid;
    
	nnew = (struct inpcb *) malloc (sizeof (struct inpcb));
	if (nnew == NULL) break;
	*nnew = pcb;
	nnew->INP_NEXT_SYMBOL = 0;

	*pp = nnew;
	pp = & nnew->INP_NEXT_SYMBOL;
      }

    fclose (in);

    /* first entry to go: */
    tcp_prev = inpcb_list;

#endif /* linux */
#else /*  !defined(CAN_USE_SYSCTL) || !defined(TCPCTL_PCBLIST) */
    {
	size_t len;
	int sname[] = { CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_PCBLIST };

	if (tcpcb_buf) {
	    free(tcpcb_buf);
	    tcpcb_buf = NULL;
	}
	xig = NULL;

	len = 0;
	if (sysctl(sname, 4, 0, &len, 0, 0) < 0) {
	    return;
	}
	if ((tcpcb_buf = malloc(len)) == NULL) {
	    return;
	}
	if (sysctl(sname, 4, tcpcb_buf, &len, 0, 0) < 0) {
	    free(tcpcb_buf);
	    tcpcb_buf = NULL;
	    return;
	}

	xig = (struct xinpgen *)tcpcb_buf;
	xig = (struct xinpgen *)((char *)xig + xig->xig_len);
	return;
    }
#endif /*  !defined(CAN_USE_SYSCTL) || !defined(TCPCTL_PCBLIST) */
}

int TCP_Scan_Next(int *State,
		  struct inpcb *RetInPcb)
{
#if !defined(CAN_USE_SYSCTL) || !defined(TCPCTL_PCBLIST)
	register struct inpcb *next;
#ifndef linux
	struct tcpcb tcpcb;

#ifdef PCB_TABLE
	if (tcp_next == tcp_head) {
#elif defined(freebsd2) || defined(netbsd1) || defined(openbsd2)
	if (tcp_inpcb.INP_NEXT_SYMBOL == NULL ||
	    tcp_inpcb.INP_NEXT_SYMBOL == (struct inpcb *) auto_nlist_value(TCP_SYMBOL)) {
#else
	if (tcp_inpcb.INP_NEXT_SYMBOL == (struct inpcb *) auto_nlist_value(TCP_SYMBOL)) {
#endif
	    return(0);	    /* "EOF" */
	}

#ifdef PCB_TABLE
	klookup((unsigned long)tcp_next, (char *)&tcp_inpcb, sizeof(tcp_inpcb));
	tcp_next = tcp_inpcb.inp_queue.cqe_next;
#else
	next = tcp_inpcb.INP_NEXT_SYMBOL;
	klookup((unsigned long)next, (char *)&tcp_inpcb, sizeof (tcp_inpcb));
#if !(defined(netbsd1) || defined(freebsd2)) || defined(openbsd2)
	if (tcp_inpcb.INP_PREV_SYMBOL != tcp_prev)	   /* ??? */
          return(-1); /* "FAILURE" */
#endif /*  !(defined(netbsd1) || defined(freebsd2) || defined(openbsd2)) */
#endif	/* PCB_TABLE */
	klookup ( (int)tcp_inpcb.inp_ppcb, (char *)&tcpcb, sizeof (tcpcb));
	*State = tcpcb.t_state;
#else /* linux */
	if (! tcp_prev)
	  return 0;

	tcp_inpcb = *tcp_prev;
	*State = tcp_inpcb.inp_state;
	next = tcp_inpcb.INP_NEXT_SYMBOL;
#endif

	*RetInPcb = tcp_inpcb;
#if !(defined(netbsd1) || defined(freebsd2) || defined(openbsd2))
	tcp_prev = next;
#endif
#else /*  !defined(CAN_USE_SYSCTL) || !defined(TCPCTL_PCBLIST) */
	/* Are we done? */
	if ((xig == NULL) ||
	    (xig->xig_len <= sizeof(struct xinpgen)))
	    return(0);  
	
	*State = ((struct xtcpcb *)xig)->xt_tp.t_state;
	*RetInPcb = ((struct xtcpcb *)xig)->xt_inp;
	
	/* Prepare for Next read */
	xig = (struct xinpgen *)((char *)xig + xig->xig_len);
#endif /*  !defined(CAN_USE_SYSCTL) || !defined(TCPCTL_PCBLIST) */
	return(1);	/* "OK" */
}
#endif /* solaris2 */
